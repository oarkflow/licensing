package offline

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestVerifySignedBundle(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "k1"

	payload := map[string]interface{}{
		"token":              "tok-123",
		"device_fingerprint": "dev-1",
		"valid_until":        time.Now().Add(24 * time.Hour).Format(time.RFC3339),
		"signing_key_id":     keyID,
	}
	pb, _ := json.Marshal(payload)
	sig := ed25519.Sign(priv, pb)
	bundle := SignedBundle{Payload: payload, Signature: base64.StdEncoding.EncodeToString(sig)}
	bj, _ := json.Marshal(bundle)

	// create client and inject key
	tmpdir := t.TempDir()
	oc, err := New(Config{ServerURL: "https://example.local", CacheDir: tmpdir})
	if err != nil {
		t.Fatalf("New err: %v", err)
	}
	oc.signingKeys[keyID] = pub

	// verify good
	_, err = oc.VerifySignedBundle(context.Background(), string(bj), "dev-1")
	if err != nil {
		t.Fatalf("VerifySignedBundle failed: %v", err)
	}

	// wrong fingerprint should fail
	if _, err := oc.VerifySignedBundle(context.Background(), string(bj), "bad-dev"); err == nil {
		t.Fatalf("expected fingerprint mismatch error")
	}
}

func TestSyncManifestAndRevocation(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(nil)
	keyID := "active-1"

	// prepare manifest that revokes token 'tok-123'
	manifest := RevocationManifest{
		Version:              "1",
		GeneratedAt:          time.Now().UTC().Format(time.RFC3339),
		RevokedOfflineTokens: []map[string]interface{}{{"token": "tok-123", "license_key": "LIC-AAA", "revoked_at": time.Now().UTC()}},
		RevokedLicenses:      []map[string]interface{}{},
	}
	mb, _ := json.Marshal(manifest)
	sig := ed25519.Sign(priv, mb)
	sigStr := base64.StdEncoding.EncodeToString(sig)

	// test server
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/keys/offline-signing-public":
			out := map[string]string{"key_id": keyID, "public_key": base64.StdEncoding.EncodeToString(pub)}
			json.NewEncoder(w).Encode(out)
			return
		case "/api/licenses/offline-revocations":
			out := map[string]interface{}{"manifest": manifest, "signature": sigStr, "signing_key_id": keyID}
			json.NewEncoder(w).Encode(out)
			return
		default:
			w.WriteHeader(404)
		}
	}))
	defer ts.Close()

	tmpdir := t.TempDir()
	oc, err := New(Config{ServerURL: ts.URL, CacheDir: tmpdir, HTTPClient: ts.Client()})
	if err != nil {
		t.Fatalf("New err: %v", err)
	}

	// sync manifest
	m, err := oc.SyncManifest(context.Background(), "")
	if err != nil {
		t.Fatalf("SyncManifest failed: %v", err)
	}
	if m == nil || len(m.RevokedOfflineTokens) == 0 {
		t.Fatalf("expected manifest with revoked tokens")
	}

	// create and sign a bundle for the revoked token
	payload := map[string]interface{}{"token": "tok-123", "device_fingerprint": "dev-1", "valid_until": time.Now().Add(24 * time.Hour).Format(time.RFC3339), "signing_key_id": keyID}
	pb, _ := json.Marshal(payload)
	bsig := ed25519.Sign(priv, pb)
	bundle := SignedBundle{Payload: payload, Signature: base64.StdEncoding.EncodeToString(bsig)}
	bj, _ := json.Marshal(bundle)

	// now attempt verify should fail because token is revoked in manifest
	if _, err := oc.VerifySignedBundle(context.Background(), string(bj), "dev-1"); err == nil {
		t.Fatalf("expected revocation to cause verification failure")
	}

	// also ensure cached file exists
	cacheFile := filepath.Join(tmpdir, "revocation_manifest.json")
	if _, err := os.Stat(cacheFile); err != nil {
		t.Fatalf("expected cache file, got error: %v", err)
	}
}
