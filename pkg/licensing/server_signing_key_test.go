package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestPublicKeyEndpoint(t *testing.T) {
	storage := NewInMemoryStorage()
	lm := &LicenseManager{storage: storage}

	// create a signing key and set active
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key := &SigningKey{ID: "k2", Name: "server-test", PublicKey: pub, PrivateKey: priv, IsActive: true, CreatedAt: time.Now().UTC()}
	if err := storage.SaveSigningKey(context.Background(), key); err != nil {
		t.Fatalf("save signing key failed: %v", err)
	}
	if err := storage.SetActiveSigningKey(context.Background(), key.ID); err != nil {
		t.Fatalf("set active key failed: %v", err)
	}

	s := &Server{lm: lm}
	req := httptest.NewRequest(http.MethodGet, "/api/keys/offline-signing-public", nil)
	rw := httptest.NewRecorder()
	s.handleGetActiveSigningPublicKey(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if resp["key_id"] != key.ID {
		t.Fatalf("unexpected key id returned: %s", resp["key_id"])
	}
	expected := base64.StdEncoding.EncodeToString(pub)
	if resp["public_key"] != expected {
		t.Fatalf("unexpected public key value")
	}
}

func TestPublicKeyEndpointFromEnvProvider(t *testing.T) {
	storage := NewInMemoryStorage()
	lm := &LicenseManager{storage: storage}

	// create env provider key and attach to license manager
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	envProv := newEnvOfflineProvider(map[string][]byte{"envk": priv}, "envk")
	lm.offlineSigner = envProv

	s := &Server{lm: lm}
	req := httptest.NewRequest(http.MethodGet, "/api/keys/offline-signing-public", nil)
	rw := httptest.NewRecorder()
	s.handleGetActiveSigningPublicKey(rw, req)
	if rw.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.Code)
	}
	var resp map[string]string
	if err := json.Unmarshal(rw.Body.Bytes(), &resp); err != nil {
		t.Fatalf("invalid json response: %v", err)
	}
	if resp["key_id"] != "envk" {
		t.Fatalf("unexpected key id returned: %s", resp["key_id"])
	}
	expected := base64.StdEncoding.EncodeToString(pub)
	if resp["public_key"] != expected {
		t.Fatalf("unexpected public key value")
	}
}
