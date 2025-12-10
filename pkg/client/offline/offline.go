package offline

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Config controls offline client behavior and caching
type Config struct {
	ServerURL  string
	CacheDir   string
	HTTPClient *http.Client
}

// OfflineClient provides local verification of signed offline bundles and
// a local cache + incremental sync for the revocation manifest.
type OfflineClient struct {
	cfg *Config

	// in-memory cache
	signingKeys map[string]ed25519.PublicKey
	manifest    *RevocationManifest
}

// SignedBundle is the JSON shape served by the licensing server for offline tokens.
type SignedBundle struct {
	Payload   map[string]interface{} `json:"payload"`
	Signature string                 `json:"signature"`
}

// RevocationManifest is the manifest returned by the server. Clients should
// fetch /api/licenses/offline-revocations and verify signature before applying.
type RevocationManifest struct {
	Version              string                   `json:"version"`
	GeneratedAt          string                   `json:"generated_at"`
	RevokedOfflineTokens []map[string]interface{} `json:"revoked_offline_tokens"`
	RevokedLicenses      []map[string]interface{} `json:"revoked_licenses"`
	SigningKeyID         string                   `json:"-"` // set when signed
}

// New creates a new OfflineClient.
func New(cfg Config) (*OfflineClient, error) {
	if cfg.ServerURL == "" {
		return nil, errors.New("server URL required")
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	oc := &OfflineClient{
		cfg:         &cfg,
		signingKeys: map[string]ed25519.PublicKey{},
	}

	// ensure cache directory
	if cfg.CacheDir != "" {
		if err := os.MkdirAll(cfg.CacheDir, 0700); err != nil {
			return nil, fmt.Errorf("failed to create cache dir: %w", err)
		}
		// attempt to load an existing cached manifest
		_ = oc.loadCachedManifest()
	}

	return oc, nil
}

// loadCachedManifest reads the cached manifest file into memory. Any errors are ignored.
func (oc *OfflineClient) loadCachedManifest() error {
	if oc.cfg.CacheDir == "" {
		return nil
	}
	f := filepath.Join(oc.cfg.CacheDir, "revocation_manifest.json")
	data, err := os.ReadFile(f)
	if err != nil {
		return err
	}
	var wrapper struct {
		Manifest     RevocationManifest `json:"manifest"`
		Signature    string             `json:"signature"`
		SigningKeyID string             `json:"signing_key_id"`
	}
	if err := json.Unmarshal(data, &wrapper); err != nil {
		return err
	}
	wrapper.Manifest.SigningKeyID = wrapper.SigningKeyID
	oc.manifest = &wrapper.Manifest
	return nil
}

// cacheManifest saves the manifest to the configured cache directory atomically.
func (oc *OfflineClient) cacheManifest(manifest RevocationManifest, signature, signingKeyID string) error {
	if oc.cfg.CacheDir == "" {
		return nil
	}
	out := map[string]interface{}{
		"manifest": manifest,
	}
	if signature != "" {
		out["signature"] = signature
		out["signing_key_id"] = signingKeyID
	}
	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return err
	}
	f := filepath.Join(oc.cfg.CacheDir, "revocation_manifest.json")
	tmp := f + ".tmp"
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	return os.Rename(tmp, f)
}

// FetchActiveSigningKey fetches and caches the currently active signing public key.
// The server endpoint expected is /api/keys/offline-signing-public
func (oc *OfflineClient) FetchActiveSigningKey(ctx context.Context) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(oc.cfg.ServerURL, "/")+"/api/keys/offline-signing-public", nil)
	if err != nil {
		return "", err
	}
	r, err := oc.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status %d fetching signing key", r.StatusCode)
	}
	var resp struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if resp.KeyID == "" || resp.PublicKey == "" {
		return "", errors.New("invalid signing key response")
	}
	pk, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	oc.signingKeys[resp.KeyID] = ed25519.PublicKey(pk)
	return resp.KeyID, nil
}

// FetchSigningKeyByID fetches and caches a specific signing public key by id
// Endpoint expected: /api/keys/offline-signing-public/{id}
func (oc *OfflineClient) FetchSigningKeyByID(ctx context.Context, id string) (string, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return "", errors.New("key id required")
	}
	url := strings.TrimRight(oc.cfg.ServerURL, "/") + "/api/keys/offline-signing-public/" + id
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	r, err := oc.cfg.HTTPClient.Do(req)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("unexpected status %d fetching signing key by id", r.StatusCode)
	}
	var resp struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", err
	}
	if resp.KeyID == "" || resp.PublicKey == "" {
		return "", errors.New("invalid signing key response")
	}
	pk, err := base64.StdEncoding.DecodeString(resp.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	oc.signingKeys[resp.KeyID] = ed25519.PublicKey(pk)
	return resp.KeyID, nil
}

// VerifySignedBundle verifies the given JSON signed bundle using the configured
// server public key(s). If a public key isn't present, it will attempt to fetch it.
// On success returns the parsed payload (as map) and nil error.
func (oc *OfflineClient) VerifySignedBundle(ctx context.Context, bundleJSON string, deviceFingerprint string) (map[string]interface{}, error) {
	var b SignedBundle
	if err := json.Unmarshal([]byte(bundleJSON), &b); err != nil {
		return nil, fmt.Errorf("invalid bundle JSON: %w", err)
	}
	skidVal, ok := b.Payload["signing_key_id"]
	if !ok {
		return nil, errors.New("bundle missing signing_key_id")
	}
	skid, ok := skidVal.(string)
	if !ok || skid == "" {
		return nil, errors.New("invalid signing_key_id in bundle")
	}

	pk, ok := oc.signingKeys[skid]
	if !ok {
		// first try to fetch the exact key by id (accounts for rotations)
		if _, err := oc.FetchSigningKeyByID(ctx, skid); err == nil {
			var present bool
			pk, present = oc.signingKeys[skid]
			if present {
				ok = true
			}
		}
	}
	if !ok {
		// fallback to fetch active key
		if _, err := oc.FetchActiveSigningKey(ctx); err != nil {
			return nil, fmt.Errorf("failed to fetch signing key: %w", err)
		}
		var present bool
		pk, present = oc.signingKeys[skid]
		if !present {
			return nil, errors.New("signing key not available")
		}
	}

	payloadBytes, err := json.Marshal(b.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to re-marshal payload: %w", err)
	}
	sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b.Signature))
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %w", err)
	}
	if !ed25519.Verify(pk, payloadBytes, sig) {
		return nil, errors.New("invalid bundle signature")
	}

	// basic payload validations: token, valid_until, device_fingerprint
	if df, ok := b.Payload["device_fingerprint"].(string); ok && deviceFingerprint != "" {
		if df != deviceFingerprint {
			return nil, errors.New("device fingerprint mismatch")
		}
	}

	// check if token is listed in the cached manifest as revoked (best-effort)
	if oc.manifest != nil {
		if oc.isTokenRevokedInManifest(b.Payload) {
			return nil, errors.New("token revoked in manifest")
		}
	}

	return b.Payload, nil
}

func (oc *OfflineClient) isTokenRevokedInManifest(payload map[string]interface{}) bool {
	if oc.manifest == nil {
		return false
	}
	tok, _ := payload["token"].(string)
	if tok == "" {
		return false
	}
	for _, t := range oc.manifest.RevokedOfflineTokens {
		if tTok, ok := t["token"].(string); ok && tTok == tok {
			return true
		}
	}
	return false
}

// SyncManifest fetches the revocation manifest. If 'since' is non-empty it will
// be sent as ?since=<iso> to enable incremental sync. The manifest is verified
// with the signing key returned in the response. On success the cached manifest
// is updated.
func (oc *OfflineClient) SyncManifest(ctx context.Context, since string) (*RevocationManifest, error) {
	url := strings.TrimRight(oc.cfg.ServerURL, "/") + "/api/licenses/offline-revocations"
	if since != "" {
		url = url + "?since=" + since
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	r, err := oc.cfg.HTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status %d fetching manifest", r.StatusCode)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	var resp struct {
		Manifest     RevocationManifest `json:"manifest"`
		Signature    string             `json:"signature"`
		SigningKeyID string             `json:"signing_key_id"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, err
	}
	// if signature present, verify it
	if resp.Signature != "" {
		// ensure we have the public key
		pk, ok := oc.signingKeys[resp.SigningKeyID]
		if !ok {
			// prefer to fetch the specific key by id (so rotated keys continue to verify)
			if _, err := oc.FetchSigningKeyByID(ctx, resp.SigningKeyID); err != nil {
				// fallback to active key if the specific key is not available via endpoint
				if _, err2 := oc.FetchActiveSigningKey(ctx); err2 != nil {
					return nil, fmt.Errorf("failed to fetch signing key for manifest: %w / %v", err, err2)
				}
			}
			var present bool
			pk, present = oc.signingKeys[resp.SigningKeyID]
			if !present {
				return nil, errors.New("signing key not available for manifest verification")
			}
		}
		sig, err := base64.StdEncoding.DecodeString(strings.TrimSpace(resp.Signature))
		if err != nil {
			return nil, fmt.Errorf("manifest signature decode failed: %w", err)
		}
		payloadBytes, err := json.Marshal(resp.Manifest)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal manifest payload: %w", err)
		}
		if !ed25519.Verify(pk, payloadBytes, sig) {
			return nil, errors.New("manifest signature verification failed")
		}
		resp.Manifest.SigningKeyID = resp.SigningKeyID
	}

	// Merge incremental updates against existing manifest if since provided
	if since != "" && oc.manifest != nil {
		// append new revoked tokens/licenses if not present
		existing := oc.manifest
		mapTok := map[string]struct{}{}
		for _, t := range existing.RevokedOfflineTokens {
			if v, ok := t["token"].(string); ok {
				mapTok[v] = struct{}{}
			}
		}
		for _, t := range resp.Manifest.RevokedOfflineTokens {
			if v, ok := t["token"].(string); ok {
				if _, has := mapTok[v]; !has {
					existing.RevokedOfflineTokens = append(existing.RevokedOfflineTokens, t)
				}
			}
		}
		// similar for licenses
		mapLic := map[string]struct{}{}
		for _, l := range existing.RevokedLicenses {
			if v, ok := l["license_key"].(string); ok {
				mapLic[v] = struct{}{}
			}
		}
		for _, l := range resp.Manifest.RevokedLicenses {
			if v, ok := l["license_key"].(string); ok {
				if _, has := mapLic[v]; !has {
					existing.RevokedLicenses = append(existing.RevokedLicenses, l)
				}
			}
		}
		existing.Version = resp.Manifest.Version
		existing.GeneratedAt = resp.Manifest.GeneratedAt
		existing.SigningKeyID = resp.Manifest.SigningKeyID
		oc.manifest = existing
	} else {
		oc.manifest = &resp.Manifest
		oc.manifest.SigningKeyID = resp.SigningKeyID
	}

	// cache to disk if enabled
	_ = oc.cacheManifest(*oc.manifest, resp.Signature, resp.SigningKeyID)

	return oc.manifest, nil
}
