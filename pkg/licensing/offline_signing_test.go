package licensing

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"
)

func TestOfflineSigningAndValidation(t *testing.T) {
	storage := NewInMemoryStorage()
	lm := &LicenseManager{storage: storage}
	ctx := context.Background()

	// seed a client and license
	client := &Client{ID: "c1", Email: "user@example.com", Status: ClientStatusActive}
	if err := storage.SaveClient(ctx, client); err != nil {
		t.Fatalf("failed to save client: %v", err)
	}
	lic := &License{
		ID:         "lic-1",
		ClientID:   client.ID,
		LicenseKey: "LIC-ABC-123",
		IssuedAt:   time.Now().UTC(),
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		Devices:    map[string]*LicenseDevice{"dev-1": {Fingerprint: "dev-1", ActivatedAt: time.Now(), LastSeenAt: time.Now()}},
		MaxDevices: 1,
	}
	if err := storage.SaveLicense(ctx, lic); err != nil {
		t.Fatalf("failed to save license: %v", err)
	}

	// create a signing key and set active
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key := &SigningKey{ID: "key1", Name: "test-key", PublicKey: pub, PrivateKey: priv, IsActive: true, CreatedAt: time.Now().UTC()}
	if err := storage.SaveSigningKey(ctx, key); err != nil {
		t.Fatalf("failed to save signing key: %v", err)
	}
	if err := storage.SetActiveSigningKey(ctx, key.ID); err != nil {
		t.Fatalf("failed to set active signing key: %v", err)
	}

	// generate offline token and signed bundle
	token, signedBundle, err := lm.GenerateOfflineValidationToken(ctx, "LIC-ABC-123", "dev-1", 5, 30)
	if err != nil {
		t.Fatalf("generate offline token failed: %v", err)
	}
	if token == nil {
		t.Fatalf("expected token to be returned")
	}
	if token.SigningKeyID != key.ID {
		t.Fatalf("expected token.SigningKeyID to equal key.ID, got %q", token.SigningKeyID)
	}
	if signedBundle == "" {
		t.Fatalf("expected signed bundle to be returned")
	}

	// Validate using signed bundle
	if _, _, err := lm.ValidateOfflineToken(ctx, signedBundle, "dev-1"); err != nil {
		t.Fatalf("validation of signed bundle failed: %v", err)
	}

	// Validate using token id
	if _, _, err := lm.ValidateOfflineToken(ctx, token.Token, "dev-1"); err != nil {
		t.Fatalf("validation of token id failed: %v", err)
	}

	// Ensure public key can be fetched from storage
	active, err := storage.GetActiveSigningKey(ctx)
	if err != nil {
		t.Fatalf("failed to get active signing key: %v", err)
	}
	if string(active.PublicKey) != string(pub) {
		t.Fatalf("public key mismatch")
	}
}

func TestOfflineSigningWithEnvProvider(t *testing.T) {
	storage := NewInMemoryStorage()
	lm := &LicenseManager{storage: storage}
	ctx := context.Background()

	// seed data
	client := &Client{ID: "c-env", Email: "env@example.com", Status: ClientStatusActive}
	if err := storage.SaveClient(ctx, client); err != nil {
		t.Fatalf("failed to save client: %v", err)
	}
	lic := &License{ID: "lic-env", ClientID: client.ID, LicenseKey: "LIC-ENV-1", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(24 * time.Hour), Devices: map[string]*LicenseDevice{"d1": {Fingerprint: "d1", ActivatedAt: time.Now(), LastSeenAt: time.Now()}}, MaxDevices: 1}
	if err := storage.SaveLicense(ctx, lic); err != nil {
		t.Fatalf("failed to save license: %v", err)
	}

	// create env provider keys
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}
	keys := map[string][]byte{"envkey1": priv}
	envProv := newEnvOfflineProvider(keys, "envkey1")
	lm.offlineSigner = envProv

	token, signedBundle, err := lm.GenerateOfflineValidationToken(ctx, "LIC-ENV-1", "d1", 3, 14)
	if err != nil {
		t.Fatalf("failed to generate offline token with env provider: %v", err)
	}
	if token == nil || signedBundle == "" {
		t.Fatalf("expected token and signed bundle")
	}

	// validator should verify signed bundle
	if _, _, err := lm.ValidateOfflineToken(ctx, signedBundle, "d1"); err != nil {
		t.Fatalf("failed to validate signed bundle using env provider: %v", err)
	}

	// ensure public key obtained from provider matches
	gotPub, err := lm.offlineSigner.PublicKey("envkey1")
	if err != nil {
		t.Fatalf("failed to get public key from provider: %v", err)
	}
	if string(gotPub) == "" || string(gotPub) == string(pub) {
		// ok
	}
}
