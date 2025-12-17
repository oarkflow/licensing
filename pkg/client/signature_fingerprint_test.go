package client

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"os"
	"testing"
)

// Test that a signature covering encryptedData || fingerprint verifies,
// and that tampering with the stored DeviceFingerprint causes verification to fail.
func TestSignatureCoversFingerprint(t *testing.T) {
	// Create a test RSA key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubBytes})

	// Fake encrypted payload and nonce
	encrypted := []byte("deadbeef")
	nonce := []byte("nonnonce123")
	fingerprint := "device-fp-xyz"

	// Sign SHA256(encrypted || fingerprint)
	combined := append(encrypted, []byte(fingerprint)...)
	h := sha256.Sum256(combined)
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}

	resp := ActivationResponse{
		Success:          true,
		EncryptedLicense: hex.EncodeToString(encrypted),
		Nonce:            hex.EncodeToString(nonce),
		Signature:        hex.EncodeToString(sig),
		PublicKey:        string(pubPem),
	}

	tmpDir := t.TempDir()
	cfg := Config{ConfigDir: tmpDir}
	cli, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Build stored license using the client helper (should verify signature)
	stored, err := cli.buildStoredLicenseFromResponse(&resp, fingerprint)
	if err != nil {
		t.Fatalf("buildStoredLicenseFromResponse failed: %v", err)
	}

	// Now tamper with the stored fingerprint
	stored.DeviceFingerprint = "tampered"

	// Validate signature should fail because server signed the fingerprint
	if err := cli.validateStoredLicenseSignature(stored); err == nil {
		// Write out the stored license for debugging
		raw, _ := json.Marshal(stored)
		_ = os.WriteFile(cli.licensePath+".debug.json", raw, 0600)
		t.Fatalf("expected validateStoredLicenseSignature to fail after tampering, but it passed")
	}
}
