package client

import (
	"encoding/json"
	"os"
	"testing"
)

func TestVerifyFailsWhenFingerprintMismatch(t *testing.T) {
	tmpDir := t.TempDir()
	cfg := Config{
		ConfigDir: tmpDir,
	}
	cli, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	// Build a stored license with a different fingerprint than the current one
	stored := StoredLicense{
		EncryptedData:     []byte("deadbeef"),
		Nonce:             []byte("nonce"),
		Signature:         []byte("sig"),
		PublicKey:         []byte("pk"),
		DeviceFingerprint: "some-other-device",
	}
	raw, _ := json.Marshal(&stored)
	if err := os.WriteFile(cli.licensePath, raw, 0600); err != nil {
		t.Fatalf("failed to write license file: %v", err)
	}

	_, err = cli.Verify()
	if err == nil {
		t.Fatalf("expected Verify to fail due to fingerprint mismatch")
	}
}
