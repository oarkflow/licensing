package client

import (
	"errors"
	"os"
	"testing"
)

func newTestClient(t *testing.T) *Client {
	t.Helper()
	cfg := Config{
		ConfigDir:   t.TempDir(),
		LicenseFile: "license.dat",
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	return client
}

func TestPersistAndVerifyLicenseChecksum(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)
	fingerprint := "test-fingerprint"
	payload := []byte(`{"license":"data"}`)

	if err := client.persistLicenseChecksum(fingerprint, payload); err != nil {
		t.Fatalf("persistLicenseChecksum returned error: %v", err)
	}

	if err := client.verifyStoredChecksum(fingerprint, payload); err != nil {
		t.Fatalf("verifyStoredChecksum returned error: %v", err)
	}
}

func TestVerifyChecksumDetectsTampering(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)
	fingerprint := "another-fingerprint"
	original := []byte("original")
	tampered := []byte("tampered")

	if err := client.persistLicenseChecksum(fingerprint, original); err != nil {
		t.Fatalf("persistLicenseChecksum returned error: %v", err)
	}

	if err := client.verifyStoredChecksum(fingerprint, tampered); err == nil {
		t.Fatal("verifyStoredChecksum succeeded for tampered payload")
	}
}

func TestVerifyChecksumMissingFile(t *testing.T) {
	t.Parallel()

	client := newTestClient(t)
	fingerprint := "missing-checksum"
	payload := []byte("payload")

	err := client.verifyStoredChecksum(fingerprint, payload)
	if err == nil || !errors.Is(err, errChecksumMissing) {
		t.Fatalf("expected errChecksumMissing, got %v", err)
	}

	if _, statErr := os.Stat(client.checksumPath); !os.IsNotExist(statErr) {
		t.Fatalf("checksum file should not be created automatically: %v", statErr)
	}
}
