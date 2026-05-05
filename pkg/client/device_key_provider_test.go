package client

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	licensingcore "github.com/oarkflow/licensing/pkg/licensing"
	"github.com/zalando/go-keyring"
)

func TestSoftwareDeviceKeyProviderBuildsVerifiableProof(t *testing.T) {
	cfg := Config{
		ConfigDir:         t.TempDir(),
		DeviceKeyProvider: "software",
	}
	provider, err := newDeviceKeyProvider(cfg)
	if err != nil {
		t.Fatalf("newDeviceKeyProvider failed: %v", err)
	}
	defer closeDeviceKeyProvider(provider)

	if provider.KeyProvider() != "software-file" {
		t.Fatalf("expected software provider, got %s", provider.KeyProvider())
	}
	keyPath := filepath.Join(cfg.ConfigDir, defaultDeviceKeyFile)
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("expected software key file: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o600 {
		t.Fatalf("expected software key file mode 0600, got %o", mode)
	}

	req := ActivationRequest{
		Email:             "device@example.com",
		ClientID:          "client-1",
		LicenseKey:        "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
		DeviceFingerprint: "softwaredevice0001",
		ProductID:         "prod-1",
	}
	challenge := &DeviceChallengeResponse{
		ChallengeID: "challenge-1",
		Nonce:       "nonce-1",
		Purpose:     licensingcore.DeviceProofPurposeActivate,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}
	proof, err := buildDeviceProof(context.Background(), provider, challenge, licensingcore.DeviceProofPurposeActivate, req)
	if err != nil {
		t.Fatalf("buildDeviceProof failed: %v", err)
	}
	if proof.KeyProvider != "software-file" || proof.PublicKeyAlgorithm != licensingcore.DeviceProofAlgorithmEd25519 {
		t.Fatalf("unexpected proof metadata: %+v", proof)
	}
	if _, err := licensingcore.VerifyDeviceProofSignature(proof, licensingcore.DeviceProofPayload{
		Purpose:     licensingcore.DeviceProofPurposeActivate,
		ChallengeID: challenge.ChallengeID,
		Nonce:       challenge.Nonce,
		LicenseKey:  req.LicenseKey,
		ClientID:    req.ClientID,
		Email:       req.Email,
		ProductID:   req.ProductID,
		Fingerprint: req.DeviceFingerprint,
	}); err != nil {
		t.Fatalf("VerifyDeviceProofSignature failed: %v", err)
	}
}

func TestOSKeystoreDeviceKeyProviderUsesKeyring(t *testing.T) {
	keyring.MockInit()
	cfg := Config{
		AppName:           "LicensingTest",
		ProductID:         "prod-1",
		DeviceKeyProvider: "os",
		DeviceKeyName:     "unit-test-device-key",
	}
	provider, err := newDeviceKeyProvider(cfg)
	if err != nil {
		t.Fatalf("newDeviceKeyProvider(os) failed: %v", err)
	}
	defer closeDeviceKeyProvider(provider)
	if provider.KeyProvider() != "os-keyring" {
		t.Fatalf("expected os keyring provider, got %s", provider.KeyProvider())
	}
	if _, err := keyring.Get(defaultDeviceKeyService, cfg.DeviceKeyName); err != nil {
		t.Fatalf("expected key to be stored in keyring: %v", err)
	}

	providerAgain, err := newDeviceKeyProvider(cfg)
	if err != nil {
		t.Fatalf("newDeviceKeyProvider(os) second load failed: %v", err)
	}
	defer closeDeviceKeyProvider(providerAgain)
	if got, want := licensingcore.DeviceProofPublicKeyID(providerAgain.PublicKeyBytes()), licensingcore.DeviceProofPublicKeyID(provider.PublicKeyBytes()); got != want {
		t.Fatalf("expected os keyring provider to reload same key, got %s want %s", got, want)
	}
}
