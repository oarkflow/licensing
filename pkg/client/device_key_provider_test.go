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
		Email:      "device@example.com",
		ClientID:   "client-1",
		LicenseKey: "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
		ProductID:  "prod-1",
	}
	req.DeviceFingerprint = licensingcore.DeviceProofFingerprint(provider.PublicKeyAlgorithm(), provider.PublicKeyBytes())
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

func TestDeviceFingerprintIsDerivedFromStableProofKey(t *testing.T) {
	cfg := Config{
		ConfigDir:         t.TempDir(),
		DeviceKeyProvider: "software",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	first, err := client.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("GetDeviceFingerprint first failed: %v", err)
	}
	second, err := client.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("GetDeviceFingerprint second failed: %v", err)
	}
	if first != second {
		t.Fatalf("expected fingerprint to remain stable across calls, got %s then %s", first, second)
	}

	provider, err := newDeviceKeyProvider(client.config)
	if err != nil {
		t.Fatalf("newDeviceKeyProvider failed: %v", err)
	}
	defer closeDeviceKeyProvider(provider)
	if want := licensingcore.DeviceProofFingerprint(provider.PublicKeyAlgorithm(), provider.PublicKeyBytes()); first != want {
		t.Fatalf("expected fingerprint to be versioned proof key id, got %s want %s", first, want)
	}
	if gotLegacyPrefix := first[:6]; gotLegacyPrefix != "fp:v2:" {
		t.Fatalf("expected versioned fingerprint, got %s", first)
	}

	identity, err := client.CurrentDeviceIdentity()
	if err != nil {
		t.Fatalf("CurrentDeviceIdentity failed: %v", err)
	}
	if identity.Fingerprint != first || identity.KeyID != first {
		t.Fatalf("identity did not report stable proof-key fingerprint: %+v", identity)
	}
	if identity.KeyProvider != "software-file" {
		t.Fatalf("unexpected provider: %+v", identity)
	}
}

func TestDeviceFingerprintUnaffectedByHardwareMetadata(t *testing.T) {
	cfg := Config{
		ConfigDir:         t.TempDir(),
		DeviceKeyProvider: "software",
	}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	before, err := client.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("GetDeviceFingerprint before failed: %v", err)
	}
	t.Setenv("DEVICE_ID", "changed-hardware-signal")
	t.Setenv("POD_NAME", "changed-pod")
	after, err := client.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("GetDeviceFingerprint after failed: %v", err)
	}
	if before != after {
		t.Fatalf("expected proof-key fingerprint to ignore hardware metadata drift, got %s then %s", before, after)
	}
}

func TestDeviceFingerprintSurvivesContainerRebuildWithPersistentKeyDir(t *testing.T) {
	persistentKeyDir := t.TempDir()
	deviceKeyFile := filepath.Join(persistentKeyDir, defaultDeviceKeyFile)

	firstClient, err := New(Config{
		ConfigDir:         t.TempDir(),
		DeviceKeyProvider: "software",
		DeviceKeyFile:     deviceKeyFile,
	})
	if err != nil {
		t.Fatalf("New first client failed: %v", err)
	}
	first, err := firstClient.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("GetDeviceFingerprint first failed: %v", err)
	}

	rebuiltClient, err := New(Config{
		ConfigDir:         t.TempDir(),
		DeviceKeyProvider: "software",
		DeviceKeyFile:     deviceKeyFile,
	})
	if err != nil {
		t.Fatalf("New rebuilt client failed: %v", err)
	}
	afterRebuild, err := rebuiltClient.GetDeviceFingerprint()
	if err != nil {
		t.Fatalf("GetDeviceFingerprint after rebuild failed: %v", err)
	}

	if first != afterRebuild {
		t.Fatalf("expected persistent key dir to preserve fingerprint across rebuild, got %s then %s", first, afterRebuild)
	}
	if _, err := os.Stat(filepath.Join(persistentKeyDir, defaultDeviceKeyFile)); err != nil {
		t.Fatalf("expected device proof key in persistent dir: %v", err)
	}
}

func TestDeviceKeyEnvironmentDoesNotOverrideConfiguredPath(t *testing.T) {
	configDir := t.TempDir()
	keyPath := filepath.Join(t.TempDir(), "configured-device-key.pem")
	envKeyPath := filepath.Join(t.TempDir(), "env-device-key.pem")
	t.Setenv("LICENSE_CLIENT_DEVICE_KEY_FILE", envKeyPath)
	t.Setenv("LICENSE_CLIENT_DEVICE_KEY_DIR", filepath.Join(t.TempDir(), "ignored"))

	if got := softwareDeviceKeyPath(Config{ConfigDir: configDir, DeviceKeyFile: keyPath}); got != keyPath {
		t.Fatalf("expected configured device key file to win, got %s want %s", got, keyPath)
	}
	provider, err := newDeviceKeyProvider(Config{
		ConfigDir:         configDir,
		DeviceKeyProvider: "software",
		DeviceKeyFile:     keyPath,
	})
	if err != nil {
		t.Fatalf("newDeviceKeyProvider failed: %v", err)
	}
	defer closeDeviceKeyProvider(provider)
	if _, err := os.Stat(keyPath); err != nil {
		t.Fatalf("expected configured key file to be created: %v", err)
	}
	if _, err := os.Stat(envKeyPath); err == nil {
		t.Fatalf("environment-selected key path must not be created")
	}
}

func TestFormatIdentifierConfidenceIsStable(t *testing.T) {
	got := formatIdentifierConfidence(map[string]string{
		"machine_id":           "medium",
		"dmi_uuid":             "high",
		"container_id":         "low",
		"configured_device_id": "high",
	})
	want := "configured_device_id:high,container_id:low,dmi_uuid:high,machine_id:medium"
	if got != want {
		t.Fatalf("unexpected confidence format: got %q want %q", got, want)
	}
}
