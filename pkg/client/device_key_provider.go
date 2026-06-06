package client

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/oarkflow/licensing/pkg/device"
	licensingcore "github.com/oarkflow/licensing/pkg/licensing"
	"github.com/zalando/go-keyring"
)

const defaultDeviceKeyFile = "device_ed25519.pem"
const defaultDeviceKeyService = "oarkflow-licensing-device-key"

type deviceKeyProvider interface {
	KeyProvider() string
	PublicKeyAlgorithm() string
	PublicKeyBytes() []byte
	Attestation() map[string]string
	Sign(context.Context, []byte) ([]byte, error)
	Close() error
}

type softwareDeviceKeyProvider struct {
	path string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newDeviceKeyProvider(cfg Config) (deviceKeyProvider, error) {
	switch strings.ToLower(strings.TrimSpace(cfg.DeviceKeyProvider)) {
	case "", "auto":
		if provider, err := newTPMDeviceProofProvider(cfg.TPMDevice, false); err == nil {
			return provider, nil
		}
		if provider, err := newOSKeystoreDeviceKeyProvider(cfg); err == nil {
			return provider, nil
		}
		return newSoftwareDeviceKeyProvider(softwareDeviceKeyPath(cfg))
	case "tpm", "hardware", "hw":
		return newTPMDeviceProofProvider(cfg.TPMDevice, true)
	case "os", "keyring", "keystore", "keychain":
		return newOSKeystoreDeviceKeyProvider(cfg)
	case "software", "file", "soft":
		return newSoftwareDeviceKeyProvider(softwareDeviceKeyPath(cfg))
	default:
		return nil, fmt.Errorf("unsupported device key provider %q", cfg.DeviceKeyProvider)
	}
}

func softwareDeviceKeyPath(cfg Config) string {
	path := strings.TrimSpace(cfg.DeviceKeyFile)
	if path != "" {
		if filepath.IsAbs(path) {
			return filepath.Clean(path)
		}
		return filepath.Clean(filepath.Join(cfg.ConfigDir, path))
	}

	if device.IsRunningInContainer() {
		if path := containerPersistentDeviceKeyPath(); path != "" {
			return path
		}
	}
	if path == "" {
		path = filepath.Join(cfg.ConfigDir, defaultDeviceKeyFile)
	}
	return filepath.Clean(path)
}

func containerPersistentDeviceKeyPath() string {
	if dir := containerPersistentConfigDir(); dir != "" {
		return filepath.Join(dir, defaultDeviceKeyFile)
	}
	return ""
}

func containerPersistentConfigDir() string {
	for _, dir := range []string{
		"/var/lib/licensing/.licensing",
		"/var/lib/licensing",
		"/data/licensing",
		"/data/.licensing",
		"/persistent/licensing",
		"/persistent/.licensing",
		"/app/.licensing",
	} {
		if directoryExists(dir) {
			return dir
		}
	}
	for _, parent := range []string{
		"/data",
		"/persistent",
		"/var/lib/licensing",
	} {
		if directoryExists(parent) {
			return filepath.Join(parent, ".licensing")
		}
	}
	return ""
}

func directoryExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

func newSoftwareDeviceKeyProvider(path string) (*softwareDeviceKeyProvider, error) {
	cleaned := filepath.Clean(path)
	if err := os.MkdirAll(filepath.Dir(cleaned), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create device key directory: %w", err)
	}
	if data, err := os.ReadFile(cleaned); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("device key file does not contain PEM data")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse device key: %w", err)
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("device key is not Ed25519")
		}
		pub, ok := priv.Public().(ed25519.PublicKey)
		if !ok {
			return nil, fmt.Errorf("device public key is not Ed25519")
		}
		return &softwareDeviceKeyProvider{path: cleaned, priv: priv, pub: pub}, nil
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to read device key: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate device key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal device key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return nil, fmt.Errorf("failed to encode device key: %w", err)
	}
	if err := os.WriteFile(cleaned, buf.Bytes(), 0o600); err != nil {
		return nil, fmt.Errorf("failed to write device key: %w", err)
	}
	return &softwareDeviceKeyProvider{path: cleaned, priv: priv, pub: pub}, nil
}

func (p *softwareDeviceKeyProvider) KeyProvider() string {
	return "software-file"
}

func (p *softwareDeviceKeyProvider) PublicKeyAlgorithm() string {
	return licensingcore.DeviceProofAlgorithmEd25519
}

func (p *softwareDeviceKeyProvider) PublicKeyBytes() []byte {
	return append(ed25519.PublicKey(nil), p.pub...)
}

func (p *softwareDeviceKeyProvider) Attestation() map[string]string {
	return map[string]string{
		"type":   "software",
		"status": "file",
	}
}

func (p *softwareDeviceKeyProvider) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(p.priv, payload), nil
}

func (p *softwareDeviceKeyProvider) Close() error {
	return nil
}

type osKeystoreDeviceKeyProvider struct {
	name string
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

func newOSKeystoreDeviceKeyProvider(cfg Config) (*osKeystoreDeviceKeyProvider, error) {
	name := deviceKeyName(cfg)
	secret, err := keyring.Get(defaultDeviceKeyService, name)
	if err != nil {
		pub, priv, genErr := ed25519.GenerateKey(rand.Reader)
		if genErr != nil {
			return nil, fmt.Errorf("failed to generate os keystore device key: %w", genErr)
		}
		encoded, encodeErr := encodeDevicePrivateKey(priv)
		if encodeErr != nil {
			return nil, encodeErr
		}
		if setErr := keyring.Set(defaultDeviceKeyService, name, encoded); setErr != nil {
			return nil, fmt.Errorf("os keystore unavailable: %w", setErr)
		}
		return &osKeystoreDeviceKeyProvider{name: name, priv: priv, pub: pub}, nil
	}
	priv, pub, err := parseDevicePrivateKey([]byte(secret))
	if err != nil {
		return nil, fmt.Errorf("failed to parse os keystore device key: %w", err)
	}
	return &osKeystoreDeviceKeyProvider{name: name, priv: priv, pub: pub}, nil
}

func deviceKeyName(cfg Config) string {
	if name := strings.TrimSpace(cfg.DeviceKeyName); name != "" {
		return name
	}
	app := strings.TrimSpace(cfg.AppName)
	if app == "" {
		app = defaultAppName
	}
	product := strings.TrimSpace(cfg.ProductID)
	if product == "" {
		product = "default"
	}
	return app + ":" + product
}

func (p *osKeystoreDeviceKeyProvider) KeyProvider() string {
	return "os-keyring"
}

func (p *osKeystoreDeviceKeyProvider) PublicKeyAlgorithm() string {
	return licensingcore.DeviceProofAlgorithmEd25519
}

func (p *osKeystoreDeviceKeyProvider) PublicKeyBytes() []byte {
	return append(ed25519.PublicKey(nil), p.pub...)
}

func (p *osKeystoreDeviceKeyProvider) Attestation() map[string]string {
	return map[string]string{
		"type":    "os-keystore",
		"status":  "protected",
		"backend": runtime.GOOS,
		"name":    p.name,
	}
}

func (p *osKeystoreDeviceKeyProvider) Sign(_ context.Context, payload []byte) ([]byte, error) {
	return ed25519.Sign(p.priv, payload), nil
}

func (p *osKeystoreDeviceKeyProvider) Close() error {
	return nil
}

type tpmDeviceProofProvider struct {
	signer licensingcore.SigningProvider
	pubDER []byte
}

func newTPMDeviceProofProvider(device string, forced bool) (*tpmDeviceProofProvider, error) {
	if !forced && !tpmLikelyAvailable(strings.TrimSpace(device)) {
		return nil, fmt.Errorf("tpm unavailable")
	}
	signer, err := licensingcore.NewTPMDeviceKeyProvider(device)
	if err != nil {
		return nil, err
	}
	pubDER, err := x509.MarshalPKIXPublicKey(signer.PublicKey())
	if err != nil {
		_ = signer.Close()
		return nil, fmt.Errorf("failed to marshal tpm public key: %w", err)
	}
	return &tpmDeviceProofProvider{signer: signer, pubDER: pubDER}, nil
}

func tpmLikelyAvailable(device string) bool {
	if strings.TrimSpace(device) != "" {
		_, err := os.Stat(device)
		return err == nil
	}
	if runtime.GOOS != "linux" {
		return false
	}
	if _, err := os.Stat("/dev/tpmrm0"); err == nil {
		return true
	}
	if _, err := os.Stat("/dev/tpm0"); err == nil {
		return true
	}
	return false
}

func (p *tpmDeviceProofProvider) KeyProvider() string {
	return "hardware-tpm2"
}

func (p *tpmDeviceProofProvider) PublicKeyAlgorithm() string {
	return licensingcore.DeviceProofAlgorithmRSAPSSSHA256
}

func (p *tpmDeviceProofProvider) PublicKeyBytes() []byte {
	return append([]byte(nil), p.pubDER...)
}

func (p *tpmDeviceProofProvider) Attestation() map[string]string {
	id := ""
	if p.signer != nil {
		id = p.signer.ID()
	}
	return map[string]string{
		"type":     "tpm2",
		"status":   "unattested",
		"provider": id,
	}
}

func (p *tpmDeviceProofProvider) Sign(_ context.Context, payload []byte) ([]byte, error) {
	digest := sha256.Sum256(payload)
	return p.signer.Sign(digest[:])
}

func (p *tpmDeviceProofProvider) Close() error {
	if p.signer == nil {
		return nil
	}
	return p.signer.Close()
}

func closeDeviceKeyProvider(provider deviceKeyProvider) {
	if provider != nil {
		_ = provider.Close()
	}
}

func encodeDevicePrivateKey(priv ed25519.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("failed to marshal device key: %w", err)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		return "", fmt.Errorf("failed to encode device key: %w", err)
	}
	return buf.String(), nil
}

func parseDevicePrivateKey(data []byte) (ed25519.PrivateKey, ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, nil, fmt.Errorf("device key data does not contain PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse device key: %w", err)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("device key is not Ed25519")
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("device public key is not Ed25519")
	}
	return priv, pub, nil
}

func buildDeviceProof(ctx context.Context, provider deviceKeyProvider, challenge *DeviceChallengeResponse, purpose string, req ActivationRequest) (*licensingcore.DeviceProof, error) {
	if provider == nil {
		return nil, fmt.Errorf("device key provider missing")
	}
	if challenge == nil {
		return nil, fmt.Errorf("device challenge missing")
	}
	pub := provider.PublicKeyBytes()
	payload := licensingcore.DeviceProofPayload{
		Purpose:     purpose,
		ChallengeID: challenge.ChallengeID,
		Nonce:       challenge.Nonce,
		LicenseKey:  req.LicenseKey,
		ClientID:    req.ClientID,
		Email:       req.Email,
		ProductID:   req.ProductID,
		Fingerprint: req.DeviceFingerprint,
		PublicKey:   pub,
	}
	sig, err := provider.Sign(ctx, licensingcore.CanonicalDeviceProofPayload(payload))
	if err != nil {
		return nil, err
	}
	return &licensingcore.DeviceProof{
		Version:            licensingcore.DeviceProofVersionV2,
		Purpose:            purpose,
		ChallengeID:        challenge.ChallengeID,
		Nonce:              challenge.Nonce,
		Fingerprint:        req.DeviceFingerprint,
		KeyID:              licensingcore.DeviceProofPublicKeyID(pub),
		KeyProvider:        provider.KeyProvider(),
		PublicKeyAlgorithm: provider.PublicKeyAlgorithm(),
		PublicKey:          licensingcore.EncodeDeviceProofBytes(pub),
		Signature:          licensingcore.EncodeDeviceProofBytes(sig),
		Attestation:        deviceProofAttestation(provider),
	}, nil
}

func deviceProofAttestation(provider deviceKeyProvider) map[string]string {
	attestation := map[string]string{}
	if provider != nil {
		for key, value := range provider.Attestation() {
			key = strings.TrimSpace(key)
			value = strings.TrimSpace(value)
			if key != "" && value != "" {
				attestation[key] = value
			}
		}
	}
	if info, err := device.GetInfo(); err == nil && info != nil {
		if strings.TrimSpace(info.Fingerprint) != "" {
			attestation["hardware_fingerprint"] = strings.TrimSpace(info.Fingerprint)
		}
		if len(info.IdentifierConfidence) > 0 {
			attestation["hardware_confidence"] = formatIdentifierConfidence(info.IdentifierConfidence)
		}
		if strings.TrimSpace(info.Name) != "" {
			attestation["label"] = strings.TrimSpace(info.Name)
		} else if strings.TrimSpace(info.Label) != "" {
			attestation["label"] = strings.TrimSpace(info.Label)
		}
		if strings.TrimSpace(info.Platform) != "" {
			attestation["platform"] = strings.TrimSpace(info.Platform)
		}
		if info.IsContainer {
			attestation["is_container"] = "true"
		} else {
			attestation["is_container"] = "false"
		}
	}
	return attestation
}

func formatIdentifierConfidence(confidence map[string]string) string {
	keys := make([]string, 0, len(confidence))
	for key := range confidence {
		if strings.TrimSpace(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		value := strings.TrimSpace(confidence[key])
		if value == "" {
			value = "low"
		}
		parts = append(parts, key+":"+value)
	}
	return strings.Join(parts, ",")
}
