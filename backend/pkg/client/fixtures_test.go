package client

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var updateFixtures = flag.Bool("update-fixtures", false, "write SDK fixture bundle under docs/fixtures/v1")

func TestGenerateFixtures(t *testing.T) {
	if !*updateFixtures {
		t.Skip("set -update-fixtures to regenerate fixtures")
	}

	bundle, err := buildFixtureBundle()
	if err != nil {
		t.Fatalf("failed to build fixture bundle: %v", err)
	}

	repoRoot := filepath.Join("..", "..")
	outDir := filepath.Join(repoRoot, "docs", "fixtures", "v1")
	if err := bundle.persist(outDir); err != nil {
		t.Fatalf("failed to write fixtures: %v", err)
	}
}

type fixtureBundle struct {
	Activation        ActivationRequest
	Response          *ActivationResponse
	Stored            *StoredLicense
	License           *LicenseData
	LicenseFileRaw    []byte
	LicenseFilePretty []byte
	LicenseDataPretty []byte
	ChecksumRaw       []byte
	ChecksumPretty    []byte
}

func buildFixtureBundle() (*fixtureBundle, error) {
	fingerprint := "f4cee5d7a65ef56c5b1ad834cf6741c9793d9e1efd9f1bb7d3a9f3c0a7d8b6e2"
	licenseKey := "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456"

	activationRequest := ActivationRequest{
		Email:             "owner@example.com",
		ClientID:          "client-runtime",
		LicenseKey:        licenseKey,
		DeviceFingerprint: fingerprint,
	}

	issuedAt := time.Date(2025, 1, 1, 12, 0, 0, 0, time.UTC)
	activatedAt := time.Date(2025, 1, 2, 8, 30, 0, 0, time.UTC)
	expiresAt := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	nextCheck := time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC)

	licenseData := &LicenseData{
		ID:                 "lic_fixture_v1",
		ClientID:           "client-provider",
		SubjectClientID:    "client-runtime",
		Email:              "owner@example.com",
		PlanSlug:           "enterprise",
		Relationship:       "direct",
		GrantedBy:          "",
		LicenseKey:         licenseKey,
		IssuedAt:           issuedAt,
		ExpiresAt:          expiresAt,
		LastActivatedAt:    activatedAt,
		CurrentActivations: 1,
		MaxDevices:         5,
		DeviceCount:        1,
		IsRevoked:          false,
		Devices: []LicenseDevice{
			{
				Fingerprint: fingerprint,
				ActivatedAt: activatedAt,
				LastSeenAt:  activatedAt,
			},
		},
		DeviceFingerprint: fingerprint,
		CheckMode:         checkModeMonthly,
		CheckIntervalSecs: 0,
		NextCheckAt:       nextCheck,
		LastCheckAt:       activatedAt,
	}

	sessionKey := deriveBytes("fixture-session-key", 32)
	nonce := deriveBytes("fixture-nonce", 12)
	transportKey := deriveTransportKeyFixture(fingerprint, nonce)

	licenseJSON, err := json.Marshal(licenseData)
	if err != nil {
		return nil, err
	}

	plaintext := append([]byte{}, sessionKey...)
	plaintext = append(plaintext, licenseJSON...)

	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	encrypted := gcm.Seal(nil, nonce, plaintext, nil)

	priv, err := generateDeterministicKey()
	if err != nil {
		return nil, err
	}

	digest := sha256.Sum256(encrypted)
	signature, err := rsa.SignPSS(newDeterministicReader(13371337), priv, crypto.SHA256, digest[:], nil)
	if err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})

	stored := &StoredLicense{
		EncryptedData:     encrypted,
		Nonce:             nonce,
		Signature:         signature,
		PublicKey:         pubDER,
		DeviceFingerprint: fingerprint,
		ExpiresAt:         expiresAt,
	}

	licenseRaw, err := json.Marshal(stored)
	if err != nil {
		return nil, err
	}
	licensePretty, err := json.MarshalIndent(stored, "", "  ")
	if err != nil {
		return nil, err
	}

	checksumRaw, checksumPretty, err := buildChecksumFiles(fingerprint, licenseRaw)
	if err != nil {
		return nil, err
	}

	licenseOutput := struct {
		*LicenseData
		DeviceFingerprint string `json:"device_fingerprint"`
	}{
		LicenseData:       licenseData,
		DeviceFingerprint: fingerprint,
	}
	licenseDataPretty, err := json.MarshalIndent(licenseOutput, "", "  ")
	if err != nil {
		return nil, err
	}

	response := &ActivationResponse{
		Success:          true,
		Message:          "License activated successfully",
		EncryptedLicense: hex.EncodeToString(encrypted),
		Nonce:            hex.EncodeToString(nonce),
		Signature:        hex.EncodeToString(signature),
		PublicKey:        string(pubPEM),
		ExpiresAt:        expiresAt,
	}

	bundle := &fixtureBundle{
		Activation:        activationRequest,
		Response:          response,
		Stored:            stored,
		License:           licenseData,
		LicenseFileRaw:    licenseRaw,
		LicenseFilePretty: licensePretty,
		LicenseDataPretty: licenseDataPretty,
		ChecksumRaw:       checksumRaw,
		ChecksumPretty:    checksumPretty,
	}
	return bundle, nil
}

func (b *fixtureBundle) persist(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "activation_request.json"), b.Activation); err != nil {
		return err
	}
	if err := writeJSONFile(filepath.Join(dir, "activation_response.json"), b.Response); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "license.dat"), b.LicenseFileRaw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "stored_license.json"), b.LicenseFilePretty, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "license.dat.chk"), b.ChecksumRaw, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "checksum_pretty.json"), b.ChecksumPretty, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "license_data.json"), b.LicenseDataPretty, 0o644); err != nil {
		return err
	}
	return nil
}

func writeJSONFile(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func deriveBytes(seed string, length int) []byte {
	buf := make([]byte, 0, length)
	material := []byte(seed)
	counter := byte(0)
	for len(buf) < length {
		input := append(append([]byte{}, material...), counter)
		sum := sha256.Sum256(input)
		buf = append(buf, sum[:]...)
		counter++
	}
	return buf[:length]
}

func deriveTransportKeyFixture(fingerprint string, nonce []byte) []byte {
	material := fingerprint + hex.EncodeToString(nonce)
	hash := sha256.Sum256([]byte(material))
	return hash[:]
}

func buildChecksumFiles(fingerprint string, licenseJSON []byte) ([]byte, []byte, error) {
	checksum := sha256.Sum256(licenseJSON)
	keyMaterial := checksumKeySalt + fingerprint
	key := sha256.Sum256([]byte(keyMaterial))
	nonce := deriveBytes("fixture-checksum-nonce", 12)
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	payload := gcm.Seal(nil, nonce, checksum[:], nil)
	record := checksumRecord{
		Version:   1,
		Nonce:     hex.EncodeToString(nonce),
		Payload:   hex.EncodeToString(payload),
		CreatedAt: time.Date(2025, 1, 2, 8, 30, 0, 0, time.UTC),
	}
	compact, err := json.Marshal(record)
	if err != nil {
		return nil, nil, err
	}
	pretty, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return nil, nil, err
	}
	return compact, pretty, nil
}

type deterministicReader struct {
	src *rand.Rand
}

func newDeterministicReader(seed int64) io.Reader {
	return &deterministicReader{src: rand.New(rand.NewSource(seed))}
}

func (r *deterministicReader) Read(p []byte) (int, error) {
	for i := range p {
		val := r.src.Int63()
		p[i] = byte(val)
	}
	return len(p), nil
}

func generateDeterministicKey() (*rsa.PrivateKey, error) {
	reader := newDeterministicReader(20240515)
	return rsa.GenerateKey(reader, 2048)
}
