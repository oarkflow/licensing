package client

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestCommittedFixturesRoundTrip(t *testing.T) {
	t.Parallel()

	fixtureDir := filepath.Join("..", "..", "docs", "fixtures", "v1")

	var activationReq ActivationRequest
	readJSONFixture(t, fixtureDir, "activation_request.json", &activationReq)

	var activationResp ActivationResponse
	readJSONFixture(t, fixtureDir, "activation_response.json", &activationResp)

	var storedPretty StoredLicense
	readJSONFixture(t, fixtureDir, "stored_license.json", &storedPretty)

	var storedCompact StoredLicense
	readJSONFixture(t, fixtureDir, "license.dat", &storedCompact)

	if !reflect.DeepEqual(storedPretty, storedCompact) {
		t.Fatalf("license.dat and stored_license.json diverge")
	}

	clientCfg := Config{ConfigDir: t.TempDir(), LicenseFile: "license.dat"}
	cli, err := New(clientCfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}

	generated, err := cli.buildStoredLicenseFromResponse(&activationResp, activationReq.DeviceFingerprint)
	if err != nil {
		t.Fatalf("buildStoredLicenseFromResponse: %v", err)
	}

	if !bytes.Equal(generated.EncryptedData, storedPretty.EncryptedData) {
		t.Fatalf("generated encrypted payload mismatch")
	}
	if !bytes.Equal(generated.Nonce, storedPretty.Nonce) {
		t.Fatalf("generated nonce mismatch")
	}
	if !bytes.Equal(generated.Signature, storedPretty.Signature) {
		t.Fatalf("generated signature mismatch")
	}
	if !bytes.Equal(generated.PublicKey, storedPretty.PublicKey) {
		t.Fatalf("generated public key mismatch")
	}

	licenseFromStored, err := cli.decryptLicense(&storedPretty)
	if err != nil {
		t.Fatalf("decryptLicense: %v", err)
	}

	expected := readLicenseDataFixture(t, fixtureDir)
	if !reflect.DeepEqual(*licenseFromStored, expected) {
		got, _ := json.Marshal(licenseFromStored)
		want, _ := json.Marshal(expected)
		t.Fatalf("decrypted license mismatch\n got: %s\nwant: %s", got, want)
	}
}

func readJSONFixture(t *testing.T, dir, name string, dst interface{}) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

func readLicenseDataFixture(t *testing.T, dir string) LicenseData {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, "license_data.json"))
	if err != nil {
		t.Fatalf("read license_data.json: %v", err)
	}
	var expected LicenseData
	if err := json.Unmarshal(raw, &expected); err != nil {
		t.Fatalf("decode license data: %v", err)
	}
	var envelope struct {
		DeviceFingerprint string `json:"device_fingerprint"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatalf("decode license fingerprint: %v", err)
	}
	expected.DeviceFingerprint = envelope.DeviceFingerprint
	return expected
}
