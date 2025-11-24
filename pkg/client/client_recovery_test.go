package client

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/oarflow/licensing/pkg/utils"
)

type licenseResponseFactory struct {
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

func newLicenseResponseFactory(t *testing.T) *licenseResponseFactory {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate test key: %v", err)
	}
	return &licenseResponseFactory{priv: priv, pub: &priv.PublicKey}
}

func (f *licenseResponseFactory) buildArtifacts(t *testing.T, licenseData *LicenseData, fingerprint string) (*StoredLicense, *ActivationResponse, []byte) {
	t.Helper()
	licenseJSON, err := json.Marshal(licenseData)
	if err != nil {
		t.Fatalf("failed to marshal license data: %v", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("failed to read nonce: %v", err)
	}
	transportKeyMaterial := fingerprint + hex.EncodeToString(nonce)
	transportHash := sha256.Sum256([]byte(transportKeyMaterial))
	transportKey := transportHash[:]
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		t.Fatalf("failed to read aes key: %v", err)
	}
	payload := append(aesKey, licenseJSON...)
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("failed to create gcm: %v", err)
	}
	encrypted := gcm.Seal(nil, nonce, payload, nil)
	hash := sha256.Sum256(encrypted)
	signature, err := rsa.SignPSS(rand.Reader, f.priv, crypto.SHA256, hash[:], nil)
	if err != nil {
		t.Fatalf("failed to sign: %v", err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(f.pub)
	if err != nil {
		t.Fatalf("failed to marshal pub: %v", err)
	}
	stored := &StoredLicense{
		EncryptedData:     encrypted,
		Nonce:             nonce,
		Signature:         signature,
		PublicKey:         pubDER,
		DeviceFingerprint: fingerprint,
		ExpiresAt:         licenseData.ExpiresAt,
	}
	resp := &ActivationResponse{
		Success:          true,
		Message:          "verified",
		EncryptedLicense: hex.EncodeToString(encrypted),
		Nonce:            hex.EncodeToString(nonce),
		Signature:        hex.EncodeToString(signature),
		PublicKey:        string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		ExpiresAt:        licenseData.ExpiresAt,
	}
	return stored, resp, aesKey
}

func TestVerifyRecoversMissingChecksumViaServer(t *testing.T) {
	t.Parallel()

	factory := newLicenseResponseFactory(t)
	cfg := Config{ConfigDir: t.TempDir(), LicenseFile: "license.dat"}
	client, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create client: %v", err)
	}
	fingerprint, err := client.generateDeviceFingerprint()
	if err != nil {
		t.Fatalf("failed to compute fingerprint: %v", err)
	}
	licenseData := &LicenseData{
		ID:              "lic-123",
		ClientID:        "client-123",
		SubjectClientID: "client-123",
		Email:           "user@example.com",
		Relationship:    "direct",
		LicenseKey:      "ABCD-EFGH-IJKL-MNOP-QRST-UVWX-YZ12-3456",
		IssuedAt:        time.Now().Add(-time.Hour),
		ExpiresAt:       time.Now().Add(12 * time.Hour),
	}
	stored, serverResp, sessionKey := factory.buildArtifacts(t, licenseData, fingerprint)
	licenseJSON, err := json.Marshal(stored)
	if err != nil {
		t.Fatalf("failed to marshal stored license: %v", err)
	}
	if err := os.WriteFile(client.licensePath, licenseJSON, 0o600); err != nil {
		t.Fatalf("failed to seed license file: %v", err)
	}
	_ = os.Remove(client.checksumPath)

	secureResponse := func() []byte {
		payload, err := json.Marshal(serverResp)
		if err != nil {
			t.Fatalf("failed to marshal server resp: %v", err)
		}
		envelope, err := utils.EncryptEnvelope(sessionKey, payload)
		if err != nil {
			t.Fatalf("failed to encrypt server resp: %v", err)
		}
		buf, err := json.Marshal(envelope)
		if err != nil {
			t.Fatalf("failed to marshal envelope: %v", err)
		}
		return buf
	}()

	verifyCalled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/verify" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request: %v", err)
		}
		var env utils.SecureEnvelope
		if err := json.Unmarshal(body, &env); err != nil {
			t.Fatalf("failed to parse secure request: %v", err)
		}
		if _, err := utils.DecryptEnvelope(sessionKey, &env); err != nil {
			t.Fatalf("failed to decrypt request: %v", err)
		}
		select {
		case verifyCalled <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set(headerSecureFlag, "1")
		_, _ = w.Write(secureResponse)
	}))
	defer server.Close()

	client.config.ServerURL = server.URL
	client.httpClient = server.Client()

	license, err := client.Verify()
	if err != nil {
		t.Fatalf("verify returned error: %v", err)
	}
	if license.ID != licenseData.ID {
		t.Fatalf("unexpected license id: %s", license.ID)
	}
	if _, err := os.Stat(client.checksumPath); err != nil {
		t.Fatalf("checksum file missing after recovery: %v", err)
	}
	select {
	case <-verifyCalled:
	default:
		t.Fatal("verify endpoint was not called")
	}
}
