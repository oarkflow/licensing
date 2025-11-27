package licensing

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
	"fmt"
)

// DecryptStoredLicense decrypts a stored license blob using the device fingerprint.
// This is useful for SDK consumers who want to inspect license data without going
// through the full client verification flow.
func DecryptStoredLicense(stored *StoredLicense) (*LicenseData, []byte, error) {
	if stored == nil {
		return nil, nil, fmt.Errorf("stored license is nil")
	}

	// Derive transport key
	material := stored.DeviceFingerprint + hex.EncodeToString(stored.Nonce)
	transportKeyHash := sha256.Sum256([]byte(material))
	transportKey := transportKeyHash[:]

	// Decrypt with AES-GCM
	block, err := aes.NewCipher(transportKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create GCM: %w", err)
	}
	decrypted, err := gcm.Open(nil, stored.Nonce, stored.EncryptedData, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("decryption failed: %w", err)
	}

	if len(decrypted) < 32 {
		return nil, nil, fmt.Errorf("decrypted payload too small")
	}

	sessionKey := decrypted[:32]
	licenseJSON := decrypted[32:]

	var license LicenseData
	if err := json.Unmarshal(licenseJSON, &license); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal license: %w", err)
	}
	license.DeviceFingerprint = stored.DeviceFingerprint

	return &license, sessionKey, nil
}

// VerifyStoredLicenseSignature verifies the RSA-PSS signature on a stored license.
func VerifyStoredLicenseSignature(stored *StoredLicense) error {
	if stored == nil {
		return fmt.Errorf("stored license is nil")
	}

	// Parse public key from DER
	pub, err := x509.ParsePKIXPublicKey(stored.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}
	rsaPub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not RSA")
	}

	// Verify RSA-PSS signature
	hash := sha256.Sum256(stored.EncryptedData)
	err = rsa.VerifyPSS(rsaPub, crypto.SHA256, hash[:], stored.Signature, nil)
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	return nil
}

// BuildStoredLicenseFromResponse constructs a StoredLicense from an activation response.
// This is useful for testing and debugging.
func BuildStoredLicenseFromResponse(resp *ActivationResponse, fingerprint string) (*StoredLicense, error) {
	if resp == nil {
		return nil, fmt.Errorf("activation response is nil")
	}

	encryptedData, err := hex.DecodeString(resp.EncryptedLicense)
	if err != nil {
		return nil, fmt.Errorf("failed to decode encrypted license: %w", err)
	}
	nonce, err := hex.DecodeString(resp.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode nonce: %w", err)
	}
	signature, err := hex.DecodeString(resp.Signature)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature: %w", err)
	}

	block, _ := pem.Decode([]byte(resp.PublicKey))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM public key")
	}

	return &StoredLicense{
		EncryptedData:     encryptedData,
		Nonce:             nonce,
		Signature:         signature,
		PublicKey:         block.Bytes,
		DeviceFingerprint: fingerprint,
		ExpiresAt:         resp.ExpiresAt,
	}, nil
}
