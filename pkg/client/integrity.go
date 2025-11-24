package client

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"
)

const checksumKeySalt = "github.com/oarkflow/licensing/client-checksum/v1"

var (
	errChecksumMissing  = errors.New("license checksum missing")
	errChecksumMismatch = errors.New("license checksum mismatch")
)

type checksumRecord struct {
	Version   int       `json:"version"`
	Nonce     string    `json:"nonce"`
	Payload   string    `json:"payload"`
	CreatedAt time.Time `json:"created_at"`
}

func (lc *Client) persistLicenseChecksum(fingerprint string, licenseJSON []byte) error {
	if len(licenseJSON) == 0 {
		return fmt.Errorf("license payload missing")
	}
	checksum := sha256.Sum256(licenseJSON)
	key, err := lc.deriveChecksumKey(fingerprint)
	if err != nil {
		return err
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("failed to generate checksum nonce: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("failed to create checksum cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("failed to initialize checksum gcm: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, checksum[:], nil)
	record := checksumRecord{
		Version:   1,
		Nonce:     hex.EncodeToString(nonce),
		Payload:   hex.EncodeToString(ciphertext),
		CreatedAt: time.Now().UTC(),
	}
	raw, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("failed to serialize checksum record: %w", err)
	}
	tmpPath := lc.checksumPath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("failed to write checksum file: %w", err)
	}
	if err := os.Rename(tmpPath, lc.checksumPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to finalize checksum file: %w", err)
	}
	return nil
}

func (lc *Client) verifyStoredChecksum(fingerprint string, licenseJSON []byte) error {
	if len(licenseJSON) == 0 {
		return fmt.Errorf("license payload missing")
	}
	expected := sha256.Sum256(licenseJSON)
	stored, err := lc.loadStoredChecksum(fingerprint)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return errChecksumMissing
		}
		return err
	}
	if subtle.ConstantTimeCompare(stored, expected[:]) != 1 {
		return fmt.Errorf("%w - license file may be tampered", errChecksumMismatch)
	}
	return nil
}

func (lc *Client) loadStoredChecksum(fingerprint string) ([]byte, error) {
	info, err := os.Stat(lc.checksumPath)
	if err != nil {
		return nil, err
	}
	if err := lc.ensureChecksumFileSecure(info); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(lc.checksumPath)
	if err != nil {
		return nil, err
	}
	var record checksumRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return nil, fmt.Errorf("failed to parse checksum record: %w", err)
	}
	nonce, err := hex.DecodeString(record.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode checksum nonce: %w", err)
	}
	payload, err := hex.DecodeString(record.Payload)
	if err != nil {
		return nil, fmt.Errorf("failed to decode checksum payload: %w", err)
	}
	key, err := lc.deriveChecksumKey(fingerprint)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create checksum cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize checksum gcm: %w", err)
	}
	checksum, err := gcm.Open(nil, nonce, payload, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt checksum record: %w", err)
	}
	if len(checksum) != sha256.Size {
		return nil, fmt.Errorf("checksum length invalid")
	}
	return checksum, nil
}

func (lc *Client) deriveChecksumKey(fingerprint string) ([]byte, error) {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return nil, fmt.Errorf("device fingerprint missing")
	}
	material := checksumKeySalt + fingerprint
	sum := sha256.Sum256([]byte(material))
	return sum[:], nil
}

func (lc *Client) ensureChecksumFileSecure(info os.FileInfo) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("checksum file %s has insecure permissions (%#o) - run 'chmod 600'", lc.checksumPath, info.Mode().Perm())
	}
	return nil
}
