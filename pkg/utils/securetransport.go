package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

const secureEnvelopeVersion = 1
const secureEnvelopeNonceSize = 12

// SecureEnvelope wraps encrypted payloads exchanged between the licensing client and server.
type SecureEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// DeriveSharedKey converts a shared secret string into a 32-byte AES key.
func DeriveSharedKey(secret string) ([]byte, error) {
	trimmed := strings.TrimSpace(secret)
	if trimmed == "" {
		return nil, errors.New("shared secret is required")
	}
	sum := sha256.Sum256([]byte(trimmed))
	key := make([]byte, len(sum))
	copy(key, sum[:])
	return key, nil
}

// EncryptEnvelope encrypts plaintext into a SecureEnvelope using the provided key.
func EncryptEnvelope(key, plaintext []byte) (*SecureEnvelope, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key length: %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gcm: %w", err)
	}
	nonce := make([]byte, secureEnvelopeNonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to read nonce: %w", err)
	}
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	return &SecureEnvelope{
		Version:    secureEnvelopeVersion,
		Nonce:      hex.EncodeToString(nonce),
		Ciphertext: hex.EncodeToString(ciphertext),
	}, nil
}

// DecryptEnvelope decrypts the payload contained within a SecureEnvelope.
func DecryptEnvelope(key []byte, envelope *SecureEnvelope) ([]byte, error) {
	if envelope == nil {
		return nil, errors.New("secure envelope missing")
	}
	if envelope.Version != secureEnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version: %d", envelope.Version)
	}
	nonce, err := hex.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to decode envelope nonce: %w", err)
	}
	ciphertext, err := hex.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode envelope ciphertext: %w", err)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize gcm: %w", err)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt envelope: %w", err)
	}
	return plaintext, nil
}
