package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

type EncryptionAlgorithm string

const (
	AlgorithmAES256GCM EncryptionAlgorithm = "AES-256-GCM"
)

type Encryptor interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
	Algorithm() EncryptionAlgorithm
}

type AESGCMEncryptor struct {
	key       []byte
	algorithm EncryptionAlgorithm
}

func NewAESGCMEncryptor(key []byte) (*AESGCMEncryptor, error) {
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes for AES-256")
	}

	return &AESGCMEncryptor{
		key:       key,
		algorithm: AlgorithmAES256GCM,
	}, nil
}

func GenerateKey() ([]byte, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("failed to generate key: %w", err)
	}
	return key, nil
}

func DeriveKey(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, 1, 64*1024, 4, 32)
}

func (e *AESGCMEncryptor) Encrypt(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (e *AESGCMEncryptor) Decrypt(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(e.key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}

func (e *AESGCMEncryptor) Algorithm() EncryptionAlgorithm {
	return e.algorithm
}

type EncryptedData struct {
	Ciphertext string              `json:"ciphertext"`
	Algorithm  EncryptionAlgorithm `json:"algorithm"`
	KeyID      string              `json:"key_id,omitempty"`
}

func CreateEncryptedData(encryptor Encryptor, plaintext []byte, keyID string) (*EncryptedData, error) {
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	return &EncryptedData{
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
		Algorithm:  encryptor.Algorithm(),
		KeyID:      keyID,
	}, nil
}

func DecryptData(encryptor Encryptor, encryptedData *EncryptedData) ([]byte, error) {
	if encryptedData.Algorithm != encryptor.Algorithm() {
		return nil, fmt.Errorf("algorithm mismatch: expected %s, got %s",
			encryptor.Algorithm(), encryptedData.Algorithm)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(encryptedData.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("failed to decode ciphertext: %w", err)
	}

	return encryptor.Decrypt(ciphertext)
}

func HashData(data []byte) string {
	hash := sha256.Sum256(data)
	return base64.StdEncoding.EncodeToString(hash[:])
}

func VerifyHash(data []byte, expectedHash string) error {
	actualHash := HashData(data)
	if actualHash != expectedHash {
		return errors.New("hash verification failed")
	}
	return nil
}

func SecureCompare(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}

	var result byte
	for i := range a {
		result |= a[i] ^ b[i]
	}

	return result == 0
}
