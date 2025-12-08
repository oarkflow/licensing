package crypto

import (
	"bytes"
	"testing"
)

func TestAESGCMEncryption(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	encryptor, err := NewAESGCMEncryptor(key)
	if err != nil {
		t.Fatalf("Failed to create encryptor: %v", err)
	}

	plaintext := []byte("This is a secret message")
	ciphertext, err := encryptor.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Failed to encrypt: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("Ciphertext should differ from plaintext")
	}

	decrypted, err := encryptor.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Failed to decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatal("Decrypted text does not match")
	}
}

func TestHashData(t *testing.T) {
	testData := []byte("Test data")
	hash1 := HashData(testData)

	if hash1 == "" {
		t.Fatal("Hash should not be empty")
	}

	hash2 := HashData(testData)
	if hash1 != hash2 {
		t.Error("Hashes should be identical")
	}
}
