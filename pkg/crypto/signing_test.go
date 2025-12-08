package crypto

import (
	"testing"
	"time"
)

func TestEd25519Signing(t *testing.T) {
	// Create signer
	signer, err := NewEd25519Signer("test-key-1")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test data
	testData := []byte("This is a test message for signing")

	// Sign data
	signature, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify signature
	err = signer.Verify(testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}

	// Test with tampered data
	tamperedData := []byte("This is a tampered message")
	err = signer.Verify(tamperedData, signature)
	if err == nil {
		t.Fatal("Verification should have failed for tampered data")
	}
}

func TestRSAPSSSigning(t *testing.T) {
	// Create signer
	signer, err := NewRSAPSSSigner("test-rsa-key-1")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Test data
	testData := []byte("This is a test message for RSA-PSS signing")

	// Sign data
	signature, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Verify signature
	err = signer.Verify(testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature: %v", err)
	}
}

func TestSignedData(t *testing.T) {
	signer, err := NewEd25519Signer("test-key-2")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	testData := []byte("Test data for signed package")

	// Create signed data
	signedData, err := CreateSignedData(signer, testData)
	if err != nil {
		t.Fatalf("Failed to create signed data: %v", err)
	}

	// Verify signed data
	err = VerifySignedData(signer, signedData)
	if err != nil {
		t.Fatalf("Failed to verify signed data: %v", err)
	}

	// Check metadata
	if signedData.Algorithm != AlgorithmEd25519 {
		t.Errorf("Expected algorithm %s, got %s", AlgorithmEd25519, signedData.Algorithm)
	}

	if signedData.KeyID != "test-key-2" {
		t.Errorf("Expected key ID 'test-key-2', got %s", signedData.KeyID)
	}

	if time.Since(signedData.Timestamp) > time.Second {
		t.Error("Timestamp is too old")
	}
}

func TestKeyPersistence(t *testing.T) {
	// Create a signer
	signer, err := NewEd25519Signer("persistence-test")
	if err != nil {
		t.Fatalf("Failed to create signer: %v", err)
	}

	// Export private key
	privateKeyPEM, err := signer.ExportPrivateKey()
	if err != nil {
		t.Fatalf("Failed to export private key: %v", err)
	}

	// Export public key
	publicKeyPEM, err := signer.PublicKey()
	if err != nil {
		t.Fatalf("Failed to export public key: %v", err)
	}

	// Sign some data with original signer
	testData := []byte("Test data for persistence")
	signature, err := signer.Sign(testData)
	if err != nil {
		t.Fatalf("Failed to sign data: %v", err)
	}

	// Load signer from private key
	loadedSigner, err := LoadEd25519Signer("persistence-test", privateKeyPEM)
	if err != nil {
		t.Fatalf("Failed to load signer: %v", err)
	}

	// Verify signature with loaded signer
	err = loadedSigner.Verify(testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify signature with loaded signer: %v", err)
	}

	// Load verifier from public key
	verifier, err := LoadEd25519Verifier(publicKeyPEM)
	if err != nil {
		t.Fatalf("Failed to load verifier: %v", err)
	}

	// Verify with public key only
	err = verifier.Verify(testData, signature)
	if err != nil {
		t.Fatalf("Failed to verify with public key: %v", err)
	}
}

func BenchmarkEd25519Sign(b *testing.B) {
	signer, _ := NewEd25519Signer("bench-key")
	testData := []byte("Benchmark data for signing performance testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(testData)
	}
}

func BenchmarkEd25519Verify(b *testing.B) {
	signer, _ := NewEd25519Signer("bench-key")
	testData := []byte("Benchmark data for verification performance testing")
	signature, _ := signer.Sign(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.Verify(testData, signature)
	}
}

func BenchmarkRSAPSSSign(b *testing.B) {
	signer, _ := NewRSAPSSSigner("bench-rsa-key")
	testData := []byte("Benchmark data for RSA-PSS signing performance testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = signer.Sign(testData)
	}
}

func BenchmarkRSAPSSVerify(b *testing.B) {
	signer, _ := NewRSAPSSSigner("bench-rsa-key")
	testData := []byte("Benchmark data for RSA-PSS verification performance testing")
	signature, _ := signer.Sign(testData)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = signer.Verify(testData, signature)
	}
}
