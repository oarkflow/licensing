package crypto

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// SigningAlgorithm represents the signature algorithm
type SigningAlgorithm string

const (
	AlgorithmEd25519 SigningAlgorithm = "Ed25519"
	AlgorithmRSAPSS  SigningAlgorithm = "RSA-PSS"
)

// Signer interface for digital signatures
type Signer interface {
	Sign(data []byte) ([]byte, error)
	Verify(data, signature []byte) error
	Algorithm() SigningAlgorithm
	PublicKey() ([]byte, error)
	KeyID() string
}

// Ed25519Signer implements Signer with Ed25519
type Ed25519Signer struct {
	privateKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
	keyID      string
}

// NewEd25519Signer creates a new Ed25519 signer
func NewEd25519Signer(keyID string) (*Ed25519Signer, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate Ed25519 key: %w", err)
	}

	return &Ed25519Signer{
		privateKey: priv,
		publicKey:  pub,
		keyID:      keyID,
	}, nil
}

// LoadEd25519Signer loads an Ed25519 signer from PEM-encoded private key
func LoadEd25519Signer(keyID string, privateKeyPEM []byte) (*Ed25519Signer, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	ed25519Key, ok := privateKey.(ed25519.PrivateKey)
	if !ok {
		return nil, errors.New("not an Ed25519 private key")
	}

	return &Ed25519Signer{
		privateKey: ed25519Key,
		publicKey:  ed25519Key.Public().(ed25519.PublicKey),
		keyID:      keyID,
	}, nil
}

// Sign signs data using Ed25519
func (s *Ed25519Signer) Sign(data []byte) ([]byte, error) {
	signature := ed25519.Sign(s.privateKey, data)
	return signature, nil
}

// Verify verifies a signature using Ed25519
func (s *Ed25519Signer) Verify(data, signature []byte) error {
	if !ed25519.Verify(s.publicKey, data, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// Algorithm returns the signing algorithm
func (s *Ed25519Signer) Algorithm() SigningAlgorithm {
	return AlgorithmEd25519
}

// PublicKey returns the PEM-encoded public key
func (s *Ed25519Signer) PublicKey() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// KeyID returns the key identifier
func (s *Ed25519Signer) KeyID() string {
	return s.keyID
}

// ExportPrivateKey exports the private key in PEM format
func (s *Ed25519Signer) ExportPrivateKey() ([]byte, error) {
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// RSAPSSSigner implements Signer with RSA-PSS
type RSAPSSSigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// NewRSAPSSSigner creates a new RSA-PSS signer with 4096-bit key
func NewRSAPSSSigner(keyID string) (*RSAPSSSigner, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &RSAPSSSigner{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
	}, nil
}

// LoadRSAPSSSigner loads an RSA-PSS signer from PEM-encoded private key
func LoadRSAPSSSigner(keyID string, privateKeyPEM []byte) (*RSAPSSSigner, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try PKCS1 format
		privateKey, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := privateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an RSA private key")
	}

	return &RSAPSSSigner{
		privateKey: rsaKey,
		publicKey:  &rsaKey.PublicKey,
		keyID:      keyID,
	}, nil
}

// Sign signs data using RSA-PSS
func (s *RSAPSSSigner) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)
	signature, err := rsa.SignPSS(rand.Reader, s.privateKey, crypto.SHA256, hash[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}
	return signature, nil
}

// Verify verifies a signature using RSA-PSS
func (s *RSAPSSSigner) Verify(data, signature []byte) error {
	hash := sha256.Sum256(data)
	err := rsa.VerifyPSS(s.publicKey, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// Algorithm returns the signing algorithm
func (s *RSAPSSSigner) Algorithm() SigningAlgorithm {
	return AlgorithmRSAPSS
}

// PublicKey returns the PEM-encoded public key
func (s *RSAPSSSigner) PublicKey() ([]byte, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(s.publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// KeyID returns the key identifier
func (s *RSAPSSSigner) KeyID() string {
	return s.keyID
}

// ExportPrivateKey exports the private key in PEM format
func (s *RSAPSSSigner) ExportPrivateKey() ([]byte, error) {
	privKeyBytes := x509.MarshalPKCS1PrivateKey(s.privateKey)

	block := &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privKeyBytes,
	}

	return pem.EncodeToMemory(block), nil
}

// SignedData represents signed data with metadata
type SignedData struct {
	Data      []byte           `json:"data"`
	Signature string           `json:"signature"`
	Algorithm SigningAlgorithm `json:"algorithm"`
	KeyID     string           `json:"key_id"`
	Timestamp time.Time        `json:"timestamp"`
}

// CreateSignedData creates a signed data package
func CreateSignedData(signer Signer, data []byte) (*SignedData, error) {
	signature, err := signer.Sign(data)
	if err != nil {
		return nil, fmt.Errorf("failed to sign data: %w", err)
	}

	return &SignedData{
		Data:      data,
		Signature: base64.StdEncoding.EncodeToString(signature),
		Algorithm: signer.Algorithm(),
		KeyID:     signer.KeyID(),
		Timestamp: time.Now().UTC(),
	}, nil
}

// VerifySignedData verifies a signed data package
func VerifySignedData(signer Signer, signedData *SignedData) error {
	if signedData.KeyID != signer.KeyID() {
		return fmt.Errorf("key ID mismatch: expected %s, got %s", signer.KeyID(), signedData.KeyID)
	}

	if signedData.Algorithm != signer.Algorithm() {
		return fmt.Errorf("algorithm mismatch: expected %s, got %s", signer.Algorithm(), signedData.Algorithm)
	}

	signature, err := base64.StdEncoding.DecodeString(signedData.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %w", err)
	}

	return signer.Verify(signedData.Data, signature)
}

// Verifier for public key only verification
type Verifier interface {
	Verify(data, signature []byte) error
	Algorithm() SigningAlgorithm
}

// Ed25519Verifier verifies Ed25519 signatures with public key only
type Ed25519Verifier struct {
	publicKey ed25519.PublicKey
}

// LoadEd25519Verifier loads a verifier from PEM-encoded public key
func LoadEd25519Verifier(publicKeyPEM []byte) (*Ed25519Verifier, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	ed25519Key, ok := publicKey.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not an Ed25519 public key")
	}

	return &Ed25519Verifier{
		publicKey: ed25519Key,
	}, nil
}

// Verify verifies an Ed25519 signature
func (v *Ed25519Verifier) Verify(data, signature []byte) error {
	if !ed25519.Verify(v.publicKey, data, signature) {
		return errors.New("signature verification failed")
	}
	return nil
}

// Algorithm returns the algorithm
func (v *Ed25519Verifier) Algorithm() SigningAlgorithm {
	return AlgorithmEd25519
}

// RSAPSSVerifier verifies RSA-PSS signatures with public key only
type RSAPSSVerifier struct {
	publicKey *rsa.PublicKey
}

// LoadRSAPSSVerifier loads a verifier from PEM-encoded public key
func LoadRSAPSSVerifier(publicKeyPEM []byte) (*RSAPSSVerifier, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	publicKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := publicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("not an RSA public key")
	}

	return &RSAPSSVerifier{
		publicKey: rsaKey,
	}, nil
}

// Verify verifies an RSA-PSS signature
func (v *RSAPSSVerifier) Verify(data, signature []byte) error {
	hash := sha256.Sum256(data)
	err := rsa.VerifyPSS(v.publicKey, crypto.SHA256, hash[:], signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
	if err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// Algorithm returns the algorithm
func (v *RSAPSSVerifier) Algorithm() SigningAlgorithm {
	return AlgorithmRSAPSS
}
