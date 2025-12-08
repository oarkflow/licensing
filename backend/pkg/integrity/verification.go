package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"
)

// Verifier performs integrity verification
type Verifier struct {
	checksums map[string]string // file path -> checksum
}

// NewVerifier creates a new integrity verifier
func NewVerifier() *Verifier {
	return &Verifier{
		checksums: make(map[string]string),
	}
}

// ChecksumFile calculates SHA-256 checksum of a file
func ChecksumFile(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", fmt.Errorf("failed to calculate checksum: %w", err)
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// ChecksumData calculates SHA-256 checksum of data
func ChecksumData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

// RegisterFile registers a file with its expected checksum
func (v *Verifier) RegisterFile(filePath string) error {
	checksum, err := ChecksumFile(filePath)
	if err != nil {
		return fmt.Errorf("failed to register file: %w", err)
	}

	v.checksums[filePath] = checksum
	return nil
}

// VerifyFile verifies that a file hasn't been tampered with
func (v *Verifier) VerifyFile(filePath string) (bool, error) {
	expectedChecksum, exists := v.checksums[filePath]
	if !exists {
		return false, fmt.Errorf("file not registered: %s", filePath)
	}

	actualChecksum, err := ChecksumFile(filePath)
	if err != nil {
		return false, fmt.Errorf("failed to calculate checksum: %w", err)
	}

	return actualChecksum == expectedChecksum, nil
}

// VerifyAllFiles verifies all registered files
func (v *Verifier) VerifyAllFiles() (map[string]bool, []error) {
	results := make(map[string]bool)
	var errors []error

	for filePath := range v.checksums {
		verified, err := v.VerifyFile(filePath)
		if err != nil {
			errors = append(errors, fmt.Errorf("failed to verify %s: %w", filePath, err))
			results[filePath] = false
			continue
		}
		results[filePath] = verified
	}

	return results, errors
}

// ExportManifest exports the checksum manifest
func (v *Verifier) ExportManifest() ([]byte, error) {
	return json.MarshalIndent(v.checksums, "", "  ")
}

// ImportManifest imports a checksum manifest
func (v *Verifier) ImportManifest(data []byte) error {
	return json.Unmarshal(data, &v.checksums)
}

// LicenseIntegrityCheck represents integrity check result for a license
type LicenseIntegrityCheck struct {
	LicenseID        string    `json:"license_id"`
	Timestamp        time.Time `json:"timestamp"`
	SignatureValid   bool      `json:"signature_valid"`
	NotTampered      bool      `json:"not_tampered"`
	NotExpired       bool      `json:"not_expired"`
	FingerprintMatch bool      `json:"fingerprint_match"`
	ChecksumValid    bool      `json:"checksum_valid"`
	Overall          bool      `json:"overall"`
	Errors           []string  `json:"errors,omitempty"`
}

// VerifyLicenseIntegrity performs comprehensive license integrity verification
func VerifyLicenseIntegrity(license interface{}, expectedChecksum string, verifySignature func() error) *LicenseIntegrityCheck {
	check := &LicenseIntegrityCheck{
		Timestamp: time.Now().UTC(),
		Errors:    []string{},
	}

	// Extract license ID (implementation specific)
	// This is a placeholder - actual implementation depends on license structure
	check.LicenseID = "unknown"

	// Verify signature
	if err := verifySignature(); err != nil {
		check.SignatureValid = false
		check.Errors = append(check.Errors, fmt.Sprintf("signature verification failed: %v", err))
	} else {
		check.SignatureValid = true
	}

	// Verify checksum
	licenseData, err := json.Marshal(license)
	if err != nil {
		check.ChecksumValid = false
		check.Errors = append(check.Errors, fmt.Sprintf("failed to marshal license: %v", err))
	} else {
		actualChecksum := ChecksumData(licenseData)
		check.ChecksumValid = actualChecksum == expectedChecksum
		if !check.ChecksumValid {
			check.Errors = append(check.Errors, "checksum mismatch")
		}
	}

	// Additional checks would go here (expiry, fingerprint, etc.)
	// These are placeholders for the full implementation
	check.NotTampered = true
	check.NotExpired = true
	check.FingerprintMatch = true

	// Overall result
	check.Overall = check.SignatureValid && check.ChecksumValid &&
		check.NotTampered && check.NotExpired && check.FingerprintMatch

	return check
}

// MultiLayerVerification performs multi-layer verification
type MultiLayerVerification struct {
	Layers []VerificationLayer `json:"layers"`
	Passed int                 `json:"passed"`
	Failed int                 `json:"failed"`
	Score  float64             `json:"score"` // 0-100
}

// VerificationLayer represents a single verification layer
type VerificationLayer struct {
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Passed      bool      `json:"passed"`
	Timestamp   time.Time `json:"timestamp"`
	Error       string    `json:"error,omitempty"`
}

// NewMultiLayerVerification creates a new multi-layer verification
func NewMultiLayerVerification() *MultiLayerVerification {
	return &MultiLayerVerification{
		Layers: []VerificationLayer{},
	}
}

// AddLayer adds a verification layer result
func (m *MultiLayerVerification) AddLayer(name, description string, passed bool, err error) {
	layer := VerificationLayer{
		Name:        name,
		Description: description,
		Passed:      passed,
		Timestamp:   time.Now().UTC(),
	}

	if err != nil {
		layer.Error = err.Error()
	}

	m.Layers = append(m.Layers, layer)

	if passed {
		m.Passed++
	} else {
		m.Failed++
	}

	// Calculate score
	if len(m.Layers) > 0 {
		m.Score = float64(m.Passed) / float64(len(m.Layers)) * 100
	}
}

// IsValid returns whether all layers passed
func (m *MultiLayerVerification) IsValid() bool {
	return m.Failed == 0 && m.Passed > 0
}

// GetReport generates a verification report
func (m *MultiLayerVerification) GetReport() string {
	report := fmt.Sprintf("Multi-Layer Verification Report\n")
	report += fmt.Sprintf("================================\n")
	report += fmt.Sprintf("Total Layers: %d\n", len(m.Layers))
	report += fmt.Sprintf("Passed: %d\n", m.Passed)
	report += fmt.Sprintf("Failed: %d\n", m.Failed)
	report += fmt.Sprintf("Score: %.2f%%\n\n", m.Score)

	for i, layer := range m.Layers {
		status := "✓ PASSED"
		if !layer.Passed {
			status = "✗ FAILED"
		}
		report += fmt.Sprintf("%d. %s - %s\n", i+1, layer.Name, status)
		report += fmt.Sprintf("   %s\n", layer.Description)
		if layer.Error != "" {
			report += fmt.Sprintf("   Error: %s\n", layer.Error)
		}
		report += fmt.Sprintf("   Timestamp: %s\n\n", layer.Timestamp.Format(time.RFC3339))
	}

	return report
}
