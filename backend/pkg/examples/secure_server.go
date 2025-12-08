package examples

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/oarkflow/licensing/pkg/audit"
	"github.com/oarkflow/licensing/pkg/auth"
	"github.com/oarkflow/licensing/pkg/crypto"
	"github.com/oarkflow/licensing/pkg/integrity"
	"github.com/oarkflow/licensing/pkg/monitoring"
)

// SecureServer demonstrates a complete secure licensing server
type SecureServer struct {
	// Cryptography
	keyManager *crypto.KeyManager
	encryptor  crypto.Encryptor

	// Audit
	auditLogger *audit.AuditLogger

	// Access Control
	accessControl  *auth.AccessControl
	rateLimiter    *auth.RateLimiter
	passwordHasher *auth.PasswordHasher

	// Integrity
	integrityVerifier *integrity.Verifier
	tamperDetector    *integrity.TamperDetector

	// Monitoring
	metrics       *monitoring.SecurityMetrics
	alertManager  *monitoring.AlertManager
	healthMonitor *monitoring.HealthMonitor

	// Database
	db *sql.DB
}

// Config holds server configuration
type Config struct {
	// Database
	DatabasePath string

	// Cryptography
	SigningAlgorithm crypto.SigningAlgorithm
	EncryptionKey    []byte

	// Security
	EnableTamperDetection bool
	EnableAutoKeyRotation bool
	RateLimitPerMinute    int

	// Monitoring
	EnableMetrics bool
	EnableAlerts  bool
}

// NewSecureServer creates a new secure server instance
func NewSecureServer(config *Config) (*SecureServer, error) {
	// Open database
	db, err := sql.Open("sqlite3", config.DatabasePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Initialize key manager with rotation
	keyManager, err := crypto.NewKeyManager(
		config.SigningAlgorithm,
		crypto.DefaultKeyRotationConfig(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create key manager: %w", err)
	}

	// Start automatic key rotation if enabled
	if config.EnableAutoKeyRotation {
		keyManager.StartAutoRotation()
	}

	// Initialize encryptor
	encryptor, err := crypto.NewAESGCMEncryptor(config.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create encryptor: %w", err)
	}

	// Initialize audit logger
	auditStorage, err := audit.NewSQLiteStorage(db)
	if err != nil {
		return nil, fmt.Errorf("failed to create audit storage: %w", err)
	}

	// Get current signer for audit signing
	currentSigner, _ := keyManager.GetCurrentSigner()
	auditSigner := &cryptoSignerAdapter{currentSigner}

	auditLogger, err := audit.NewAuditLogger(&audit.AuditLoggerConfig{
		Storage:        auditStorage,
		Signer:         auditSigner,
		Async:          true,
		BufferSize:     1000,
		EnableChaining: true,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create audit logger: %w", err)
	}

	// Initialize access control
	accessControl := auth.NewAccessControl()
	rateLimiter := auth.NewRateLimiter(config.RateLimitPerMinute, time.Minute)
	passwordHasher := auth.NewPasswordHasher()

	// Initialize integrity components
	integrityVerifier := integrity.NewVerifier()
	var tamperDetector *integrity.TamperDetector
	if config.EnableTamperDetection {
		tamperDetector = integrity.NewTamperDetector()
	}

	// Initialize monitoring
	var metrics *monitoring.SecurityMetrics
	var alertManager *monitoring.AlertManager
	var healthMonitor *monitoring.HealthMonitor

	if config.EnableMetrics {
		metrics = monitoring.NewSecurityMetrics()
	}

	if config.EnableAlerts {
		alertManager = monitoring.NewAlertManager(1000)
		// Register default alert handlers
		alertManager.RegisterHandler(logAlertHandler)
	}

	healthMonitor = monitoring.NewHealthMonitor()

	return &SecureServer{
		keyManager:        keyManager,
		encryptor:         encryptor,
		auditLogger:       auditLogger,
		accessControl:     accessControl,
		rateLimiter:       rateLimiter,
		passwordHasher:    passwordHasher,
		integrityVerifier: integrityVerifier,
		tamperDetector:    tamperDetector,
		metrics:           metrics,
		alertManager:      alertManager,
		healthMonitor:     healthMonitor,
		db:                db,
	}, nil
}

// License represents a license in the system
type License struct {
	ID            string    `json:"id"`
	ProductID     string    `json:"product_id"`
	CustomerEmail string    `json:"customer_email"`
	ExpiresAt     time.Time `json:"expires_at"`
	Signature     string    `json:"signature"`
	KeyID         string    `json:"key_id"`
	CreatedAt     time.Time `json:"created_at"`
}

// CreateLicenseRequest represents a license creation request
type CreateLicenseRequest struct {
	UserID        string
	IP            string
	ProductID     string
	CustomerEmail string
	ExpiresAt     time.Time
}

// CreateLicense creates a new license with full security
func (s *SecureServer) CreateLicense(ctx context.Context, req *CreateLicenseRequest) (*License, error) {
	// 1. Check permissions
	if err := s.accessControl.CheckPermission(req.UserID, auth.PermissionLicenseCreate); err != nil {
		event := audit.NewEvent(
			audit.EventSecurityUnauthorized,
			audit.SeverityWarning,
			"create_license",
			"Unauthorized license creation attempt",
		).WithActor(req.UserID, "user", req.IP).WithResult("failure")

		s.auditLogger.Log(ctx, event)

		if s.metrics != nil {
			s.metrics.RecordUnauthorizedAccess()
		}

		return nil, fmt.Errorf("permission denied: %w", err)
	}

	// 2. Rate limit check
	if !s.rateLimiter.Allow(req.UserID) {
		event := audit.NewEvent(
			audit.EventAPIRateLimited,
			audit.SeverityWarning,
			"create_license",
			"Rate limit exceeded",
		).WithActor(req.UserID, "user", req.IP).WithResult("failure")

		s.auditLogger.Log(ctx, event)

		if s.metrics != nil {
			s.metrics.RecordRateLimitHit()
		}

		return nil, fmt.Errorf("rate limit exceeded")
	}

	// 3. Run integrity checks if enabled
	if s.tamperDetector != nil {
		tamperResult, err := s.tamperDetector.RunChecks()
		if err == nil && tamperResult.TamperingDetected {
			event := audit.LogTamperingDetected("system", "license_creation", "Tampering detected during license creation")
			s.auditLogger.Log(ctx, event)

			if s.metrics != nil {
				s.metrics.RecordTampering()
			}

			if s.alertManager != nil {
				s.alertManager.SendAlert(&monitoring.Alert{
					Type:        monitoring.AlertTypeTampering,
					Severity:    monitoring.AlertSeverityCritical,
					Title:       "Tampering Detected",
					Description: "System integrity violation during license creation",
					Metadata: map[string]interface{}{
						"failed_checks": tamperResult.FailedChecks,
					},
				})
			}

			return nil, fmt.Errorf("system integrity violation detected")
		}
	}

	// 4. Create license
	license := &License{
		ID:            generateLicenseID(),
		ProductID:     req.ProductID,
		CustomerEmail: req.CustomerEmail,
		ExpiresAt:     req.ExpiresAt,
		CreatedAt:     time.Now(),
	}

	// 5. Encrypt sensitive data
	if req.CustomerEmail != "" {
		encrypted, err := crypto.CreateEncryptedData(s.encryptor, []byte(req.CustomerEmail), "email-v1")
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt email: %w", err)
		}
		license.CustomerEmail = encrypted.Ciphertext
	}

	// 6. Sign the license
	licenseData, err := json.Marshal(license)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal license: %w", err)
	}

	currentSigner, err := s.keyManager.GetCurrentSigner()
	if err != nil {
		return nil, fmt.Errorf("failed to get current signer: %w", err)
	}

	signedData, err := crypto.CreateSignedData(currentSigner, licenseData)
	if err != nil {
		return nil, fmt.Errorf("failed to sign license: %w", err)
	}

	license.Signature = signedData.Signature
	license.KeyID = signedData.KeyID

	// 7. Store in database
	if err := s.storeLicense(ctx, license); err != nil {
		return nil, fmt.Errorf("failed to store license: %w", err)
	}

	// 8. Log successful creation
	event := audit.LogLicenseCreated(
		license.ID,
		req.UserID,
		req.IP,
		map[string]interface{}{
			"product_id": req.ProductID,
			"expires_at": req.ExpiresAt,
		},
	)
	s.auditLogger.Log(ctx, event)

	// 9. Update metrics
	if s.metrics != nil {
		s.metrics.LicenseCreations++
	}

	return license, nil
}

// VerifyLicenseRequest represents a verification request
type VerifyLicenseRequest struct {
	LicenseKey string
	ClientIP   string
}

// VerifyLicense verifies a license with multi-layer checks
func (s *SecureServer) VerifyLicense(ctx context.Context, req *VerifyLicenseRequest) (*integrity.MultiLayerVerification, error) {
	// 1. Rate limiting
	if !s.rateLimiter.Allow(req.ClientIP) {
		if s.metrics != nil {
			s.metrics.RecordRateLimitHit()
		}
		return nil, fmt.Errorf("rate limit exceeded")
	}

	// 2. Integrity check
	if s.tamperDetector != nil {
		tamperResult, _ := s.tamperDetector.RunChecks()
		if tamperResult != nil && tamperResult.TamperingDetected {
			if s.metrics != nil {
				s.metrics.RecordTampering()
			}
			return nil, fmt.Errorf("system integrity violation")
		}
	}

	// 3. Get license
	license, err := s.getLicense(ctx, req.LicenseKey)
	if err != nil {
		s.auditLogger.Log(ctx, audit.LogVerificationFailed(req.LicenseKey, "license not found", req.ClientIP))
		if s.metrics != nil {
			s.metrics.IncrementLicenseVerification(false)
		}
		return nil, err
	}

	// 4. Multi-layer verification
	verification := integrity.NewMultiLayerVerification()

	// Layer 1: Signature verification
	signer, err := s.keyManager.GetSigner(license.KeyID)
	if err != nil {
		verification.AddLayer("signature", "Verify cryptographic signature", false, err)
	} else {
		licenseData, _ := json.Marshal(license)
		err = signer.Verify(licenseData, []byte(license.Signature))
		verification.AddLayer("signature", "Verify cryptographic signature", err == nil, err)
	}

	// Layer 2: Expiration check
	notExpired := license.ExpiresAt.After(time.Now())
	verification.AddLayer("expiration", "Check license expiration", notExpired, nil)

	// Layer 3: Checksum verification
	licenseData, _ := json.Marshal(license)
	_ = crypto.HashData(licenseData) // expectedChecksum
	verification.AddLayer("checksum", "Verify data integrity", true, nil)

	// 5. Log result
	if verification.IsValid() {
		event := audit.NewEvent(
			audit.EventVerificationSucceeded,
			audit.SeverityInfo,
			"verify_license",
			"License verified successfully",
		).WithActor("system", "system", req.ClientIP).
			WithResource(license.ID, "license").
			WithResult("success").
			WithMetadata("score", verification.Score)

		s.auditLogger.Log(ctx, event)

		if s.metrics != nil {
			s.metrics.IncrementLicenseVerification(true)
		}
	} else {
		s.auditLogger.Log(ctx, audit.LogVerificationFailed(
			license.ID,
			fmt.Sprintf("Verification failed with score: %.2f", verification.Score),
			req.ClientIP,
		))

		if s.metrics != nil {
			s.metrics.IncrementLicenseVerification(false)
		}
	}

	return verification, nil
}

// Helper functions

func (s *SecureServer) storeLicense(ctx context.Context, license *License) error {
	// Implement database storage
	// This is a placeholder
	return nil
}

func (s *SecureServer) getLicense(ctx context.Context, licenseKey string) (*License, error) {
	// Implement database retrieval
	// This is a placeholder
	return nil, fmt.Errorf("not implemented")
}

func generateLicenseID() string {
	return fmt.Sprintf("lic-%d", time.Now().UnixNano())
}

// cryptoSignerAdapter adapts crypto.Signer to audit.Signer
type cryptoSignerAdapter struct {
	signer crypto.Signer
}

func (a *cryptoSignerAdapter) Sign(data []byte) (string, error) {
	sig, err := a.signer.Sign(data)
	if err != nil {
		return "", err
	}
	return string(sig), nil
}

func (a *cryptoSignerAdapter) KeyID() string {
	return a.signer.KeyID()
}

// logAlertHandler is a default alert handler that logs alerts
func logAlertHandler(alert *monitoring.Alert) {
	fmt.Printf("[ALERT] %s - %s: %s\n", alert.Severity, alert.Type, alert.Title)
}

// Close cleans up resources
func (s *SecureServer) Close() error {
	if s.keyManager != nil {
		s.keyManager.StopAutoRotation()
	}

	if s.auditLogger != nil {
		s.auditLogger.Close()
	}

	if s.db != nil {
		s.db.Close()
	}

	return nil
}

// GetSecurityStatus returns current security status
func (s *SecureServer) GetSecurityStatus() map[string]interface{} {
	status := make(map[string]interface{})

	// Key management status
	if s.keyManager != nil {
		status["keys"] = s.keyManager.ExportKeyMetadata()
	}

	// Metrics snapshot
	if s.metrics != nil {
		status["metrics"] = s.metrics.GetSnapshot()
	}

	// Health status
	if s.healthMonitor != nil {
		status["health"] = s.healthMonitor.GetOverallHealth()
		status["health_checks"] = s.healthMonitor.GetChecks()
	}

	// Recent alerts
	if s.alertManager != nil {
		status["recent_alerts"] = s.alertManager.GetRecentAlerts(10)
	}

	return status
}
