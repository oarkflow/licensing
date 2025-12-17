package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/crypto"
)

// SecurityConfig holds all security-related configuration
type SecurityConfig struct {
	// Database
	DatabasePath string

	// Cryptography
	SigningAlgorithm    crypto.SigningAlgorithm
	EncryptionKeyPath   string
	KeyRotationEnabled  bool
	KeyRotationInterval time.Duration
	KeyRetentionPeriod  time.Duration

	// Authentication
	RequireAuthentication bool
	SessionTimeout        time.Duration
	MaxLoginAttempts      int

	// Rate Limiting
	RateLimitEnabled   bool
	RateLimitPerMinute int
	RateLimitPerHour   int

	// Audit
	AuditEnabled        bool
	AuditAsync          bool
	AuditBufferSize     int
	AuditSigningEnabled bool

	// Integrity
	TamperDetectionEnabled bool
	IntegrityCheckInterval time.Duration
	DebuggerDetection      bool

	// Network Security
	TLSEnabled        bool
	TLSCertFile       string
	TLSKeyFile        string
	TLSClientCAFile   string
	RequireClientCert bool
	AllowedOrigins    []string

	// Monitoring
	MetricsEnabled      bool
	AlertsEnabled       bool
	HealthCheckEnabled  bool
	HealthCheckInterval time.Duration

	// Server
	ServerAddress   string
	ReadTimeout     time.Duration
	WriteTimeout    time.Duration
	ShutdownTimeout time.Duration
}

type LoadOptions struct {
	FilePath      string
	MigrtionTable string
	MigrationDir  string
}

// LoadFromEnv loads configuration from environment variables
func LoadFromEnv(opts LoadOptions) (*SecurityConfig, error) {
	filePath := strings.TrimSpace(opts.FilePath)
	if filePath == "" {
		filePath = strings.TrimSpace(getEnv("DB_PATH", "./licensing.db"))
	}
	config := &SecurityConfig{
		// Defaults
		DatabasePath:           filePath,
		SigningAlgorithm:       crypto.SigningAlgorithm(getEnv("SIGNING_ALGORITHM", string(crypto.AlgorithmEd25519))),
		EncryptionKeyPath:      getEnv("ENCRYPTION_KEY_PATH", "./keys/encryption.key"),
		KeyRotationEnabled:     getEnvBool("KEY_ROTATION_ENABLED", true),
		KeyRotationInterval:    getEnvDuration("KEY_ROTATION_INTERVAL", 90*24*time.Hour),
		KeyRetentionPeriod:     getEnvDuration("KEY_RETENTION_PERIOD", 365*24*time.Hour),
		RequireAuthentication:  getEnvBool("REQUIRE_AUTHENTICATION", true),
		SessionTimeout:         getEnvDuration("SESSION_TIMEOUT", 24*time.Hour),
		MaxLoginAttempts:       getEnvInt("MAX_LOGIN_ATTEMPTS", 5),
		RateLimitEnabled:       getEnvBool("RATE_LIMIT_ENABLED", true),
		RateLimitPerMinute:     getEnvInt("RATE_LIMIT_PER_MINUTE", 60),
		RateLimitPerHour:       getEnvInt("RATE_LIMIT_PER_HOUR", 1000),
		AuditEnabled:           getEnvBool("AUDIT_ENABLED", true),
		AuditAsync:             getEnvBool("AUDIT_ASYNC", true),
		AuditBufferSize:        getEnvInt("AUDIT_BUFFER_SIZE", 1000),
		AuditSigningEnabled:    getEnvBool("AUDIT_SIGNING_ENABLED", true),
		TamperDetectionEnabled: getEnvBool("TAMPER_DETECTION_ENABLED", true),
		IntegrityCheckInterval: getEnvDuration("INTEGRITY_CHECK_INTERVAL", 5*time.Minute),
		DebuggerDetection:      getEnvBool("DEBUGGER_DETECTION", true),
		TLSEnabled:             getEnvBool("TLS_ENABLED", true),
		TLSCertFile:            getEnv("TLS_CERT_FILE", "./certs/server.crt"),
		TLSKeyFile:             getEnv("TLS_KEY_FILE", "./certs/server.key"),
		TLSClientCAFile:        getEnv("TLS_CLIENT_CA_FILE", ""),
		RequireClientCert:      getEnvBool("REQUIRE_CLIENT_CERT", false),
		AllowedOrigins:         getEnvSlice("ALLOWED_ORIGINS", []string{"https://localhost:3000"}),
		MetricsEnabled:         getEnvBool("METRICS_ENABLED", true),
		AlertsEnabled:          getEnvBool("ALERTS_ENABLED", true),
		HealthCheckEnabled:     getEnvBool("HEALTH_CHECK_ENABLED", true),
		HealthCheckInterval:    getEnvDuration("HEALTH_CHECK_INTERVAL", 30*time.Second),
		ServerAddress:          getEnv("SERVER_ADDRESS", ":8443"),
		ReadTimeout:            getEnvDuration("READ_TIMEOUT", 10*time.Second),
		WriteTimeout:           getEnvDuration("WRITE_TIMEOUT", 10*time.Second),
		ShutdownTimeout:        getEnvDuration("SHUTDOWN_TIMEOUT", 30*time.Second),
	}

	return config, config.Validate()
}

// Validate validates the configuration
func (c *SecurityConfig) Validate() error {
	if c.DatabasePath == "" {
		return fmt.Errorf("database path is required")
	}

	if c.SigningAlgorithm != crypto.AlgorithmEd25519 && c.SigningAlgorithm != crypto.AlgorithmRSAPSS {
		return fmt.Errorf("invalid signing algorithm: %s", c.SigningAlgorithm)
	}

	if c.KeyRotationEnabled && c.KeyRotationInterval <= 0 {
		return fmt.Errorf("key rotation interval must be positive")
	}

	if c.RateLimitEnabled && c.RateLimitPerMinute <= 0 {
		return fmt.Errorf("rate limit per minute must be positive")
	}

	if c.TLSEnabled {
		if c.TLSCertFile == "" || c.TLSKeyFile == "" {
			return fmt.Errorf("TLS cert and key files are required when TLS is enabled")
		}
	}

	return nil
}

// ProductionConfig returns a secure production configuration
func ProductionConfig() *SecurityConfig {
	return &SecurityConfig{
		DatabasePath:           "./data/licensing.db",
		SigningAlgorithm:       crypto.AlgorithmEd25519,
		EncryptionKeyPath:      "./keys/encryption.key",
		KeyRotationEnabled:     true,
		KeyRotationInterval:    90 * 24 * time.Hour,
		KeyRetentionPeriod:     365 * 24 * time.Hour,
		RequireAuthentication:  true,
		SessionTimeout:         8 * time.Hour,
		MaxLoginAttempts:       3,
		RateLimitEnabled:       true,
		RateLimitPerMinute:     30,
		RateLimitPerHour:       500,
		AuditEnabled:           true,
		AuditAsync:             true,
		AuditBufferSize:        5000,
		AuditSigningEnabled:    true,
		TamperDetectionEnabled: true,
		IntegrityCheckInterval: 5 * time.Minute,
		DebuggerDetection:      true,
		TLSEnabled:             true,
		TLSCertFile:            "./certs/server.crt",
		TLSKeyFile:             "./certs/server.key",
		RequireClientCert:      true,
		AllowedOrigins:         []string{}, // No CORS in production by default
		MetricsEnabled:         true,
		AlertsEnabled:          true,
		HealthCheckEnabled:     true,
		HealthCheckInterval:    30 * time.Second,
		ServerAddress:          ":8443",
		ReadTimeout:            10 * time.Second,
		WriteTimeout:           10 * time.Second,
		ShutdownTimeout:        30 * time.Second,
	}
}

// DevelopmentConfig returns a development configuration
func DevelopmentConfig() *SecurityConfig {
	return &SecurityConfig{
		DatabasePath:           "./dev.db",
		SigningAlgorithm:       crypto.AlgorithmEd25519,
		EncryptionKeyPath:      "./dev-keys/encryption.key",
		KeyRotationEnabled:     false,
		KeyRotationInterval:    90 * 24 * time.Hour,
		KeyRetentionPeriod:     365 * 24 * time.Hour,
		RequireAuthentication:  true,
		SessionTimeout:         24 * time.Hour,
		MaxLoginAttempts:       10,
		RateLimitEnabled:       true,
		RateLimitPerMinute:     100,
		RateLimitPerHour:       5000,
		AuditEnabled:           true,
		AuditAsync:             true,
		AuditBufferSize:        1000,
		AuditSigningEnabled:    false,
		TamperDetectionEnabled: false,
		IntegrityCheckInterval: 10 * time.Minute,
		DebuggerDetection:      false,
		TLSEnabled:             false,
		RequireClientCert:      false,
		AllowedOrigins:         []string{"http://localhost:3000", "http://localhost:5173"},
		MetricsEnabled:         true,
		AlertsEnabled:          false,
		HealthCheckEnabled:     true,
		HealthCheckInterval:    60 * time.Second,
		ServerAddress:          ":8080",
		ReadTimeout:            30 * time.Second,
		WriteTimeout:           30 * time.Second,
		ShutdownTimeout:        5 * time.Second,
	}
}

// Helper functions for environment variables

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBool(key string, defaultValue bool) bool {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	b, err := strconv.ParseBool(value)
	if err != nil {
		return defaultValue
	}
	return b
}

func getEnvInt(key string, defaultValue int) int {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	i, err := strconv.Atoi(value)
	if err != nil {
		return defaultValue
	}
	return i
}

func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		return defaultValue
	}
	return d
}

func getEnvSlice(key string, defaultValue []string) []string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	// Simple comma-separated parsing
	// In production, consider using a proper parser
	return []string{value}
}
