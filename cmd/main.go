package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/audit"
	licensingclient "github.com/oarkflow/licensing/pkg/client"
	"github.com/oarkflow/licensing/pkg/licensing"
	"github.com/oarkflow/licensing/pkg/utils"
	"github.com/oarkflow/licensing/pkg/web"
	_ "modernc.org/sqlite"
)

var buildVersion = "dev"

// ==================== Main ====================

func main() {
	if err := loadDotEnvConfig(); err != nil {
		log.Fatalf("Failed to load dotenv configuration: %v", err)
	}

	// Check for help flag in any position
	for _, arg := range os.Args[1:] {
		if arg == "--help" || arg == "-h" || arg == "help" {
			printUsage()
			return
		}
	}

	// Find the first non-flag argument as the command
	var command string
	for i, arg := range os.Args[1:] {
		if !strings.HasPrefix(arg, "-") {
			command = arg
			// Shift args to remove the command for flag parsing
			if i > 0 {
				os.Args = append(os.Args[:1], os.Args[i+1:]...)
			} else {
				os.Args = os.Args[1:]
			}
			break
		}
	}

	// Execute command
	switch command {
	case "device-fingerprint", "fingerprint", "device":
		runDeviceFingerprintCommand()
	case "check-config":
		runCheckConfigCommand()
	case "audit-verify":
		runAuditVerifyCommand()
	case "server", "":
		runServerCommand()
	case "--help", "-h", "help":
		printUsage()
	default:
		runServerCommand()
	}
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("  licensing-server server    - Start the license server")
	fmt.Println("  licensing-server check-config - Validate production configuration without binding HTTP")
	fmt.Println("  licensing-server audit-verify - Verify the local audit hash chain without binding HTTP")
	fmt.Println("  licensing-server device-fingerprint - Print local device fingerprint info")
	fmt.Println()
	fmt.Println("Server options:")
	flag.PrintDefaults()
}

func runDeviceFingerprintCommand() {
	configDir := flag.String("config-dir", "", fmt.Sprintf("Directory for local licensing data (default $HOME/%s)", licensingclient.DefaultConfigDir))
	deviceKeyProvider := flag.String("device-key-provider", "software", "Device proof key provider: software, os, tpm, or auto")
	deviceKeyFile := flag.String("device-key-file", "", "Software device proof key file; use a persistent mounted path for containers")
	deviceKeyName := flag.String("device-key-name", "", "OS keyring account/key label")
	tpmDevice := flag.String("tpm-device", "", "TPM device path for device proof")
	jsonOutput := flag.Bool("json", false, "Print device identity as JSON")
	flag.Parse()

	client, err := licensingclient.New(licensingclient.Config{
		ConfigDir:         strings.TrimSpace(*configDir),
		DeviceKeyProvider: strings.TrimSpace(*deviceKeyProvider),
		DeviceKeyFile:     strings.TrimSpace(*deviceKeyFile),
		DeviceKeyName:     strings.TrimSpace(*deviceKeyName),
		TPMDevice:         strings.TrimSpace(*tpmDevice),
	})
	if err != nil {
		log.Fatalf("Failed to prepare device identity: %v", err)
	}
	identity, err := client.CurrentDeviceIdentity()
	if err != nil {
		log.Fatalf("Failed to read device identity: %v", err)
	}

	if *jsonOutput {
		encoded, err := json.MarshalIndent(identity, "", "  ")
		if err != nil {
			log.Fatalf("Failed to encode device identity: %v", err)
		}
		fmt.Println(string(encoded))
		return
	}

	fmt.Println("Device Fingerprint Info")
	fmt.Println("-----------------------")
	fmt.Printf("Fingerprint:          %s\n", identity.Fingerprint)
	fmt.Printf("Key ID:               %s\n", identity.KeyID)
	fmt.Printf("Key provider:         %s\n", identity.KeyProvider)
	fmt.Printf("Proof algorithm:      %s\n", identity.PublicKeyAlgorithm)
	if strings.TrimSpace(identity.HardwareFingerprint) != "" {
		fmt.Printf("Hardware fingerprint: %s\n", identity.HardwareFingerprint)
	}
	if strings.TrimSpace(identity.HardwareConfidence) != "" {
		fmt.Printf("Hardware confidence:  %s\n", identity.HardwareConfidence)
	}
	if strings.TrimSpace(identity.Platform) != "" {
		fmt.Printf("Platform:             %s\n", identity.Platform)
	}
	if strings.TrimSpace(identity.Label) != "" {
		fmt.Printf("Label:                %s\n", identity.Label)
	}
	fmt.Printf("Container:            %t\n", identity.IsContainer)
}

func runServerCommand() {
	httpServer := flag.String("http-addr", defaultHTTPAddr(), "HTTP server address")
	defaultAllowInsecure := envBool("LICENSE_SERVER_ALLOW_INSECURE_HTTP") || envBool("LICENSE_SERVER_TLS_TERMINATED_BY_PROXY")
	allowInsecureHTTP := flag.Bool("allow-insecure-http", defaultAllowInsecure, "Allow HTTP without local TLS (development or trusted reverse proxy only)")
	flag.Parse()
	if *httpServer == "" {
		*httpServer = ":6601"
	}
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager Server                 ║")
	fmt.Println("║    Hardware-Secured Licensing System      ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()
	ctx := context.Background()

	runWithDistributionLicense(ctx, func(ctx context.Context) {
		runLicensedServer(ctx, *httpServer, *allowInsecureHTTP)
	})
}

func runCheckConfigCommand() {
	httpServer := flag.String("http-addr", defaultHTTPAddr(), "HTTP server address")
	defaultAllowInsecure := envBool("LICENSE_SERVER_ALLOW_INSECURE_HTTP") || envBool("LICENSE_SERVER_TLS_TERMINATED_BY_PROXY")
	allowInsecureHTTP := flag.Bool("allow-insecure-http", defaultAllowInsecure, "Allow HTTP without local TLS (development or trusted reverse proxy only)")
	flag.Parse()
	apiKeys := legacyAPIKeysFromEnv()
	cfg := productionConfigFromEnv(*httpServer, *allowInsecureHTTP, apiKeys)
	if err := validateProductionConfig(cfg); err != nil {
		log.Fatalf("Configuration check failed: %v", err)
	}
	fmt.Println("configuration ok")
}

func runAuditVerifyCommand() {
	limit := flag.Int("limit", 50000, "Maximum audit events to verify")
	auditPath := flag.String("audit-db", defaultAuditDBPath(), "SQLite audit database path")
	flag.Parse()
	if strings.TrimSpace(*auditPath) == "" {
		log.Fatalf("Audit database path is required")
	}
	db, err := sql.Open("sqlite", filepath.Clean(*auditPath))
	if err != nil {
		log.Fatalf("Failed to open audit database: %v", err)
	}
	defer db.Close()
	storage, err := audit.NewSQLiteStorage(db)
	if err != nil {
		log.Fatalf("Failed to initialize audit storage: %v", err)
	}
	logger, err := audit.NewAuditLogger(&audit.AuditLoggerConfig{
		Storage:        storage,
		Async:          false,
		EnableChaining: true,
	})
	if err != nil {
		log.Fatalf("Failed to initialize audit verifier: %v", err)
	}
	defer logger.Close()
	filter := &audit.AuditFilter{Limit: *limit}
	events, err := logger.Query(context.Background(), filter)
	if err != nil {
		log.Fatalf("Failed to read audit events: %v", err)
	}
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
	valid, errors := logger.VerifyChain(context.Background(), events)
	if !valid {
		fmt.Printf("audit chain invalid: checked=%d errors=%d\n", len(events), len(errors))
		for _, errMsg := range errors {
			fmt.Printf("- %s\n", errMsg)
		}
		os.Exit(1)
	}
	fmt.Printf("audit chain valid: checked=%d\n", len(events))
}

func runLicensedServer(ctx context.Context, httpServer string, allowInsecureHTTP bool) {
	// Initialize storage + License Manager
	storage, storageMode, err := licensing.BuildStorageFromEnv()
	if err != nil {
		log.Fatalf("Failed to configure storage: %v", err)
	}
	lm, err := licensing.NewLicenseManager(storage)
	if err != nil {
		log.Fatalf("Failed to initialize License Manager: %v", err)
	}
	mode, interval, err := resolveDefaultCheckPolicyFromEnv()
	if err != nil {
		log.Fatalf("Invalid default check policy: %v", err)
	}
	lm.SetDefaultCheckPolicy(mode, interval)
	defer func() {
		if err := lm.Close(); err != nil {
			log.Printf("Error closing license manager: %v", err)
		}
	}()
	log.Printf("📦 Storage backend: %s", storageMode)
	if pubPath := lm.PublicKeyPath(); pubPath != "" {
		log.Printf("🔑 Public key stored at %s", pubPath)
	}
	log.Printf("🔏 Signing provider: %s", lm.SigningProviderID())
	adminUsers, err := lm.ListAdminUsers(ctx)
	if err != nil {
		log.Fatalf("Failed to inspect admin users: %v", err)
	}
	if len(adminUsers) == 0 {
		log.Printf("🚩 No admin users found. Open the /setup page in your browser to create the first administrator.")
	}

	log.Printf("🔄 Applying default check policy to existing licenses...")
	if err := lm.BackfillLicenseCheckPolicy(ctx); err != nil {
		log.Fatalf("Failed to apply default check policy: %v", err)
	}
	log.Printf("✅ Default check policy applied")

	apiKeys := legacyAPIKeysFromEnv()
	if len(apiKeys) > 0 {
		log.Printf("🔐 Loaded %d legacy admin API key(s) from environment", len(apiKeys))
	} else {
		log.Printf("🔐 No legacy API keys configured - relying on stored user API keys")
	}
	rateLimitConfig, err := licensing.RateLimitConfigFromEnv()
	if err != nil {
		log.Fatalf("Invalid rate limit configuration: %v", err)
	}
	rateLimiter := licensing.NewRateLimiterWithConfig(rateLimitConfig)
	tlsCert := os.Getenv("LICENSE_SERVER_TLS_CERT")
	tlsKey := os.Getenv("LICENSE_SERVER_TLS_KEY")
	clientCA := os.Getenv("LICENSE_SERVER_CLIENT_CA")
	cfg := productionConfigFromEnv(httpServer, allowInsecureHTTP, apiKeys)
	cfg.StorageMode = storageMode
	cfg.SigningProviderID = lm.SigningProviderID()
	cfg.TLSCert = tlsCert
	cfg.TLSKey = tlsKey
	if err := validateProductionConfig(cfg); err != nil {
		log.Fatalf("Invalid runtime configuration: %v", err)
	}
	server, err := licensing.NewServer(lm, httpServer, apiKeys, rateLimiter, tlsCert, tlsKey, clientCA, allowInsecureHTTP)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Initialize and attach web UI
	webServer, err := web.NewWebServer(lm)
	if err != nil {
		log.Fatalf("Failed to initialize web UI: %v", err)
	}
	webServer.SetServer(server)
	server.SetWebHandler(webServer.Handler())
	server.SetSessionValidator(webServer) // Enable session-based auth for API endpoints
	log.Printf("🖥️  Web Admin UI available at %s", httpServer)

	// Start HTTP server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func defaultHTTPAddr() string {
	if raw := strings.TrimSpace(os.Getenv("LICENSE_SERVER_HTTP_ADDR")); raw != "" {
		return raw
	}
	if raw := strings.TrimSpace(os.Getenv("PORT")); raw != "" {
		return ":" + strings.TrimPrefix(raw, ":")
	}
	return ":6601"
}

func legacyAPIKeysFromEnv() []string {
	apiKeys := utils.ParseAPIKeys(os.Getenv("LICENSE_SERVER_API_KEYS"))
	if len(apiKeys) == 0 {
		if single := strings.TrimSpace(os.Getenv("LICENSE_SERVER_API_KEY")); single != "" {
			apiKeys = append(apiKeys, single)
		}
	}
	return apiKeys
}

type productionConfig struct {
	HTTPAddr           string
	AllowInsecure      bool
	StorageMode        string
	SQLitePath         string
	FileStoragePath    string
	TLSCert            string
	TLSKey             string
	ProxyTLSTerminated bool
	AuditPath          string
	BackupMarkerPath   string
	SigningProviderID  string
	KeyProvider        string
	KeyFile            string
	LegacyAPIKeys      []string
}

func productionConfigFromEnv(httpAddr string, allowInsecure bool, apiKeys []string) productionConfig {
	return productionConfig{
		HTTPAddr:           httpAddr,
		AllowInsecure:      allowInsecure,
		StorageMode:        storageModeFromEnv(),
		SQLitePath:         strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_SQLITE_PATH")),
		FileStoragePath:    strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_FILE")),
		TLSCert:            strings.TrimSpace(os.Getenv("LICENSE_SERVER_TLS_CERT")),
		TLSKey:             strings.TrimSpace(os.Getenv("LICENSE_SERVER_TLS_KEY")),
		ProxyTLSTerminated: envBool("LICENSE_SERVER_TLS_TERMINATED_BY_PROXY"),
		AuditPath:          strings.TrimSpace(os.Getenv("LICENSE_SERVER_AUDIT_DB_PATH")),
		BackupMarkerPath:   strings.TrimSpace(os.Getenv("LICENSE_SERVER_BACKUP_MARKER_FILE")),
		SigningProviderID:  signingProviderIDFromEnv(),
		KeyProvider:        strings.TrimSpace(os.Getenv("LICENSE_SERVER_KEY_PROVIDER")),
		KeyFile:            strings.TrimSpace(os.Getenv("LICENSE_SERVER_KEY_FILE")),
		LegacyAPIKeys:      apiKeys,
	}
}

func storageModeFromEnv() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE")))
	if mode == "" || mode == "sql" || mode == "sqlite3" {
		return "sqlite"
	}
	return mode
}

func signingProviderIDFromEnv() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LICENSE_SERVER_KEY_PROVIDER")))
	switch mode {
	case "", "software", "memory", "soft", "dev":
		return "software"
	default:
		return mode
	}
}

func validateProductionConfig(cfg productionConfig) error {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV")))
	if len(cfg.LegacyAPIKeys) == 0 {
		log.Printf("⚠️ No legacy admin API keys in environment; rely on web setup/session auth and stored API keys")
	}
	if env != "prod" && env != "production" {
		return nil
	}

	if cfg.AllowInsecure && !cfg.ProxyTLSTerminated {
		return fmt.Errorf("insecure HTTP is forbidden when APP_ENV=%q unless LICENSE_SERVER_TLS_TERMINATED_BY_PROXY=true", env)
	}
	if cfg.ProxyTLSTerminated && !cfg.AllowInsecure {
		return fmt.Errorf("LICENSE_SERVER_TLS_TERMINATED_BY_PROXY=true requires internal HTTP; set LICENSE_SERVER_ALLOW_INSECURE_HTTP=true or do not pass --allow-insecure-http=false")
	}
	if !cfg.ProxyTLSTerminated {
		if strings.TrimSpace(cfg.TLSCert) == "" || strings.TrimSpace(cfg.TLSKey) == "" {
			return fmt.Errorf("TLS cert/key are required when APP_ENV=%q unless LICENSE_SERVER_TLS_TERMINATED_BY_PROXY=true", env)
		}
		if err := requireReadableAbsFile("TLS certificate", cfg.TLSCert); err != nil {
			return err
		}
		if err := requireReadableAbsFile("TLS key", cfg.TLSKey); err != nil {
			return err
		}
	}
	if !envBoolDefault("LICENSE_SERVER_AUDIT_ENABLED", true) {
		return fmt.Errorf("audit logging cannot be disabled when APP_ENV=%q", env)
	}
	if len(cfg.LegacyAPIKeys) > 0 && !envBool("LICENSE_SERVER_ALLOW_LEGACY_ENV_KEYS_IN_PROD") {
		return fmt.Errorf("legacy env API keys are disabled in production; use stored scoped API keys or set LICENSE_SERVER_ALLOW_LEGACY_ENV_KEYS_IN_PROD=true for break-glass")
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.StorageMode))
	if mode == "" {
		mode = "sqlite"
	}
	if mode == "memory" && !envBool("LICENSE_SERVER_ALLOW_MEMORY_STORAGE_IN_PROD") {
		return fmt.Errorf("memory storage is not allowed in production")
	}
	if mode == "file" || mode == "disk" || mode == "persistent" {
		return fmt.Errorf("file/json storage is not allowed in production; use sqlite")
	}
	if mode != "sqlite" && !strings.HasPrefix(mode, "sqlite:") {
		return fmt.Errorf("unsupported production storage mode %q; use sqlite", cfg.StorageMode)
	}
	sqlitePath := strings.TrimSpace(cfg.SQLitePath)
	if sqlitePath == "" && strings.HasPrefix(strings.ToLower(strings.TrimSpace(cfg.StorageMode)), "sqlite:") {
		sqlitePath = strings.TrimPrefix(strings.TrimSpace(cfg.StorageMode), "sqlite:")
	}
	if sqlitePath == "" {
		return fmt.Errorf("LICENSE_SERVER_STORAGE_SQLITE_PATH must be set to an absolute managed SQLite path in production")
	}
	if !filepath.IsAbs(sqlitePath) {
		return fmt.Errorf("sqlite path must be absolute in production: %s", sqlitePath)
	}
	if filepath.Base(filepath.Clean(sqlitePath)) == "licensing.db" && filepath.Dir(filepath.Clean(sqlitePath)) == "." {
		return fmt.Errorf("sqlite path must not be local licensing.db in production")
	}
	if cfg.AuditPath != "" && !filepath.IsAbs(cfg.AuditPath) {
		return fmt.Errorf("audit database path must be absolute in production: %s", cfg.AuditPath)
	}
	if cfg.BackupMarkerPath != "" && !filepath.IsAbs(cfg.BackupMarkerPath) {
		return fmt.Errorf("backup marker path must be absolute in production: %s", cfg.BackupMarkerPath)
	}
	signingProvider := strings.ToLower(strings.TrimSpace(cfg.SigningProviderID))
	if signingProvider == "" {
		signingProvider = signingProviderIDFromEnv()
	}
	if (signingProvider == "software" || strings.HasPrefix(signingProvider, "software-")) && !envBool("LICENSE_SERVER_ALLOW_SOFTWARE_KEYS_IN_PROD") {
		return fmt.Errorf("software signing provider is not allowed in production; use file or TPM provider")
	}
	keyProvider := strings.ToLower(strings.TrimSpace(cfg.KeyProvider))
	if keyProvider == "file" || keyProvider == "pem" {
		if err := requireReadableAbsFile("signing key", cfg.KeyFile); err != nil {
			return err
		}
	}
	return nil
}

func requireReadableAbsFile(label, path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("%s path is required", label)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s path must be absolute in production: %s", label, path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("%s path is not readable: %w", label, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s path must be a file, got directory: %s", label, path)
	}
	return nil
}

func defaultAuditDBPath() string {
	if auditPath := strings.TrimSpace(os.Getenv("LICENSE_SERVER_AUDIT_DB_PATH")); auditPath != "" {
		return auditPath
	}
	if sqlitePath := strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_SQLITE_PATH")); sqlitePath != "" {
		return sqlitePath
	}
	if homeDir, err := os.UserHomeDir(); err == nil {
		return filepath.Join(homeDir, ".licensing", "data", "audit.db")
	}
	return "./data/audit.db"
}

func envBoolDefault(key string, defaultVal bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultVal
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func envBool(key string) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch val {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func resolveDefaultCheckPolicyFromEnv() (licensing.LicenseCheckMode, time.Duration, error) {
	modeRaw := strings.TrimSpace(os.Getenv("LICENSE_SERVER_DEFAULT_CHECK_MODE"))
	intervalRaw := strings.TrimSpace(os.Getenv("LICENSE_SERVER_DEFAULT_CHECK_INTERVAL"))
	mode := licensing.LicenseCheckModeYearly
	if modeRaw != "" {
		mode = licensing.ParseLicenseCheckMode(modeRaw)
	}
	var interval time.Duration
	if mode == licensing.LicenseCheckModeCustom {
		if intervalRaw != "" {
			parsed, err := time.ParseDuration(intervalRaw)
			if err != nil {
				return licensing.LicenseCheckModeYearly, 0, fmt.Errorf("invalid LICENSE_SERVER_DEFAULT_CHECK_INTERVAL: %w", err)
			}
			interval = parsed
		}
	}
	return mode, interval, nil
}
