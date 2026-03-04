package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/email"
	"github.com/oarkflow/licensing/pkg/licensing"
	"github.com/oarkflow/licensing/pkg/utils"
	"github.com/oarkflow/licensing/pkg/web"
)

// ==================== Main ====================

func main() {
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
	case "seed":
		runSeedCommand()
	case "reset":
		runResetCommand()
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
	fmt.Println("  licensing-server seed      - Seed the database with plans, features, and scopes")
	fmt.Println("  licensing-server reset     - Reset and reseed the database")
	fmt.Println()
	fmt.Println("Server options:")
	flag.PrintDefaults()
}

func runServerCommand() {
	httpServer := flag.String("http-addr", defaultHTTPAddr(), "HTTP server address")
	defaultAllowInsecure := envBool("LICENSE_SERVER_ALLOW_INSECURE_HTTP")
	allowInsecureHTTP := flag.Bool("allow-insecure-http", defaultAllowInsecure, "Allow HTTP without TLS (development only)")
	flag.Parse()
	if *httpServer == "" {
		*httpServer = ":6601"
	}
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager Server                 ║")
	fmt.Println("║    Hardware-Secured Licensing System      ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()
	// os.Setenv("LICENSE_SERVER_BOOTSTRAP_DEMO", "true")
	// Initialize storage + License Manager
	ctx := context.Background()
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
	if err := validateProductionHardening(storageMode, lm.SigningProviderID()); err != nil {
		log.Fatalf("Production hardening check failed: %v", err)
	}
	adminUsers, err := lm.ListAdminUsers(ctx)
	if err != nil {
		log.Fatalf("Failed to inspect admin users: %v", err)
	}
	if len(adminUsers) == 0 {
		log.Printf("🚩 No admin users found. Open the /setup page in your browser to create the first administrator.")
	}

	if shouldBootstrapDemoData() {
		if err := createDemoData(ctx, lm); err != nil {
			log.Printf("⚠️ Failed to bootstrap demo data: %v", err)
		}
	} else {
		log.Printf("📋 Demo bootstrap skipped (set LICENSE_SERVER_BOOTSTRAP_DEMO=true to enable)")
	}
	log.Printf("🔄 Applying default check policy to existing licenses...")
	if err := lm.BackfillLicenseCheckPolicy(ctx); err != nil {
		log.Fatalf("Failed to apply default check policy: %v", err)
	}
	log.Printf("✅ Default check policy applied")

	rawAPIKeys := os.Getenv("LICENSE_SERVER_API_KEYS")
	apiKeys := utils.ParseAPIKeys(rawAPIKeys)
	if len(apiKeys) == 0 {
		if single := strings.TrimSpace(os.Getenv("LICENSE_SERVER_API_KEY")); single != "" {
			apiKeys = append(apiKeys, single)
		}
	}
	if len(apiKeys) > 0 {
		log.Printf("🔐 Loaded %d legacy admin API key(s) from environment", len(apiKeys))
	} else {
		log.Printf("🔐 No legacy API keys configured - relying on stored user API keys")
	}
	rateLimiter := licensing.NewRateLimiter(30, time.Minute)
	tlsCert := os.Getenv("LICENSE_SERVER_TLS_CERT")
	tlsKey := os.Getenv("LICENSE_SERVER_TLS_KEY")
	clientCA := os.Getenv("LICENSE_SERVER_CLIENT_CA")
	if err := validateServerRuntime(*allowInsecureHTTP, tlsCert, tlsKey, apiKeys); err != nil {
		log.Fatalf("Invalid runtime configuration: %v", err)
	}
	server, err := licensing.NewServer(lm, *httpServer, apiKeys, rateLimiter, tlsCert, tlsKey, clientCA, *allowInsecureHTTP)
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
	log.Printf("🖥️  Web Admin UI available at %s", *httpServer)

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

func validateServerRuntime(allowInsecure bool, tlsCert, tlsKey string, apiKeys []string) error {
	if len(apiKeys) == 0 {
		log.Printf("⚠️ No legacy admin API keys in environment; rely on web setup/session auth and stored API keys")
	}
	env := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV")))
	if env == "prod" || env == "production" {
		if allowInsecure {
			return fmt.Errorf("insecure HTTP is forbidden when APP_ENV=%q", env)
		}
		if strings.TrimSpace(tlsCert) == "" || strings.TrimSpace(tlsKey) == "" {
			return fmt.Errorf("TLS cert/key are required when APP_ENV=%q", env)
		}
		if !envBoolDefault("LICENSE_SERVER_AUDIT_ENABLED", true) {
			return fmt.Errorf("audit logging cannot be disabled when APP_ENV=%q", env)
		}
	}
	return nil
}

func validateProductionHardening(storageMode, signingProviderID string) error {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV")))
	if env != "prod" && env != "production" {
		return nil
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LICENSE_SERVER_ALLOW_MEMORY_STORAGE_IN_PROD")), "true") {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(storageMode)), "memory") {
		return fmt.Errorf("memory storage is not allowed in production")
	}
	if strings.EqualFold(strings.TrimSpace(os.Getenv("LICENSE_SERVER_ALLOW_SOFTWARE_KEYS_IN_PROD")), "true") {
		return nil
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(signingProviderID)), "software-") {
		return fmt.Errorf("software signing provider is not allowed in production; use file or TPM provider")
	}
	return nil
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

func shouldBootstrapDemoData() bool {
	flag := strings.TrimSpace(os.Getenv("LICENSE_SERVER_BOOTSTRAP_DEMO"))
	if flag == "" {
		return false
	}
	switch strings.ToLower(flag) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func runSeedCommand() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager - Seed Database        ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	ctx := context.Background()
	storage, storageMode, err := licensing.BuildStorageFromEnv()
	if err != nil {
		log.Fatalf("Failed to configure storage: %v", err)
	}

	log.Printf("📦 Storage backend: %s", storageMode)

	if err := seedDatabase(ctx, storage); err != nil {
		log.Fatalf("Failed to seed database: %v", err)
	}

	log.Printf("✅ Database seeded successfully")
}

func runResetCommand() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager - Reset Database       ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	ctx := context.Background()
	storage, storageMode, err := licensing.BuildStorageFromEnv()
	if err != nil {
		log.Fatalf("Failed to configure storage: %v", err)
	}

	log.Printf("📦 Storage backend: %s", storageMode)

	// Reset database (clear existing data)
	if err := resetDatabase(ctx, storage); err != nil {
		log.Fatalf("Failed to reset database: %v", err)
	}

	// Seed fresh data
	if err := seedDatabase(ctx, storage); err != nil {
		log.Fatalf("Failed to seed database after reset: %v", err)
	}

	log.Printf("✅ Database reset and seeded successfully")
}

func seedDatabase(ctx context.Context, storage licensing.Storage) error {
	log.Printf("🧩 Seeding Secretr catalog...")

	catalog, err := licensing.BootstrapSecretrProduct(ctx, storage)
	if err != nil {
		return fmt.Errorf("bootstrap Secretr catalog: %w", err)
	}

	log.Printf("✅ Seeded Secretr catalog (%d features / %d plans)", len(catalog.Features), len(catalog.Plans))

	// Seed default email provider
	if err := seedDefaultEmailProvider(ctx, storage); err != nil {
		log.Printf("⚠️ Failed to seed default email provider: %v", err)
	} else {
		log.Printf("✅ Seeded default email provider")
	}

	return nil
}

func seedDefaultEmailProvider(ctx context.Context, storage licensing.Storage) error {
	// Check if any email providers already exist
	providers, err := storage.ListEmailProviders(ctx, true)
	if err != nil {
		return fmt.Errorf("check existing email providers: %w", err)
	}

	if len(providers) > 0 {
		log.Printf("📧 Email providers already exist, skipping default provider creation")
		return nil
	}

	// Create a default SMTP provider for development/testing
	defaultProvider := &email.EmailProvider{
		ID:   "default-smtp",
		Name: "Default SMTP",
		Slug: "default-smtp",
		Type: email.ProviderTypeSMTP,
		Config: map[string]any{
			"host":            "localhost",
			"port":            1025,
			"username":        "your-email@gmail.com",
			"password":        "your-app-password",
			"from_email":      "noreply@yourdomain.com",
			"from_name":       "Licensing System",
			"use_tls":         false,
			"start_tls":       false,
			"skip_tls_verify": true, // For development
			"timeout_seconds": 30,
		},
		Priority:       100,
		MaxRetries:     3,
		RetryBaseMS:    1000,
		RetryMaxMS:     60000,
		RetryJitterPct: 0.25,
		IsDefault:      true,
		Enabled:        false, // Disabled by default for security
		Metadata: map[string]string{
			"description": "Default SMTP provider - configure credentials and enable for email functionality",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	if err := storage.SaveEmailProvider(ctx, defaultProvider); err != nil {
		return fmt.Errorf("save default email provider: %w", err)
	}

	log.Printf("📧 Created default SMTP email provider (disabled by default)")
	log.Printf("   To enable: Configure SMTP credentials and set enabled=true")
	log.Printf("   Web UI: /messaging/providers")

	return nil
}

func resetDatabase(ctx context.Context, storage licensing.Storage) error {
	log.Printf("🗑️  Resetting database...")

	// For SQLite, we can recreate tables by dropping and recreating
	// For other storage backends, this might need different implementation
	if sqliteStorage, ok := storage.(*licensing.SQLiteStorage); ok {
		if err := sqliteStorage.ResetTables(ctx); err != nil {
			return fmt.Errorf("reset SQLite tables: %w", err)
		}
	} else {
		log.Printf("⚠️  Reset not implemented for storage type: %T", storage)
		log.Printf("   Manual reset may be required")
	}

	log.Printf("✅ Database reset complete")
	return nil
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

func createDemoData(ctx context.Context, lm *licensing.LicenseManager) error {
	log.Printf("📋 Syncing demo Secretr catalog and sample customers...")

	storage := lm.Storage()
	catalog, err := licensing.BootstrapSecretrProduct(ctx, storage)
	if err != nil {
		return fmt.Errorf("bootstrap Secretr catalog: %w", err)
	}

	product := catalog.Product

	type demoSeed struct {
		label        string
		email        string
		planSlug     string
		maxDevices   int
		durationDays int
	}

	demoUsers := []demoSeed{
		{label: "Trial", email: "user-trial@example.com", planSlug: "trial", maxDevices: 1, durationDays: 14},
		{label: "Personal", email: "user-personal@example.com", planSlug: "personal", maxDevices: 1, durationDays: 365},
		{label: "Solo", email: "user-solo@example.com", planSlug: "solo", maxDevices: 2, durationDays: 365},
		{label: "Team", email: "user-team@example.com", planSlug: "team", maxDevices: 5, durationDays: 365},
		{label: "Business", email: "user-business@example.com", planSlug: "business", maxDevices: 15, durationDays: 365},
		{label: "Enterprise", email: "user-enterprise@example.com", planSlug: "enterprise", maxDevices: 50, durationDays: 365},
	}

	type credentialInfo struct {
		label        string
		clientID     string
		email        string
		licenseKey   string
		planSlug     string
		planName     string
		entitlements *licensing.LicenseEntitlements
	}

	var credentials []credentialInfo
	mode, interval := lm.DefaultCheckPolicy()

	for _, seed := range demoUsers {
		plan, ok := catalog.Plans[seed.planSlug]
		if !ok {
			log.Printf("⚠️ Plan %s not found in catalog, skipping demo user %s", seed.planSlug, seed.email)
			continue
		}

		client, err := lm.CreateClient(ctx, seed.email)
		if err != nil {
			existing, lookupErr := lm.GetClientByEmail(ctx, seed.email)
			if lookupErr != nil {
				log.Printf("⚠️ Skipping demo client %s: %v", seed.email, err)
				continue
			}
			client = existing
			log.Printf("↺ Demo client already exists: %s (ID: %s)", client.Email, client.ID)
		}

		duration := time.Duration(seed.durationDays) * 24 * time.Hour
		if duration == 0 {
			duration = plan.TrialDuration()
		}
		if duration == 0 {
			duration = 365 * 24 * time.Hour
		}

		opts := &licensing.GenerateLicenseOptions{ProductID: product.ID, PlanID: plan.ID}
		license, err := lm.GenerateLicenseWithOptions(ctx, client.ID, duration, seed.maxDevices, plan.Slug, mode, interval, opts)
		if err != nil {
			log.Printf("⚠️ Failed to create demo license for %s: %v", client.Email, err)
			continue
		}

		entitlements, err := storage.ComputeLicenseEntitlements(ctx, product.ID, plan.ID)
		if err != nil {
			log.Printf("⚠️ Failed to compute entitlements for %s: %v", plan.Slug, err)
			continue
		}

		log.Printf("   ✓ Client: %s (ID: %s) | Plan: %s | License: %s", client.Email, client.ID, plan.Slug, license.LicenseKey)
		credentials = append(credentials, credentialInfo{
			label:        seed.label,
			clientID:     client.ID,
			email:        client.Email,
			licenseKey:   license.LicenseKey,
			planSlug:     plan.Slug,
			planName:     plan.Name,
			entitlements: entitlements,
		})
	}

	if len(credentials) == 0 {
		return nil
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Println("📄 Demo License Credentials with Permissions/Scopes")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")

	for i, cred := range credentials {
		userLetter := string(rune('A' + i))
		fmt.Println()
		fmt.Printf("👤 USER %s (%s): %s\n", userLetter, cred.label, cred.email)
		fmt.Printf("   Plan: %s (%s)\n", cred.planName, cred.planSlug)
		fmt.Printf("   Client ID: %s\n", cred.clientID)
		fmt.Printf("   License Key: %s\n", cred.licenseKey)
		fmt.Println("   ─────────────────────────────────────────────────────────────────────────────────────────────")

		if cred.entitlements != nil && len(cred.entitlements.Features) > 0 {
			fmt.Println("   📋 PERMISSIONS/SCOPES:")

			featSlugs := make([]string, 0, len(cred.entitlements.Features))
			for slug := range cred.entitlements.Features {
				featSlugs = append(featSlugs, slug)
			}
			sort.Strings(featSlugs)

			for fi, featSlug := range featSlugs {
				feat := cred.entitlements.Features[featSlug]
				if !feat.Enabled {
					continue
				}
				featPrefix := "├─"
				if fi == len(featSlugs)-1 {
					featPrefix = "└─"
				}
				fmt.Printf("      %s Feature: %s (%s)\n", featPrefix, feat.FeatureSlug, feat.Category)

				if len(feat.Scopes) == 0 {
					continue
				}

				scopeList := make([]string, 0, len(feat.Scopes))
				for scopeSlug := range feat.Scopes {
					scopeList = append(scopeList, scopeSlug)
				}
				sort.Strings(scopeList)

				for j, scopeSlug := range scopeList {
					scope := feat.Scopes[scopeSlug]
					prefix := "│     ├─"
					if fi == len(featSlugs)-1 {
						prefix = "      ├─"
					}
					if j == len(scopeList)-1 {
						if fi == len(featSlugs)-1 {
							prefix = "      └─"
						} else {
							prefix = "│     └─"
						}
					}

					permIcon := "✅"
					if scope.Permission == licensing.ScopePermissionDeny {
						permIcon = "❌"
					} else if scope.Permission == licensing.ScopePermissionLimit {
						permIcon = "⚠️"
					}

					limitStr := ""
					if scope.Limit > 0 {
						limitStr = fmt.Sprintf(" (limit: %d)", scope.Limit)
					}

					fmt.Printf("      %s %s %s [%s]%s\n", prefix, permIcon, scope.ScopeSlug, scope.Permission, limitStr)
				}
			}
		} else {
			fmt.Println("   📋 PERMISSIONS: No specific entitlements defined")
		}

		fmt.Println("   ─────────────────────────────────────────────────────────────────────────────────────────────")
		fmt.Printf("   📁 Save as license-%s.json:\n", cred.clientID)
		fmt.Printf(`   {"email": "%s", "client_id": "%s", "license_key": "%s"}`, cred.email, cred.clientID, cred.licenseKey)
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Println("📊 PERMISSION SUMMARY:")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Println("   Trial        → All features unlocked for 14 days evaluation")
	fmt.Println("   Personal     → Core secrets, SSH, generators, GUI, 1 GB storage")
	fmt.Println("   Solo         → + 2FA, P2P sharing, audit logs, version history, 5 GB storage")
	fmt.Println("   Team         → + Scratchpads, templates, rotation, bundles, 25 GB storage")
	fmt.Println("   Business     → + HTTP API, user management, ACLs, multi-tenant, sandbox, unlimited storage")
	fmt.Println("   Enterprise   → + Compliance, FIPS, classification, container runtime, HSM")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Println()

	return nil
}
