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

	"github.com/oarkflow/licensing/pkg/licensing"
	"github.com/oarkflow/licensing/pkg/licensing/web"
	"github.com/oarkflow/licensing/pkg/utils"
)

// ==================== Main ====================

func main() {
	os.Setenv("LICENSE_SERVER_ALLOW_INSECURE_HTTP", "true")
	httpServer := flag.String("http-addr", ":8801", "HTTP server address")
	defaultAllowInsecure := envBool("LICENSE_SERVER_ALLOW_INSECURE_HTTP")
	allowInsecureHTTP := flag.Bool("allow-insecure-http", defaultAllowInsecure, "Allow HTTP without TLS (development only)")
	flag.Parse()
	if *httpServer == "" {
		*httpServer = ":8801"
	}
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager Server                 ║")
	fmt.Println("║    Hardware-Secured Licensing System      ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()
	os.Setenv("LICENSE_SERVER_BOOTSTRAP_DEMO", "true")
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
	if catalog, err := licensing.BootstrapSecretrProduct(ctx, storage); err != nil {
		log.Printf("⚠️ Failed to synchronize Secretr catalog: %v", err)
	} else {
		log.Printf("🧩 Synced Secretr catalog (%d features / %d plans)", len(catalog.Features), len(catalog.Plans))
	}
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
	server, err := licensing.NewServer(lm, *httpServer, apiKeys, rateLimiter, tlsCert, tlsKey, clientCA, *allowInsecureHTTP)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Initialize and attach web UI
	webServer, err := web.NewWebServer(lm)
	if err != nil {
		log.Fatalf("Failed to initialize web UI: %v", err)
	}
	server.SetWebHandler(webServer.Handler())
	log.Printf("🖥️  Web Admin UI available at %s", *httpServer)

	// Start HTTP server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
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
		{label: "Personal", email: "user-personal@example.com", planSlug: "personal", maxDevices: 1, durationDays: 365},
		{label: "Solo", email: "user-solo@example.com", planSlug: "solo", maxDevices: 3, durationDays: 365},
		{label: "Professional", email: "user-pro@example.com", planSlug: "professional", maxDevices: 10, durationDays: 365},
		{label: "Team", email: "user-team@example.com", planSlug: "team", maxDevices: 25, durationDays: 365},
		{label: "Startup", email: "user-startup@example.com", planSlug: "startup", maxDevices: 50, durationDays: 365},
		{label: "Enterprise", email: "user-enterprise@example.com", planSlug: "enterprise", maxDevices: 50, durationDays: 365},
		{label: "Trial", email: "user-trial@example.com", planSlug: "trial", maxDevices: 1, durationDays: 7},
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
	fmt.Println("   Personal      → Desktop + metadata context, CLI/API off")
	fmt.Println("   Solo          → Adds CLI bootstrap + 3 devices")
	fmt.Println("   Professional  → CLI + API automation, 10 devices")
	fmt.Println("   Team          → Adds MSP tooling, SSO, 25 devices")
	fmt.Println("   Startup       → Full platform, 50 devices")
	fmt.Println("   Enterprise    → All features, premium governance")
	fmt.Println("   Trial         → Same as Personal for 7 days")
	fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")
	fmt.Println()

	return nil
}
