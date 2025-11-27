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
	adminUser, bootstrapPassword, bootstrapKey, err := lm.EnsureDefaultAdmin(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize admin user: %v", err)
	}
	if adminUser != nil {
		log.Printf("🆕 Default admin user created: %s", adminUser.Username)
		log.Printf("   Temporary password: %s", bootstrapPassword)
		log.Printf("   Bootstrap API key: %s", bootstrapKey)
		log.Printf("   Rotate these credentials immediately after logging in.")
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
	log.Printf("📋 Creating demo product, features, plans, and licenses...")

	storage := lm.Storage()

	// ==================== Create Product ====================
	product := &licensing.Product{
		ID:          "prod_demo_001",
		Name:        "Demo Application",
		Slug:        "demo-app",
		Description: "A demo application with GUI, CLI, and API capabilities",
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}
	if err := storage.SaveProduct(ctx, product); err != nil {
		log.Printf("↺ Product already exists or error: %v", err)
	} else {
		log.Printf("   ✓ Created product: %s", product.Name)
	}

	// ==================== Create Features ====================
	features := []*licensing.Feature{
		{
			ID:          "feat_gui",
			ProductID:   product.ID,
			Name:        "GUI Access",
			Slug:        "gui",
			Description: "Access to graphical user interface",
			Category:    "interface",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "feat_cli",
			ProductID:   product.ID,
			Name:        "CLI Access",
			Slug:        "cli",
			Description: "Access to command line interface",
			Category:    "interface",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
		{
			ID:          "feat_api",
			ProductID:   product.ID,
			Name:        "API Access",
			Slug:        "api",
			Description: "Access to REST API",
			Category:    "interface",
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		},
	}

	for _, feature := range features {
		if err := storage.SaveFeature(ctx, feature); err != nil {
			log.Printf("↺ Feature %s already exists or error: %v", feature.Slug, err)
		} else {
			log.Printf("   ✓ Created feature: %s", feature.Name)
		}
	}

	// ==================== Create Feature Scopes ====================
	// GUI Scopes
	guiScopes := []*licensing.FeatureScope{
		{ID: "scope_gui_dashboard", FeatureID: "feat_gui", Name: "Dashboard", Slug: "dashboard", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_gui_settings", FeatureID: "feat_gui", Name: "Settings", Slug: "settings", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_gui_reports", FeatureID: "feat_gui", Name: "Reports", Slug: "reports", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_gui_admin", FeatureID: "feat_gui", Name: "Admin Panel", Slug: "admin", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	// CLI Scopes
	cliScopes := []*licensing.FeatureScope{
		{ID: "scope_cli_container", FeatureID: "feat_cli", Name: "Container Commands", Slug: "container", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_cli_sandbox", FeatureID: "feat_cli", Name: "Sandbox Commands", Slug: "sandbox", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_cli_server", FeatureID: "feat_cli", Name: "Server Commands", Slug: "server", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_cli_build", FeatureID: "feat_cli", Name: "Build Commands", Slug: "build", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_cli_deploy", FeatureID: "feat_cli", Name: "Deploy Commands", Slug: "deploy", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_cli_config", FeatureID: "feat_cli", Name: "Config Commands", Slug: "config", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	// API Scopes
	apiScopes := []*licensing.FeatureScope{
		{ID: "scope_api_read", FeatureID: "feat_api", Name: "Read Operations", Slug: "read", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_api_write", FeatureID: "feat_api", Name: "Write Operations", Slug: "write", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_api_delete", FeatureID: "feat_api", Name: "Delete Operations", Slug: "delete", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
		{ID: "scope_api_admin", FeatureID: "feat_api", Name: "Admin Operations", Slug: "admin", Permission: licensing.ScopePermissionAllow, CreatedAt: time.Now(), UpdatedAt: time.Now()},
	}

	allScopes := append(append(guiScopes, cliScopes...), apiScopes...)
	for _, scope := range allScopes {
		if err := storage.SaveFeatureScope(ctx, scope); err != nil {
			log.Printf("↺ Scope %s already exists or error: %v", scope.Slug, err)
		}
	}
	log.Printf("   ✓ Created %d feature scopes", len(allScopes))

	// ==================== Create Plans ====================
	type planConfig struct {
		plan          *licensing.Plan
		enabledFeats  []string
		scopeOverride map[string]map[string]licensing.ScopeOverride // featureID -> scopeID -> override
	}

	plans := []planConfig{
		// Plan A: Enterprise - Full Access (User A)
		{
			plan: &licensing.Plan{
				ID:           "plan_enterprise",
				ProductID:    product.ID,
				Name:         "Enterprise",
				Slug:         "enterprise",
				Description:  "Full access to all features and scopes",
				Price:        99900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 1,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_gui", "feat_cli", "feat_api"},
			// No scope overrides - all scopes allowed by default
		},
		// Plan B: CLI Only - Restrict GUI (User B)
		{
			plan: &licensing.Plan{
				ID:           "plan_cli_only",
				ProductID:    product.ID,
				Name:         "CLI Only",
				Slug:         "cli-only",
				Description:  "CLI and API access only, no GUI",
				Price:        49900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 2,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_cli", "feat_api"}, // GUI not included
		},
		// Plan C: GUI Only - Restrict CLI (User C)
		{
			plan: &licensing.Plan{
				ID:           "plan_gui_only",
				ProductID:    product.ID,
				Name:         "GUI Only",
				Slug:         "gui-only",
				Description:  "GUI and API access only, no CLI",
				Price:        49900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 3,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_gui", "feat_api"}, // CLI not included
		},
		// Plan D: CLI Limited - Restrict container, sandbox, server commands (User D)
		{
			plan: &licensing.Plan{
				ID:           "plan_cli_limited",
				ProductID:    product.ID,
				Name:         "CLI Limited",
				Slug:         "cli-limited",
				Description:  "CLI access with restricted commands (no container, sandbox, server)",
				Price:        29900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 4,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_gui", "feat_cli", "feat_api"},
			scopeOverride: map[string]map[string]licensing.ScopeOverride{
				"feat_cli": {
					"scope_cli_container": {Permission: licensing.ScopePermissionDeny},
					"scope_cli_sandbox":   {Permission: licensing.ScopePermissionDeny},
					"scope_cli_server":    {Permission: licensing.ScopePermissionDeny},
				},
			},
		},
		// Plan E: API Read Only (User E)
		{
			plan: &licensing.Plan{
				ID:           "plan_api_readonly",
				ProductID:    product.ID,
				Name:         "API Read Only",
				Slug:         "api-readonly",
				Description:  "API access with read-only permissions",
				Price:        19900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 5,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_api"},
			scopeOverride: map[string]map[string]licensing.ScopeOverride{
				"feat_api": {
					"scope_api_write":  {Permission: licensing.ScopePermissionDeny},
					"scope_api_delete": {Permission: licensing.ScopePermissionDeny},
					"scope_api_admin":  {Permission: licensing.ScopePermissionDeny},
				},
			},
		},
		// Plan F: Basic - Limited everything (User F)
		{
			plan: &licensing.Plan{
				ID:           "plan_basic",
				ProductID:    product.ID,
				Name:         "Basic",
				Slug:         "basic",
				Description:  "Basic access with limited features",
				Price:        9900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 6,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_gui"},
			scopeOverride: map[string]map[string]licensing.ScopeOverride{
				"feat_gui": {
					"scope_gui_admin":   {Permission: licensing.ScopePermissionDeny},
					"scope_gui_reports": {Permission: licensing.ScopePermissionDeny},
				},
			},
		},
		// Plan G: Developer - Full CLI, limited GUI (User G)
		{
			plan: &licensing.Plan{
				ID:           "plan_developer",
				ProductID:    product.ID,
				Name:         "Developer",
				Slug:         "developer",
				Description:  "Full CLI access, basic GUI, full API",
				Price:        39900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 7,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_gui", "feat_cli", "feat_api"},
			scopeOverride: map[string]map[string]licensing.ScopeOverride{
				"feat_gui": {
					"scope_gui_admin": {Permission: licensing.ScopePermissionDeny},
				},
			},
		},
		// Plan H: Viewer - Read-only everything (User H)
		{
			plan: &licensing.Plan{
				ID:           "plan_viewer",
				ProductID:    product.ID,
				Name:         "Viewer",
				Slug:         "viewer",
				Description:  "Read-only access across all interfaces",
				Price:        4900,
				Currency:     "USD",
				BillingCycle: "yearly",
				IsActive:     true,
				DisplayOrder: 8,
				CreatedAt:    time.Now(),
				UpdatedAt:    time.Now(),
			},
			enabledFeats: []string{"feat_gui", "feat_api"},
			scopeOverride: map[string]map[string]licensing.ScopeOverride{
				"feat_gui": {
					"scope_gui_settings": {Permission: licensing.ScopePermissionDeny},
					"scope_gui_admin":    {Permission: licensing.ScopePermissionDeny},
				},
				"feat_api": {
					"scope_api_write":  {Permission: licensing.ScopePermissionDeny},
					"scope_api_delete": {Permission: licensing.ScopePermissionDeny},
					"scope_api_admin":  {Permission: licensing.ScopePermissionDeny},
				},
			},
		},
	}

	// Save plans and their features, and build a map for entitlement computation
	planFeatureMap := make(map[string]planFeatureData)

	for _, pc := range plans {
		if err := storage.SavePlan(ctx, pc.plan); err != nil {
			log.Printf("↺ Plan %s already exists or error: %v", pc.plan.Slug, err)
		} else {
			log.Printf("   ✓ Created plan: %s", pc.plan.Name)
		}

		// Track plan features for entitlement computation
		planFeatureMap[pc.plan.ID] = planFeatureData{
			enabledFeatures: pc.enabledFeats,
			scopeOverrides:  pc.scopeOverride,
		}

		// Create plan features
		for _, featID := range pc.enabledFeats {
			pf := &licensing.PlanFeature{
				ID:        fmt.Sprintf("pf_%s_%s", pc.plan.ID, featID),
				PlanID:    pc.plan.ID,
				FeatureID: featID,
				Enabled:   true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}

			// Apply scope overrides if any
			if overrides, ok := pc.scopeOverride[featID]; ok {
				pf.ScopeOverrides = overrides
			}

			if err := storage.SavePlanFeature(ctx, pf); err != nil {
				log.Printf("↺ PlanFeature %s already exists or error: %v", pf.ID, err)
			}
		}
	}

	// Build feature and scope maps for entitlement computation
	featureMap := make(map[string]*licensing.Feature)
	for _, f := range features {
		featureMap[f.ID] = f
	}
	scopesByFeature := make(map[string][]*licensing.FeatureScope)
	for _, s := range allScopes {
		scopesByFeature[s.FeatureID] = append(scopesByFeature[s.FeatureID], s)
	}

	// ==================== Create Demo Users with Licenses ====================
	type userSeed struct {
		email    string
		planID   string
		planSlug string
		duration time.Duration
		max      int
	}

	users := []userSeed{
		{"user-a@example.com", "plan_enterprise", "enterprise", 365 * 24 * time.Hour, 10},    // Full access
		{"user-b@example.com", "plan_cli_only", "cli-only", 365 * 24 * time.Hour, 5},         // No GUI
		{"user-c@example.com", "plan_gui_only", "gui-only", 365 * 24 * time.Hour, 5},         // No CLI
		{"user-d@example.com", "plan_cli_limited", "cli-limited", 365 * 24 * time.Hour, 5},   // CLI without container/sandbox/server
		{"user-e@example.com", "plan_api_readonly", "api-readonly", 365 * 24 * time.Hour, 3}, // API read-only
		{"user-f@example.com", "plan_basic", "basic", 180 * 24 * time.Hour, 2},               // Basic GUI only
		{"user-g@example.com", "plan_developer", "developer", 365 * 24 * time.Hour, 5},       // Developer plan
		{"user-h@example.com", "plan_viewer", "viewer", 365 * 24 * time.Hour, 3},             // Viewer plan
	}

	type credentialInfo struct {
		clientID     string
		email        string
		licenseKey   string
		planSlug     string
		entitlements *licensing.LicenseEntitlements
	}
	var credentials []credentialInfo

	mode, interval := lm.DefaultCheckPolicy()
	for _, u := range users {
		client, err := lm.CreateClient(ctx, u.email)
		if err != nil {
			existing, lookupErr := lm.GetClientByEmail(ctx, u.email)
			if lookupErr != nil {
				log.Printf("⚠️ Skipping demo client %s: %v", u.email, err)
				continue
			}
			client = existing
			log.Printf("↺ Demo client already exists: %s (ID: %s)", client.Email, client.ID)
		}

		// Create license with basic plan slug
		license, err := lm.GenerateLicense(ctx, client.ID, u.duration, u.max, u.planSlug, mode, interval)
		if err != nil {
			log.Printf("⚠️ Failed to create demo license for %s: %v", client.Email, err)
			continue
		}

		// Compute entitlements manually from in-memory plan/feature data
		entitlements := computeDemoEntitlements(product.ID, product.Slug, u.planID, u.planSlug, planFeatureMap, featureMap, scopesByFeature)

		log.Printf("   ✓ Client: %s (ID: %s) | Plan: %s | License: %s", client.Email, client.ID, u.planSlug, license.LicenseKey)
		credentials = append(credentials, credentialInfo{
			clientID:     client.ID,
			email:        client.Email,
			licenseKey:   license.LicenseKey,
			planSlug:     u.planSlug,
			entitlements: entitlements,
		})
	}

	// ==================== Display Credentials and Permissions ====================
	if len(credentials) > 0 {
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")
		fmt.Println("📄 Demo License Credentials with Permissions/Scopes")
		fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")

		for i, cred := range credentials {
			userLetter := string(rune('A' + i))
			fmt.Println()
			fmt.Printf("👤 USER %s: %s\n", userLetter, cred.email)
			fmt.Printf("   Plan: %s\n", cred.planSlug)
			fmt.Printf("   Client ID: %s\n", cred.clientID)
			fmt.Printf("   License Key: %s\n", cred.licenseKey)
			fmt.Println("   ─────────────────────────────────────────────────────────────────────────────────────────────")

			if cred.entitlements != nil && len(cred.entitlements.Features) > 0 {
				fmt.Println("   📋 PERMISSIONS/SCOPES:")

				// Sort features for consistent output
				featSlugs := make([]string, 0, len(cred.entitlements.Features))
				for slug := range cred.entitlements.Features {
					featSlugs = append(featSlugs, slug)
				}
				sort.Strings(featSlugs)

				// Display features and their scopes
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

					if len(feat.Scopes) > 0 {
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
		fmt.Println("   User A (Enterprise)    → ✅ FULL ACCESS: GUI, CLI, API (all scopes)")
		fmt.Println("   User B (CLI Only)      → ❌ GUI restricted, ✅ CLI, ✅ API")
		fmt.Println("   User C (GUI Only)      → ✅ GUI, ❌ CLI restricted, ✅ API")
		fmt.Println("   User D (CLI Limited)   → ✅ GUI, ⚠️  CLI (no container/sandbox/server), ✅ API")
		fmt.Println("   User E (API Read Only) → ❌ GUI, ❌ CLI, ⚠️  API (read only)")
		fmt.Println("   User F (Basic)         → ⚠️  GUI (no admin/reports), ❌ CLI, ❌ API")
		fmt.Println("   User G (Developer)     → ⚠️  GUI (no admin), ✅ CLI, ✅ API")
		fmt.Println("   User H (Viewer)        → ⚠️  GUI (read only), ❌ CLI, ⚠️  API (read only)")
		fmt.Println("═══════════════════════════════════════════════════════════════════════════════════════════════════")
		fmt.Println()
	}

	return nil
}

// planFeatureData holds the feature configuration for a plan
type planFeatureData struct {
	enabledFeatures []string
	scopeOverrides  map[string]map[string]licensing.ScopeOverride
}

// computeDemoEntitlements builds entitlements from in-memory demo data
func computeDemoEntitlements(
	productID, productSlug, planID, planSlug string,
	planFeatureMap map[string]planFeatureData,
	featureMap map[string]*licensing.Feature,
	scopesByFeature map[string][]*licensing.FeatureScope,
) *licensing.LicenseEntitlements {
	pfData, ok := planFeatureMap[planID]
	if !ok {
		return nil
	}

	entitlements := &licensing.LicenseEntitlements{
		ProductID:   productID,
		ProductSlug: productSlug,
		PlanID:      planID,
		PlanSlug:    planSlug,
		Features:    make(map[string]licensing.FeatureGrant),
	}

	for _, featID := range pfData.enabledFeatures {
		feature, ok := featureMap[featID]
		if !ok {
			continue
		}

		featureGrant := licensing.FeatureGrant{
			FeatureID:   feature.ID,
			FeatureSlug: feature.Slug,
			Category:    feature.Category,
			Enabled:     true,
			Scopes:      make(map[string]licensing.ScopeGrant),
		}

		// Add scopes for this feature
		for _, scope := range scopesByFeature[featID] {
			scopeGrant := licensing.ScopeGrant{
				ScopeID:    scope.ID,
				ScopeSlug:  scope.Slug,
				Permission: scope.Permission,
				Limit:      scope.Limit,
				Metadata:   scope.Metadata,
			}

			// Apply override if exists
			if overrides, hasFeatureOverrides := pfData.scopeOverrides[featID]; hasFeatureOverrides {
				if override, hasScopeOverride := overrides[scope.ID]; hasScopeOverride {
					scopeGrant.Permission = override.Permission
					scopeGrant.Limit = override.Limit
					if override.Metadata != nil {
						scopeGrant.Metadata = override.Metadata
					}
				}
			}

			featureGrant.Scopes[scope.Slug] = scopeGrant
		}

		entitlements.Features[feature.Slug] = featureGrant
	}

	return entitlements
}
