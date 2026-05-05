package licensing

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestComputeLicenseEntitlementsIncludesDecorationsAndSlugOverrides(t *testing.T) {
	storage := NewInMemoryStorage()
	ctx := context.Background()

	product := &Product{ID: "prod-1", Name: "Product", Slug: "product", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	plan := &Plan{ID: "plan-1", ProductID: product.ID, Name: "Pro", Slug: "pro", IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	feature := &Feature{
		ID:        "feature-1",
		ProductID: product.ID,
		Name:      "Analytics",
		Slug:      "analytics",
		Type:      FeatureTypeMetered,
		Category:  "reports",
		Metadata: map[string]string{
			"flag:beta":                   "true",
			"setting:theme":               "pro",
			"limit:projects":              "10",
			"usage:events:limit":          "500",
			"usage:events:window_seconds": "3600",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	scope := &FeatureScope{
		ID:         "scope-1",
		FeatureID:  feature.ID,
		Name:       "Export",
		Slug:       "export",
		Permission: ScopePermissionLimit,
		Limit:      25,
		Metadata: map[string]string{
			"flag:enabled":               "true",
			"setting:format":             "json",
			"limit:rows":                 "100",
			"usage:exports:limit":        "12",
			"restriction_type":           "device",
			"restriction_limit":          "2",
			"restriction_window_seconds": "60",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	planFeature := &PlanFeature{
		ID:        "pf-1",
		PlanID:    plan.ID,
		FeatureID: feature.ID,
		Enabled:   true,
		ScopeOverrides: map[string]ScopeOverride{
			scope.Slug: {
				Permission: ScopePermissionLimit,
				Limit:      9,
				Metadata: map[string]string{
					"setting:format":      "csv",
					"usage:exports:limit": "6",
				},
			},
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	for _, save := range []func() error{
		func() error { return storage.SaveProduct(ctx, product) },
		func() error { return storage.SavePlan(ctx, plan) },
		func() error { return storage.SaveFeature(ctx, feature) },
		func() error { return storage.SaveFeatureScope(ctx, scope) },
		func() error { return storage.SavePlanFeature(ctx, planFeature) },
	} {
		if err := save(); err != nil {
			t.Fatalf("setup failed: %v", err)
		}
	}

	entitlements, err := storage.ComputeLicenseEntitlements(ctx, product.ID, plan.ID)
	if err != nil {
		t.Fatalf("ComputeLicenseEntitlements failed: %v", err)
	}

	grant := entitlements.Features["analytics"]
	if grant.Type != FeatureTypeMetered {
		t.Fatalf("expected feature type %q, got %q", FeatureTypeMetered, grant.Type)
	}
	if !grant.Flags["beta"] {
		t.Fatalf("expected feature flag beta=true")
	}
	if grant.Settings["theme"] != "pro" {
		t.Fatalf("expected feature setting theme=pro, got %q", grant.Settings["theme"])
	}
	if grant.Limits["projects"] != 10 {
		t.Fatalf("expected feature limit projects=10, got %d", grant.Limits["projects"])
	}
	if grant.Usage["events"].Limit != 500 || grant.Usage["events"].WindowSeconds != 3600 {
		t.Fatalf("unexpected feature usage grant: %+v", grant.Usage["events"])
	}

	scopeGrant := grant.Scopes["export"]
	if scopeGrant.Limit != 9 {
		t.Fatalf("expected override limit 9, got %d", scopeGrant.Limit)
	}
	if scopeGrant.Settings["format"] != "csv" {
		t.Fatalf("expected override setting format=csv, got %q", scopeGrant.Settings["format"])
	}
	if scopeGrant.Usage["exports"].Limit != 6 {
		t.Fatalf("expected override usage limit 6, got %+v", scopeGrant.Usage["exports"])
	}
	if len(scopeGrant.Restrictions) != 1 || scopeGrant.Restrictions[0].Type != UsageRestrictionDevice {
		t.Fatalf("expected device restriction, got %+v", scopeGrant.Restrictions)
	}
}

func TestApplyFeatureScopeSelectionsSupportsIDsAndMetadata(t *testing.T) {
	entitlements := &LicenseEntitlements{
		Features: map[string]FeatureGrant{
			"analytics": {
				FeatureID:   "feature-1",
				FeatureSlug: "analytics",
				Enabled:     true,
				Scopes: map[string]ScopeGrant{
					"export": {
						ScopeID:    "scope-1",
						ScopeSlug:  "export",
						Permission: ScopePermissionAllow,
					},
				},
			},
		},
	}

	applyFeatureScopeSelections(entitlements, []FeatureScopeSelection{
		{
			FeatureID: "feature-1",
			Enabled:   true,
			Scopes: []ScopeSelection{
				{
					ScopeID:    "scope-1",
					Permission: ScopePermissionLimit,
					Limit:      7,
					Metadata: map[string]string{
						"setting:region": "eu",
						"flag:beta":      "false",
					},
				},
			},
		},
	})

	scopeGrant := entitlements.Features["analytics"].Scopes["export"]
	if scopeGrant.Permission != ScopePermissionLimit || scopeGrant.Limit != 7 {
		t.Fatalf("expected scope limit override, got %+v", scopeGrant)
	}
	if scopeGrant.Settings["region"] != "eu" {
		t.Fatalf("expected region setting to be applied, got %+v", scopeGrant.Settings)
	}
	if scopeGrant.Flags["beta"] {
		t.Fatalf("expected beta flag to be false, got %+v", scopeGrant.Flags)
	}

	applyFeatureScopeSelections(entitlements, []FeatureScopeSelection{{FeatureID: "feature-1", Enabled: false}})
	if entitlements.Features["analytics"].Enabled {
		t.Fatalf("expected feature to be disabled")
	}
	if entitlements.Features["analytics"].Scopes["export"].Permission != ScopePermissionDeny {
		t.Fatalf("expected disabling feature to deny scopes")
	}
}

func TestSQLiteAndServerFeatureEnhancements(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "licensing.db")
	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}

	ctx := context.Background()
	product := &Product{ID: "prod-1", Name: "Product", Slug: "product", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	plan := &Plan{ID: "plan-1", ProductID: product.ID, Name: "Pro", Slug: "pro", IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	feature := &Feature{ID: "feature-1", ProductID: product.ID, Name: "CLI", Slug: "cli", Type: FeatureTypeScoped, Metadata: map[string]string{"flag:core": "true"}, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	scope := &FeatureScope{
		ID:         "scope-1",
		FeatureID:  feature.ID,
		Name:       "Run",
		Slug:       "run",
		Permission: ScopePermissionAllow,
		Metadata: map[string]string{
			"restriction_type":  "device",
			"restriction_limit": "1",
		},
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}
	planFeature := &PlanFeature{ID: "pf-1", PlanID: plan.ID, FeatureID: feature.ID, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}

	for _, save := range []func() error{
		func() error { return storage.SaveProduct(ctx, product) },
		func() error { return storage.SavePlan(ctx, plan) },
		func() error { return storage.SaveFeature(ctx, feature) },
		func() error { return storage.SaveFeatureScope(ctx, scope) },
		func() error { return storage.SavePlanFeature(ctx, planFeature) },
	} {
		if err := save(); err != nil {
			t.Fatalf("sqlite setup failed: %v", err)
		}
	}

	gotFeature, err := storage.GetFeature(ctx, feature.ID)
	if err != nil {
		t.Fatalf("GetFeature failed: %v", err)
	}
	if gotFeature.Type != FeatureTypeScoped || gotFeature.Metadata["flag:core"] != "true" {
		t.Fatalf("unexpected feature round-trip: %+v", gotFeature)
	}

	entitlements, err := storage.ComputeLicenseEntitlements(ctx, product.ID, plan.ID)
	if err != nil {
		t.Fatalf("ComputeLicenseEntitlements failed: %v", err)
	}
	scopeGrant := entitlements.Features["cli"].Scopes["run"]
	if len(scopeGrant.Restrictions) != 1 || scopeGrant.Restrictions[0].Limit != 1 {
		t.Fatalf("expected sqlite restrictions to match in-memory behavior, got %+v", scopeGrant.Restrictions)
	}

	t.Setenv("HOME", t.TempDir())
	lm, err := NewLicenseManager(NewInMemoryStorage())
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	server, err := NewServer(lm, ":0", nil, NewRateLimiter(100, time.Minute), "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if err := lm.Storage().SaveProduct(ctx, product); err != nil {
		t.Fatalf("save product for server failed: %v", err)
	}
	admin, err := lm.CreateAdminUser(ctx, "admin", "password123")
	if err != nil {
		t.Fatalf("CreateAdminUser failed: %v", err)
	}
	token, _, err := lm.GenerateAPIKey(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}

	body, _ := json.Marshal(map[string]any{
		"name":        "API",
		"slug":        "api",
		"type":        "metered",
		"category":    "integration",
		"metadata":    map[string]string{"setting:burst": "high"},
		"description": "API access",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/products/prod-1/features", bytes.NewReader(body))
	req.Header.Set("X-API-Key", token)
	w := httptest.NewRecorder()
	server.handleProductActions(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 creating feature, got %d: %s", w.Code, w.Body.String())
	}
	var created Feature
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatalf("failed to decode feature response: %v", err)
	}
	if created.Type != FeatureTypeMetered || created.Metadata["setting:burst"] != "high" {
		t.Fatalf("expected feature type+metadata in API response, got %+v", created)
	}
}

func TestSQLiteProductSchemaAddsFeatureMetadataToExistingTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "licensing.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite fixture failed: %v", err)
	}
	for _, stmt := range []string{
		`CREATE TABLE plans (
			id TEXT PRIMARY KEY,
			product_id TEXT NOT NULL,
			name TEXT NOT NULL,
			slug TEXT NOT NULL,
			slug_key TEXT NOT NULL UNIQUE,
			description TEXT,
			price INTEGER NOT NULL DEFAULT 0,
			min_devices INTEGER NOT NULL DEFAULT 1,
			price_per_device INTEGER NOT NULL DEFAULT 0,
			currency TEXT NOT NULL DEFAULT 'USD',
			billing_cycle TEXT NOT NULL DEFAULT 'monthly',
			trial_days INTEGER NOT NULL DEFAULT 0,
			is_trial INTEGER NOT NULL DEFAULT 0,
			is_active INTEGER NOT NULL DEFAULT 1,
			display_order INTEGER NOT NULL DEFAULT 0,
			metadata TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);`,
		`CREATE TABLE features (
			id TEXT PRIMARY KEY,
			product_id TEXT NOT NULL,
			name TEXT NOT NULL,
			slug TEXT NOT NULL,
			slug_key TEXT NOT NULL UNIQUE,
			description TEXT,
			type TEXT NOT NULL DEFAULT 'boolean',
			category TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create legacy schema failed: %v", err)
		}
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite fixture failed: %v", err)
	}

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	defer storage.db.Close()

	exists, err := sqliteColumnExists(storage.db, "features", "metadata")
	if err != nil {
		t.Fatalf("sqliteColumnExists failed: %v", err)
	}
	if !exists {
		t.Fatalf("expected features.metadata to be added to existing features table")
	}

	ctx := context.Background()
	if err := storage.SaveProduct(ctx, &Product{ID: "prod-1", Name: "Product", Slug: "product"}); err != nil {
		t.Fatalf("SaveProduct failed: %v", err)
	}
	if err := storage.SaveFeature(ctx, &Feature{
		ID:        "feature-1",
		ProductID: "prod-1",
		Name:      "CLI",
		Slug:      "cli",
		Metadata:  map[string]string{"flag:core": "true"},
	}); err != nil {
		t.Fatalf("SaveFeature failed after schema migration: %v", err)
	}
}
