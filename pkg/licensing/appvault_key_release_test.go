package licensing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testAppVaultFeature = "runtime.key-release"

func TestReleaseAppVaultBundleKeySuccessAndStability(t *testing.T) {
	t.Setenv(appVaultKeySecretEnv, "test-secret")
	lm, license := testAppVaultLicense(t, true)

	req := AppVaultKeyReleaseRequest{
		LicenseKey: license.LicenseKey,
		ClientID:   license.ClientID,
		Email:      license.Email,
		ProductID:  license.ProductID,
		Feature:    testAppVaultFeature,
		Bundle:     AppVaultBundleIdentity{AppID: "laravel-app", BundleID: "bundle-1"},
	}
	first, err := lm.ReleaseAppVaultBundleKey(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(first.BundleKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 byte key, got %d", len(decoded))
	}
	second, err := lm.ReleaseAppVaultBundleKey(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.BundleKeyBase64 != second.BundleKeyBase64 {
		t.Fatal("expected stable key for same bundle identity")
	}
	req.Bundle.BundleID = "bundle-2"
	third, err := lm.ReleaseAppVaultBundleKey(context.Background(), req)
	if err != nil {
		t.Fatal(err)
	}
	if first.BundleKeyBase64 == third.BundleKeyBase64 {
		t.Fatal("expected different key for different bundle identity")
	}
}

func TestReleaseAppVaultBundleKeyRejectsInvalidInputs(t *testing.T) {
	t.Setenv(appVaultKeySecretEnv, "test-secret")
	tests := map[string]func(*License, *AppVaultKeyReleaseRequest){
		"revoked": func(license *License, _ *AppVaultKeyReleaseRequest) {
			license.IsRevoked = true
		},
		"expired": func(license *License, _ *AppVaultKeyReleaseRequest) {
			license.ExpiresAt = time.Now().Add(-time.Hour)
		},
		"wrong product": func(_ *License, req *AppVaultKeyReleaseRequest) {
			req.ProductID = "other-product"
		},
		"wrong client": func(_ *License, req *AppVaultKeyReleaseRequest) {
			req.ClientID = "other-client"
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			lm, license := testAppVaultLicense(t, true)
			req := &AppVaultKeyReleaseRequest{
				LicenseKey: license.LicenseKey,
				ClientID:   license.ClientID,
				Email:      license.Email,
				ProductID:  license.ProductID,
				Feature:    testAppVaultFeature,
				Bundle:     AppVaultBundleIdentity{BundleID: "bundle-1"},
			}
			mutate(license, req)
			if err := lm.storage.UpdateLicense(context.Background(), license); err != nil {
				t.Fatal(err)
			}
			if _, err := lm.ReleaseAppVaultBundleKey(context.Background(), *req); err == nil {
				t.Fatal("expected key release to fail")
			}
		})
	}
}

func TestReleaseAppVaultBundleKeyRejectsMissingFeature(t *testing.T) {
	t.Setenv(appVaultKeySecretEnv, "test-secret")
	lm, license := testAppVaultLicense(t, false)
	_, err := lm.ReleaseAppVaultBundleKey(context.Background(), AppVaultKeyReleaseRequest{
		LicenseKey: license.LicenseKey,
		ClientID:   license.ClientID,
		Email:      license.Email,
		ProductID:  license.ProductID,
		Feature:    testAppVaultFeature,
		Bundle:     AppVaultBundleIdentity{BundleID: "bundle-1"},
	})
	if err == nil {
		t.Fatal("expected missing feature to fail")
	}
}

func TestReleaseAppVaultBundleKeyRejectsWrongProductLicense(t *testing.T) {
	t.Setenv(appVaultKeySecretEnv, "test-secret")
	ctx := context.Background()
	storage := newSQLiteStorageForTest(t)
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatal(err)
	}
	otherProduct, otherPlan := saveAppVaultTestCatalog(t, storage, "other", true)
	runtimeProduct, _ := saveAppVaultTestCatalog(t, storage, "runtime", true)
	client, err := lm.CreateClient(ctx, "other-user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	license, err := lm.GenerateLicenseWithOptions(ctx, client.ID, 365*24*time.Hour, 2, otherPlan.Slug, LicenseCheckModeYearly, 0, &GenerateLicenseOptions{
		ProductID: otherProduct.ID,
		PlanID:    otherPlan.ID,
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = lm.ReleaseAppVaultBundleKey(ctx, AppVaultKeyReleaseRequest{
		LicenseKey: license.LicenseKey,
		ClientID:   license.ClientID,
		Email:      license.Email,
		ProductID:  runtimeProduct.ID,
		Feature:    testAppVaultFeature,
		Bundle:     AppVaultBundleIdentity{BundleID: "bundle-1"},
	})
	if err == nil {
		t.Fatal("expected wrong product license to fail key release")
	}
}

func TestHandleAppVaultBundleKey(t *testing.T) {
	t.Setenv(appVaultKeySecretEnv, "test-secret")
	lm, license := testAppVaultLicense(t, true)
	server, err := NewServer(lm, ":0", nil, NewRateLimiter(100, time.Minute), "", "", "", true)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(AppVaultKeyReleaseRequest{
		LicenseKey: license.LicenseKey,
		ClientID:   license.ClientID,
		Email:      license.Email,
		ProductID:  license.ProductID,
		Feature:    testAppVaultFeature,
		Bundle:     AppVaultBundleIdentity{BundleID: "bundle-1"},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/appvault/bundle-key", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handleAppVaultBundleKey(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp AppVaultKeyReleaseResponse
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.StdEncoding.DecodeString(resp.BundleKeyBase64)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 32 {
		t.Fatalf("expected 32 byte key, got %d", len(decoded))
	}
}

func testAppVaultLicense(t *testing.T, includeFeature bool) (*LicenseManager, *License) {
	t.Helper()
	storage := newSQLiteStorageForTest(t)
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatal(err)
	}
	if includeFeature {
		product, plan := saveAppVaultTestCatalog(t, storage, "runtime", true)
		return generateAppVaultTestLicense(t, lm, product, plan)
	}
	product, plan := saveAppVaultTestCatalog(t, storage, "runtime-no-feature", false)
	return generateAppVaultTestLicense(t, lm, product, plan)
}

func generateAppVaultTestLicense(t *testing.T, lm *LicenseManager, product *Product, plan *Plan) (*LicenseManager, *License) {
	t.Helper()
	ctx := context.Background()
	client, err := lm.CreateClient(ctx, "user-"+testSlug(t)+("@example.com"))
	if err != nil {
		t.Fatal(err)
	}
	license, err := lm.GenerateLicenseWithOptions(ctx, client.ID, 365*24*time.Hour, 2, plan.Slug, LicenseCheckModeYearly, 0, &GenerateLicenseOptions{ProductID: product.ID, PlanID: plan.ID})
	if err != nil {
		t.Fatal(err)
	}
	return lm, license
}

func saveAppVaultTestCatalog(t *testing.T, storage Storage, suffix string, includeFeature bool) (*Product, *Plan) {
	t.Helper()
	now := time.Now()
	slug := testSlug(t) + "-" + suffix
	product := &Product{ID: "product-" + slug, Name: "Runtime Product", Slug: "product-" + slug, CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveProduct(context.Background(), product); err != nil {
		t.Fatal(err)
	}
	plan := &Plan{ID: "plan-" + slug, ProductID: product.ID, Name: "Runtime Plan", Slug: "plan-" + slug, DurationDays: 365, IsActive: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.SavePlan(context.Background(), plan); err != nil {
		t.Fatal(err)
	}
	if includeFeature {
		feature := &Feature{ID: "feature-" + slug, ProductID: product.ID, Name: "Runtime Feature", Slug: testAppVaultFeature, Type: FeatureTypeBoolean, CreatedAt: now, UpdatedAt: now}
		if err := storage.SaveFeature(context.Background(), feature); err != nil {
			t.Fatal(err)
		}
		if err := storage.SavePlanFeature(context.Background(), &PlanFeature{ID: "pf-" + slug, PlanID: plan.ID, FeatureID: feature.ID, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	return product, plan
}

func newSQLiteStorageForTest(t *testing.T) *SQLiteStorage {
	t.Helper()
	storage, err := NewSQLiteStorage(filepath.Join(t.TempDir(), "licensing.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	return storage
}

func testSlug(t *testing.T) string {
	t.Helper()
	slug := strings.ToLower(t.Name())
	replacer := strings.NewReplacer("/", "-", "_", "-", " ", "-", ".", "-")
	return replacer.Replace(slug)
}
