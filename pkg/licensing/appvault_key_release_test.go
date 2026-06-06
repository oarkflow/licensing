package licensing

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestReleaseAppVaultBundleKeySuccessAndStability(t *testing.T) {
	t.Setenv(appVaultKeySecretEnv, "test-secret")
	lm, license := testAppVaultLicense(t, true)

	req := AppVaultKeyReleaseRequest{
		LicenseKey: license.LicenseKey,
		ClientID:   license.ClientID,
		Email:      license.Email,
		ProductID:  "appvault",
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
				ProductID:  "appvault",
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
		ProductID:  "appvault",
		Bundle:     AppVaultBundleIdentity{BundleID: "bundle-1"},
	})
	if err == nil {
		t.Fatal("expected missing feature to fail")
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
		ProductID:  "appvault",
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
	ctx := context.Background()
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatal(err)
	}
	product := &Product{ID: "prod-appvault", Name: "AppVault", Slug: "appvault", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := storage.SaveProduct(ctx, product); err != nil {
		t.Fatal(err)
	}
	plan := &Plan{ID: "plan-appvault", ProductID: product.ID, Name: "AppVault Plan", Slug: "appvault-plan", DurationDays: 365, IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := storage.SavePlan(ctx, plan); err != nil {
		t.Fatal(err)
	}
	if includeFeature {
		feature := &Feature{ID: "feature-appvault-runtime", ProductID: product.ID, Name: "AppVault Runtime", Slug: appVaultDefaultFeature, CreatedAt: time.Now(), UpdatedAt: time.Now()}
		if err := storage.SaveFeature(ctx, feature); err != nil {
			t.Fatal(err)
		}
		if err := storage.SavePlanFeature(ctx, &PlanFeature{ID: "pf-appvault-runtime", PlanID: plan.ID, FeatureID: feature.ID, Enabled: true, CreatedAt: time.Now(), UpdatedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	client, err := lm.CreateClient(ctx, "user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	license, err := lm.GenerateLicenseWithOptions(ctx, client.ID, 365*24*time.Hour, 2, plan.Slug, LicenseCheckModeYearly, 0, &GenerateLicenseOptions{ProductID: product.ID, PlanID: plan.ID})
	if err != nil {
		t.Fatal(err)
	}
	return lm, license
}
