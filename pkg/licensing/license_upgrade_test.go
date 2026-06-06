package licensing

import (
	"context"
	"strings"
	"testing"
	"time"
)

type upgradeFixture struct {
	ctx     context.Context
	storage *InMemoryStorage
	lm      *LicenseManager
	client  *Client
	product *Product
	basic   *Plan
	pro     *Plan
	other   *Product
}

func newUpgradeFixture(t *testing.T) upgradeFixture {
	t.Helper()
	ctx := context.Background()
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}

	now := time.Now().UTC()
	product := &Product{ID: "prod-upgrade", Name: "Upgrade Product", Slug: "upgrade-product", CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveProduct(ctx, product); err != nil {
		t.Fatalf("SaveProduct failed: %v", err)
	}
	basic := &Plan{ID: "plan-basic", ProductID: product.ID, Name: "Basic", Slug: "basic", BillingCycle: "monthly", DurationDays: 30, MaxDevices: 2, IsActive: true, CreatedAt: now, UpdatedAt: now}
	pro := &Plan{ID: "plan-pro", ProductID: product.ID, Name: "Pro", Slug: "pro", BillingCycle: "yearly", DurationDays: 365, TrialDays: 14, MaxDevices: 10, IsActive: true, CreatedAt: now, UpdatedAt: now}
	if err := storage.SavePlan(ctx, basic); err != nil {
		t.Fatalf("SavePlan basic failed: %v", err)
	}
	if err := storage.SavePlan(ctx, pro); err != nil {
		t.Fatalf("SavePlan pro failed: %v", err)
	}
	basicFeature := &Feature{ID: "feature-basic", ProductID: product.ID, Name: "Basic Feature", Slug: "basic-feature", Type: FeatureTypeBoolean, CreatedAt: now, UpdatedAt: now}
	proFeature := &Feature{ID: "feature-pro", ProductID: product.ID, Name: "Pro Feature", Slug: "pro-feature", Type: FeatureTypeBoolean, CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveFeature(ctx, basicFeature); err != nil {
		t.Fatalf("SaveFeature basic failed: %v", err)
	}
	if err := storage.SaveFeature(ctx, proFeature); err != nil {
		t.Fatalf("SaveFeature pro failed: %v", err)
	}
	if err := storage.SavePlanFeature(ctx, &PlanFeature{PlanID: basic.ID, FeatureID: basicFeature.ID, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("SavePlanFeature basic failed: %v", err)
	}
	if err := storage.SavePlanFeature(ctx, &PlanFeature{PlanID: pro.ID, FeatureID: basicFeature.ID, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("SavePlanFeature pro/basic failed: %v", err)
	}
	if err := storage.SavePlanFeature(ctx, &PlanFeature{PlanID: pro.ID, FeatureID: proFeature.ID, Enabled: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("SavePlanFeature pro failed: %v", err)
	}

	other := &Product{ID: "prod-other", Name: "Other", Slug: "other", CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveProduct(ctx, other); err != nil {
		t.Fatalf("SaveProduct other failed: %v", err)
	}
	if err := storage.SavePlan(ctx, &Plan{ID: "plan-other", ProductID: other.ID, Name: "Other", Slug: "other", BillingCycle: "monthly", DurationDays: 30, MaxDevices: 1, IsActive: true, CreatedAt: now, UpdatedAt: now}); err != nil {
		t.Fatalf("SavePlan other failed: %v", err)
	}

	client, err := lm.CreateClientWithProfile(ctx, "upgrade@example.com", "", "Upgrade User", "Acme")
	if err != nil {
		t.Fatalf("CreateClientWithProfile failed: %v", err)
	}
	return upgradeFixture{ctx: ctx, storage: storage, lm: lm, client: client, product: product, basic: basic, pro: pro, other: other}
}

func (f upgradeFixture) issueBasicLicense(t *testing.T, isTrial bool) *License {
	t.Helper()
	license, err := f.lm.GenerateLicenseWithOptions(f.ctx, f.client.ID, 30*24*time.Hour, 2, f.basic.Slug, LicenseCheckModeMonthly, 0, &GenerateLicenseOptions{
		ProductID: f.product.ID,
		PlanID:    f.basic.ID,
		IsTrial:   isTrial,
	})
	if err != nil {
		t.Fatalf("GenerateLicenseWithOptions failed: %v", err)
	}
	return license
}

func TestUpgradeLicenseCreatesNewLicenseRevokesOldCopiesDevicesAndEntitlements(t *testing.T) {
	f := newUpgradeFixture(t)
	oldLicense := f.issueBasicLicense(t, false)
	now := time.Now().UTC()
	oldLicense.Devices = map[string]*LicenseDevice{
		"device-1": {
			Fingerprint:  "device-1",
			Status:       DeviceStatusTrusted,
			ActivatedAt:  now.Add(-24 * time.Hour),
			LastSeenAt:   now,
			TransportKey: []byte("transport"),
		},
	}
	refreshLicenseDeviceStats(oldLicense)
	if err := f.storage.UpdateLicense(f.ctx, oldLicense); err != nil {
		t.Fatalf("UpdateLicense failed: %v", err)
	}
	sub := &Subscription{
		ID:           "sub-upgrade",
		ClientID:     f.client.ID,
		ProductID:    f.product.ID,
		PlanID:       f.basic.ID,
		LicenseID:    oldLicense.ID,
		Status:       SubscriptionStatusActive,
		StartDate:    oldLicense.IssuedAt,
		EndDate:      oldLicense.ExpiresAt,
		BillingCycle: f.basic.BillingCycle,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	if err := f.storage.SaveSubscription(f.ctx, sub); err != nil {
		t.Fatalf("SaveSubscription failed: %v", err)
	}

	result, err := f.lm.UpgradeLicense(f.ctx, oldLicense.ID, UpgradeLicenseOptions{ProductID: f.product.ID, PlanID: f.pro.ID})
	if err != nil {
		t.Fatalf("UpgradeLicense failed: %v", err)
	}
	if result.License.ID == oldLicense.ID || result.License.LicenseKey == oldLicense.LicenseKey {
		t.Fatalf("expected a new license/key, got old id/key")
	}
	if !result.OldLicense.IsRevoked || !strings.Contains(result.OldLicense.RevokeReason, result.License.ID) {
		t.Fatalf("old license was not revoked with upgrade reason: %+v", result.OldLicense)
	}
	if result.License.PlanID != f.pro.ID || result.License.ProductID != f.product.ID {
		t.Fatalf("new license has wrong product/plan: %+v", result.License)
	}
	if result.License.CurrentActivations != 1 || result.License.Devices["device-1"] == nil {
		t.Fatalf("expected carried device, got %+v", result.License.Devices)
	}
	if result.License.Devices["device-1"].TransportKey == nil {
		t.Fatalf("expected transport key to be carried")
	}
	if result.License.Entitlements == nil || !result.License.Entitlements.Features["pro-feature"].Enabled {
		t.Fatalf("expected pro entitlements, got %+v", result.License.Entitlements)
	}
	if result.Subscription == nil || result.Subscription.LicenseID != result.License.ID || result.Subscription.PlanID != f.pro.ID {
		t.Fatalf("subscription was not updated: %+v", result.Subscription)
	}
}

func TestUpgradeLicenseTrialBehavior(t *testing.T) {
	f := newUpgradeFixture(t)
	oldTrial := f.issueBasicLicense(t, true)

	paidResult, err := f.lm.UpgradeLicense(f.ctx, oldTrial.ID, UpgradeLicenseOptions{ProductID: f.product.ID, PlanID: f.pro.ID})
	if err != nil {
		t.Fatalf("paid UpgradeLicense failed: %v", err)
	}
	if paidResult.License.IsTrial {
		t.Fatalf("expected paid upgrade to create a non-trial license")
	}

	second := f.issueBasicLicense(t, false)
	trialResult, err := f.lm.UpgradeLicense(f.ctx, second.ID, UpgradeLicenseOptions{ProductID: f.product.ID, PlanID: f.pro.ID, Trial: true})
	if err != nil {
		t.Fatalf("trial UpgradeLicense failed: %v", err)
	}
	if !trialResult.License.IsTrial {
		t.Fatalf("expected trial upgrade to create trial license")
	}
	duration := trialResult.License.ExpiresAt.Sub(trialResult.License.IssuedAt)
	if duration < 13*24*time.Hour || duration > 15*24*time.Hour {
		t.Fatalf("expected trial duration around 14 days, got %v", duration)
	}
	if trialResult.License.Entitlements == nil || !trialResult.License.Entitlements.Features["pro-feature"].Enabled {
		t.Fatalf("expected target plan entitlements on trial upgrade")
	}
}

func TestUpgradeLicenseRejectsInvalidTargets(t *testing.T) {
	tests := []struct {
		name string
		opts func(upgradeFixture) UpgradeLicenseOptions
		want string
	}{
		{
			name: "wrong product",
			opts: func(f upgradeFixture) UpgradeLicenseOptions {
				return UpgradeLicenseOptions{ProductID: f.other.ID, PlanID: "plan-other"}
			},
			want: "target product",
		},
		{
			name: "inactive plan",
			opts: func(f upgradeFixture) UpgradeLicenseOptions {
				inactive := *f.pro
				inactive.ID = "plan-inactive"
				inactive.Slug = "inactive"
				inactive.IsActive = false
				if err := f.storage.SavePlan(f.ctx, &inactive); err != nil {
					t.Fatalf("SavePlan inactive failed: %v", err)
				}
				return UpgradeLicenseOptions{ProductID: f.product.ID, PlanID: inactive.ID}
			},
			want: "not active",
		},
		{
			name: "missing plan",
			opts: func(f upgradeFixture) UpgradeLicenseOptions {
				return UpgradeLicenseOptions{ProductID: f.product.ID, PlanID: "missing"}
			},
			want: "plan not found",
		},
		{
			name: "max below carried devices",
			opts: func(f upgradeFixture) UpgradeLicenseOptions {
				return UpgradeLicenseOptions{ProductID: f.product.ID, PlanID: f.pro.ID, MaxDevices: 1}
			},
			want: "below carried device count",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newUpgradeFixture(t)
			oldLicense := f.issueBasicLicense(t, false)
			oldLicense.Devices = map[string]*LicenseDevice{
				"device-1": {Fingerprint: "device-1", Status: DeviceStatusTrusted},
				"device-2": {Fingerprint: "device-2", Status: DeviceStatusTrusted},
			}
			refreshLicenseDeviceStats(oldLicense)
			if err := f.storage.UpdateLicense(f.ctx, oldLicense); err != nil {
				t.Fatalf("UpdateLicense failed: %v", err)
			}
			if _, err := f.lm.UpgradeLicense(f.ctx, oldLicense.ID, tt.opts(f)); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
			reloaded, err := f.storage.GetLicense(f.ctx, oldLicense.ID)
			if err != nil {
				t.Fatalf("GetLicense failed: %v", err)
			}
			if reloaded.IsRevoked {
				t.Fatalf("old license should remain untouched before new license creation")
			}
		})
	}
}
