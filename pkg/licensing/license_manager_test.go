package licensing

import (
	"context"
	"testing"
	"time"
)

func TestResolveLicenseIdentity(t *testing.T) {
	lm := &LicenseManager{}
	license := &License{
		ClientID: "client-owner",
		Email:    "owner@example.com",
	}

	t.Run("owner identity", func(t *testing.T) {
		req := &ActivationRequest{Email: "owner@example.com", ClientID: "client-owner"}
		identity, needsAttach, err := lm.resolveLicenseIdentity(license, req, true)
		if err != nil {
			t.Fatalf("expected owner to resolve, got error: %v", err)
		}
		if needsAttach {
			t.Fatalf("owner identity should already be attached")
		}
		if identity == nil || identity.Email != license.Email {
			t.Fatalf("unexpected identity returned: %+v", identity)
		}
	})

	t.Run("missing client id", func(t *testing.T) {
		req := &ActivationRequest{Email: "delegate@example.com"}
		if _, _, err := lm.resolveLicenseIdentity(license, req, true); err == nil {
			t.Fatalf("expected error when client_id missing")
		}
	})

	t.Run("delegated identity", func(t *testing.T) {
		req := &ActivationRequest{
			Email:    "delegate@example.com",
			ClientID: "client-owner",
		}
		identity, needsAttach, err := lm.resolveLicenseIdentity(license, req, true)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !needsAttach {
			t.Fatalf("expected delegated identity to require persistence")
		}
		if identity == nil || identity.Email != "delegate@example.com" {
			t.Fatalf("unexpected identity returned: %+v", identity)
		}
		if identity.ProviderClientID != "client-owner" {
			t.Fatalf("expected provider id to match owner, got %+v", identity)
		}
		attachAuthorizedIdentity(license, identity)
	})

	t.Run("reuse without source", func(t *testing.T) {
		req := &ActivationRequest{Email: "delegate@example.com", ClientID: "client-owner"}
		identity, needsAttach, err := lm.resolveLicenseIdentity(license, req, false)
		if err != nil {
			t.Fatalf("expected stored delegate to resolve, got error: %v", err)
		}
		if needsAttach {
			t.Fatalf("resolved delegate should not require persistence")
		}
		if identity == nil || identity.Email != "delegate@example.com" {
			t.Fatalf("unexpected identity: %+v", identity)
		}
		if identity.ClientID == "" {
			t.Fatalf("expected subject client id to persist, got %+v", identity)
		}
	})
}

func TestComputeNextCheck(t *testing.T) {
	base := time.Date(2025, time.November, 25, 10, 0, 0, 0, time.UTC)
	tests := []struct {
		name     string
		mode     LicenseCheckMode
		interval time.Duration
		want     time.Time
	}{
		{
			name: "each run",
			mode: LicenseCheckModeEachRun,
			want: base,
		},
		{
			name: "monthly",
			mode: LicenseCheckModeMonthly,
			want: time.Date(2025, time.December, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			name: "yearly",
			mode: LicenseCheckModeYearly,
			want: time.Date(2026, time.November, 25, 10, 0, 0, 0, time.UTC),
		},
		{
			name:     "custom interval",
			mode:     LicenseCheckModeCustom,
			interval: 2 * time.Hour,
			want:     base.Add(2 * time.Hour),
		},
	}
	for _, tt := range tests {
		tc := tt
		t.Run(tc.name, func(t *testing.T) {
			lic := &License{CheckMode: tc.mode, CheckIntervalSecs: int64(tc.interval.Seconds())}
			ensureLicenseCheckDefaults(lic)
			got := computeNextCheck(lic, base)
			if !got.Equal(tc.want) {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}
}

func TestMarkServerCheck(t *testing.T) {
	base := time.Unix(0, 0).Add(10 * time.Hour)
	lm := &LicenseManager{}
	lm.SetDefaultCheckPolicy(LicenseCheckModeCustom, 3*time.Hour)
	custom := &License{CheckMode: LicenseCheckModeCustom}
	lm.markServerCheck(custom, base)
	if custom.LastCheckAt != base {
		t.Fatalf("expected last check to equal %v, got %v", base, custom.LastCheckAt)
	}
	expectedNext := base.Add(3 * time.Hour)
	if !custom.NextCheckAt.Equal(expectedNext) {
		t.Fatalf("expected next check %v, got %v", expectedNext, custom.NextCheckAt)
	}
	none := &License{CheckMode: LicenseCheckModeNone}
	lm.markServerCheck(none, base)
	if !none.LastCheckAt.IsZero() || !none.NextCheckAt.IsZero() {
		t.Fatalf("none mode should clear scheduling timestamps")
	}
}

func TestGenerateLicenseRequiresPlan(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemoryStorage()
	lm := &LicenseManager{storage: storage}
	client := &Client{ID: "client-1", Email: "user@example.com", Status: ClientStatusActive}
	if err := storage.SaveClient(ctx, client); err != nil {
		t.Fatalf("failed to seed client: %v", err)
	}
	if _, err := lm.GenerateLicense(ctx, client.ID, time.Hour, 1, "", LicenseCheckModeEachRun, 0); err == nil {
		t.Fatal("expected error when plan slug missing")
	}
	license, err := lm.GenerateLicense(ctx, client.ID, time.Hour, 1, "pro", LicenseCheckModeEachRun, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if license.PlanSlug != "pro" {
		t.Fatalf("expected plan slug to persist, got %s", license.PlanSlug)
	}
}
