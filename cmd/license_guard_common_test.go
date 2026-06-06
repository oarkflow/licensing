package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidateDistributionLicense(t *testing.T) {
	t.Parallel()
	cfg := distributionLicenseConfig{ProductID: "product-runtime", FeatureSlug: "runtime.start"}

	tests := map[string]struct {
		productID  string
		revoked    bool
		expiresAt  time.Time
		hasFeature func(string) bool
		wantErr    string
	}{
		"valid": {
			productID: cfg.ProductID,
			hasFeature: func(slug string) bool {
				return slug == cfg.FeatureSlug
			},
		},
		"wrong product": {
			productID: "other-product",
			hasFeature: func(slug string) bool {
				return slug == cfg.FeatureSlug
			},
			wantErr: "product",
		},
		"revoked": {
			productID: cfg.ProductID,
			revoked:   true,
			hasFeature: func(slug string) bool {
				return slug == cfg.FeatureSlug
			},
			wantErr: "revoked",
		},
		"expired": {
			productID: cfg.ProductID,
			expiresAt: time.Now().Add(-time.Hour),
			hasFeature: func(slug string) bool {
				return slug == cfg.FeatureSlug
			},
			wantErr: "expired",
		},
		"missing feature": {
			productID: cfg.ProductID,
			hasFeature: func(string) bool {
				return false
			},
			wantErr: "feature",
		},
		"nil feature checker": {
			productID: cfg.ProductID,
			wantErr:   "feature",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := validateDistributionLicense(cfg, tt.productID, tt.revoked, tt.expiresAt, tt.hasFeature)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected valid license, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected error containing %q, got %v", tt.wantErr, err)
			}
		})
	}
}

func TestLoadDistributionLicenseConfigRequiresEnv(t *testing.T) {
	t.Setenv(distributionProductIDEnv, "")
	t.Setenv(distributionFeatureSlugEnv, "")
	if _, err := loadDistributionLicenseConfig(); err == nil {
		t.Fatal("expected missing env to fail")
	}

	t.Setenv(distributionProductIDEnv, "product-runtime")
	t.Setenv(distributionFeatureSlugEnv, "runtime.start")
	cfg, err := loadDistributionLicenseConfig()
	if err != nil {
		t.Fatalf("expected config to load: %v", err)
	}
	if cfg.ProductID != "product-runtime" || cfg.FeatureSlug != "runtime.start" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}
