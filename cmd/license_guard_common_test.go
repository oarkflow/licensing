package main

import (
	"strings"
	"testing"
	"time"
)

func TestValidateDistributionLicense(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		productID  string
		revoked    bool
		expiresAt  time.Time
		hasFeature func(string) bool
		wantErr    string
	}{
		"valid": {
			productID: distributionProductID,
			hasFeature: func(slug string) bool {
				return slug == distributionFeatureSlug
			},
		},
		"wrong product": {
			productID: "secretr",
			hasFeature: func(slug string) bool {
				return slug == distributionFeatureSlug
			},
			wantErr: "product",
		},
		"revoked": {
			productID: distributionProductID,
			revoked:   true,
			hasFeature: func(slug string) bool {
				return slug == distributionFeatureSlug
			},
			wantErr: "revoked",
		},
		"expired": {
			productID: distributionProductID,
			expiresAt: time.Now().Add(-time.Hour),
			hasFeature: func(slug string) bool {
				return slug == distributionFeatureSlug
			},
			wantErr: "expired",
		},
		"missing feature": {
			productID: distributionProductID,
			hasFeature: func(string) bool {
				return false
			},
			wantErr: "feature",
		},
		"nil feature checker": {
			productID: distributionProductID,
			wantErr:   "feature",
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			err := validateDistributionLicense(tt.productID, tt.revoked, tt.expiresAt, tt.hasFeature)
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
