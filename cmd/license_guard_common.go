package main

import (
	"fmt"
	"strings"
	"time"
)

const (
	distributionProductID   = "licensing-server"
	distributionFeatureSlug = "distribution"
)

func validateDistributionLicense(productID string, isRevoked bool, expiresAt time.Time, hasFeature func(string) bool) error {
	if strings.TrimSpace(productID) != distributionProductID {
		return fmt.Errorf("distribution license must be for product %q", distributionProductID)
	}
	if isRevoked {
		return fmt.Errorf("distribution license is revoked")
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		return fmt.Errorf("distribution license expired at %s", expiresAt.Format(time.RFC3339))
	}
	if hasFeature == nil || !hasFeature(distributionFeatureSlug) {
		return fmt.Errorf("distribution license missing required feature %q", distributionFeatureSlug)
	}
	return nil
}
