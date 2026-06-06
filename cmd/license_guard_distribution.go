//go:build distribution

package main

import (
	"context"
	"log"

	licensing "github.com/oarkflow/licensing-go"
)

func runWithDistributionLicense(ctx context.Context, run func(context.Context)) {
	licenseData, err := licensing.EnsureActivated(licensing.Config{
		AppName:           "Licensing Server",
		AppVersion:        buildVersion,
		ProductID:         distributionProductID,
		DeviceKeyProvider: "auto",
	})
	if err != nil {
		log.Fatalf("Distribution license activation/verification failed: %v", err)
	}
	if licenseData == nil {
		log.Fatalf("Distribution license activation/verification failed: empty license data")
	}
	if err := validateDistributionLicense(licenseData.ProductID, licenseData.IsRevoked, licenseData.ExpiresAt, licenseData.HasFeature); err != nil {
		log.Fatalf("Distribution license rejected: %v", err)
	}
	log.Printf("✅ Distribution license verified: plan=%s client=%s", licenseData.PlanSlug, licenseData.ClientID)
	run(ctx)
}
