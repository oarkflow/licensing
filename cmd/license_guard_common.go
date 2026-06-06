package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	distributionProductIDEnv   = "LICENSE_SERVER_DISTRIBUTION_PRODUCT_ID"
	distributionFeatureSlugEnv = "LICENSE_SERVER_DISTRIBUTION_FEATURE"
)

type distributionLicenseConfig struct {
	ProductID   string
	FeatureSlug string
}

func loadDistributionLicenseConfig() (distributionLicenseConfig, error) {
	cfg := distributionLicenseConfig{
		ProductID:   strings.TrimSpace(os.Getenv(distributionProductIDEnv)),
		FeatureSlug: strings.TrimSpace(os.Getenv(distributionFeatureSlugEnv)),
	}
	if cfg.ProductID == "" {
		return cfg, fmt.Errorf("%s is required for distribution builds", distributionProductIDEnv)
	}
	if cfg.FeatureSlug == "" {
		return cfg, fmt.Errorf("%s is required for distribution builds", distributionFeatureSlugEnv)
	}
	return cfg, nil
}

func validateDistributionLicense(cfg distributionLicenseConfig, productID string, isRevoked bool, expiresAt time.Time, hasFeature func(string) bool) error {
	if strings.TrimSpace(cfg.ProductID) == "" {
		return fmt.Errorf("distribution product id is required")
	}
	if strings.TrimSpace(cfg.FeatureSlug) == "" {
		return fmt.Errorf("distribution feature slug is required")
	}
	if strings.TrimSpace(productID) != cfg.ProductID {
		return fmt.Errorf("distribution license must be for product %q", cfg.ProductID)
	}
	if isRevoked {
		return fmt.Errorf("distribution license is revoked")
	}
	if !expiresAt.IsZero() && time.Now().After(expiresAt) {
		return fmt.Errorf("distribution license expired at %s", expiresAt.Format(time.RFC3339))
	}
	if hasFeature == nil || !hasFeature(cfg.FeatureSlug) {
		return fmt.Errorf("distribution license missing required feature %q", cfg.FeatureSlug)
	}
	return nil
}

func distributionLicenseConfigDir() string {
	if dir := strings.TrimSpace(os.Getenv("LICENSE_SERVER_DISTRIBUTION_CONFIG_DIR")); dir != "" {
		return dir
	}
	for _, dir := range []string{
		"/data/.licensing",
		"/var/lib/licensing/.licensing",
		"/persistent/.licensing",
	} {
		if info, err := os.Stat(filepath.Dir(dir)); err == nil && info.IsDir() {
			return dir
		}
	}
	return ""
}

func distributionLicenseDeviceKeyFile() string {
	if path := strings.TrimSpace(os.Getenv("LICENSE_SERVER_DISTRIBUTION_DEVICE_KEY_FILE")); path != "" {
		return path
	}
	if dir := distributionLicenseConfigDir(); dir != "" {
		return filepath.Join(dir, "device_ed25519.pem")
	}
	return ""
}
