package licensing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"strings"
	"time"
)

const (
	appVaultFeatureEnv   = "LICENSE_SERVER_APPVAULT_FEATURE"
	appVaultKeySecretEnv = "LICENSE_SERVER_APPVAULT_KEY_SECRET"
)

type AppVaultBundleIdentity struct {
	AppID          string   `json:"app_id,omitempty"`
	BundleID       string   `json:"bundle_id,omitempty"`
	PublisherID    string   `json:"publisher_id,omitempty"`
	Version        string   `json:"version,omitempty"`
	Hash           string   `json:"hash,omitempty"`
	RuntimeTargets []string `json:"runtime_targets,omitempty"`
}

type AppVaultKeyReleaseRequest struct {
	LicenseID         string                 `json:"license_id,omitempty"`
	LicenseKey        string                 `json:"license_key"`
	ClientID          string                 `json:"client_id,omitempty"`
	Email             string                 `json:"email,omitempty"`
	ProductID         string                 `json:"product_id,omitempty"`
	DeviceFingerprint string                 `json:"device_fingerprint,omitempty"`
	Feature           string                 `json:"feature,omitempty"`
	Bundle            AppVaultBundleIdentity `json:"bundle"`
}

type AppVaultKeyReleaseResponse struct {
	BundleKeyBase64 string `json:"bundle_key_base64"`
}

func (lm *LicenseManager) ReleaseAppVaultBundleKey(ctx context.Context, req AppVaultKeyReleaseRequest) (*AppVaultKeyReleaseResponse, error) {
	secret := strings.TrimSpace(os.Getenv(appVaultKeySecretEnv))
	if secret == "" {
		return nil, fmt.Errorf("%s is required", appVaultKeySecretEnv)
	}
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	if req.LicenseKey == "" {
		return nil, fmt.Errorf("license_key is required")
	}
	featureSlug := strings.TrimSpace(req.Feature)
	if featureSlug == "" {
		featureSlug = strings.TrimSpace(os.Getenv(appVaultFeatureEnv))
	}
	if featureSlug == "" {
		return nil, fmt.Errorf("feature is required; set request feature or %s", appVaultFeatureEnv)
	}
	license, err := lm.storage.GetLicenseByKey(ctx, req.LicenseKey)
	if err != nil {
		return nil, fmt.Errorf("invalid license key")
	}
	if strings.TrimSpace(req.LicenseID) != "" && strings.TrimSpace(req.LicenseID) != license.ID {
		return nil, fmt.Errorf("license_id does not match license key")
	}
	if err := validateAppVaultLicenseForRelease(ctx, lm, license, req, featureSlug); err != nil {
		return nil, err
	}
	key := deriveAppVaultBundleKey([]byte(secret), license, req, featureSlug)
	return &AppVaultKeyReleaseResponse{BundleKeyBase64: base64.StdEncoding.EncodeToString(key)}, nil
}

func validateAppVaultLicenseForRelease(ctx context.Context, lm *LicenseManager, license *License, req AppVaultKeyReleaseRequest, featureSlug string) error {
	if license == nil {
		return fmt.Errorf("license is required")
	}
	if license.IsRevoked {
		return fmt.Errorf("license has been revoked")
	}
	if !license.ExpiresAt.IsZero() && time.Now().After(license.ExpiresAt) {
		return fmt.Errorf("license expired at %s", license.ExpiresAt.Format(time.RFC3339))
	}
	if err := validateAppVaultProduct(ctx, lm, license, req.ProductID); err != nil {
		return err
	}
	if err := validateAppVaultIdentity(ctx, license, req); err != nil {
		return err
	}
	if err := validateAppVaultDevice(license, req.DeviceFingerprint); err != nil {
		return err
	}
	if err := lm.ensureLicenseEntitlements(ctx, license); err != nil {
		return fmt.Errorf("compute entitlements: %w", err)
	}
	feature, ok := license.Entitlements.Features[featureSlug]
	if !ok || !feature.Enabled {
		return fmt.Errorf("license is missing enabled %q entitlement", featureSlug)
	}
	return nil
}

func validateAppVaultProduct(ctx context.Context, lm *LicenseManager, license *License, requestedProductID string) error {
	requestedProductID = strings.TrimSpace(requestedProductID)
	if requestedProductID == "" {
		return nil
	}
	licenseProductID := strings.TrimSpace(license.ProductID)
	if licenseProductID == "" {
		return fmt.Errorf("license is not associated with any product")
	}
	if licenseProductID == requestedProductID {
		return nil
	}
	product, err := lm.storage.GetProduct(ctx, licenseProductID)
	if err == nil && product != nil && strings.EqualFold(product.Slug, requestedProductID) {
		return nil
	}
	return fmt.Errorf("license is not valid for this product")
}

func validateAppVaultIdentity(_ context.Context, license *License, req AppVaultKeyReleaseRequest) error {
	clientID := strings.TrimSpace(req.ClientID)
	if clientID != "" && clientID != license.ClientID {
		return fmt.Errorf("client_id does not match license")
	}
	email := normalizeEmail(req.Email)
	if email != "" && email != normalizeEmail(license.Email) {
		identity := existingLicenseIdentity(license, email)
		if identity == nil {
			return fmt.Errorf("email does not match license")
		}
	}
	return nil
}

func validateAppVaultDevice(license *License, fingerprint string) error {
	fingerprint = strings.TrimSpace(fingerprint)
	if fingerprint == "" {
		return nil
	}
	device, ok := license.Devices[fingerprint]
	if !ok {
		return fmt.Errorf("device is not activated for this license")
	}
	if !deviceCanVerify(device) {
		return fmt.Errorf("device is %s", normalizeDeviceStatus(device.Status))
	}
	return nil
}

func deriveAppVaultBundleKey(secret []byte, license *License, req AppVaultKeyReleaseRequest, featureSlug string) []byte {
	productID := strings.TrimSpace(req.ProductID)
	if productID == "" {
		productID = strings.TrimSpace(license.ProductID)
	}
	bundleID := strings.TrimSpace(req.Bundle.BundleID)
	if bundleID == "" {
		bundleID = strings.TrimSpace(req.Bundle.AppID)
	}
	mac := hmac.New(sha256.New, secret)
	parts := []string{
		"appvault-bundle-key-v1",
		license.ID,
		normalizeLicenseKey(license.LicenseKey),
		productID,
		strings.TrimSpace(featureSlug),
		bundleID,
	}
	for _, part := range parts {
		mac.Write([]byte(part))
		mac.Write([]byte{0})
	}
	return mac.Sum(nil)
}
