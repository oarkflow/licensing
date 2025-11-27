// Package licensing provides a Go SDK for the hardware-key licensing service.
//
// This package re-exports the core client functionality from the main licensing
// module, providing a clean API for Go applications to integrate license
// activation, verification, and management.
//
// # Quick Start
//
//	cfg := licensing.Config{
//	    ServerURL: "https://licensing.example.com",
//	}
//	client, err := licensing.NewClient(cfg)
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Activate a new device
//	err = client.Activate("user@example.com", "client-123", "ABCD-EFGH-...")
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	// Verify existing license
//	license, err := client.Verify()
//	if err != nil {
//	    log.Fatal(err)
//	}
//	fmt.Printf("Licensed plan: %s\n", license.PlanSlug)
package licensing

import (
	"github.com/oarkflow/licensing/pkg/client"
)

// Re-export core types from the internal client package.
type (
	// Config controls how the licensing client persists data and contacts the server.
	Config = client.Config

	// Client manages license activation and verification for Go applications.
	Client = client.Client

	// LicenseData is the decrypted license information consumed by applications.
	LicenseData = client.LicenseData

	// LicenseDevice represents device metadata tied to a license.
	LicenseDevice = client.LicenseDevice

	// StoredLicense is the encrypted payload persisted locally.
	StoredLicense = client.StoredLicense

	// ActivationRequest is sent to the licensing server.
	ActivationRequest = client.ActivationRequest

	// ActivationResponse is returned by the licensing server.
	ActivationResponse = client.ActivationResponse

	// LicenseEntitlements contains all features and scopes granted by a license.
	LicenseEntitlements = client.LicenseEntitlements

	// FeatureGrant represents a feature enabled for a license.
	FeatureGrant = client.FeatureGrant

	// ScopeGrant represents a scope permission granted for a feature.
	ScopeGrant = client.ScopeGrant

	// ScopePermission defines the permission level for a scope.
	ScopePermission = client.ScopePermission

	// CredentialsFile represents a JSON file containing license activation credentials.
	CredentialsFile = client.CredentialsFile
)

// Re-export constants.
const (
	// EnvServerURL is the environment variable for the licensing server URL.
	EnvServerURL = client.EnvServerURL

	// DefaultLicenseFile is the default license file name.
	DefaultLicenseFile = client.DefaultLicenseFile

	// DefaultConfigDir is the default configuration directory name.
	DefaultConfigDir = client.DefaultConfigDir

	// DefaultServerURL is the default licensing server URL.
	DefaultServerURL = client.DefaultServerURL

	// ScopePermissionAllow indicates the scope action is allowed.
	ScopePermissionAllow = client.ScopePermissionAllow

	// ScopePermissionDeny indicates the scope action is denied.
	ScopePermissionDeny = client.ScopePermissionDeny

	// ScopePermissionLimit indicates the scope action is allowed with limits.
	ScopePermissionLimit = client.ScopePermissionLimit
)

// Re-export errors.
var (
	// ErrServerUnavailable is returned when the licensing server cannot be reached.
	ErrServerUnavailable = client.ErrServerUnavailable
)

// NewClient creates a new licensing client with the given configuration.
func NewClient(cfg Config) (*Client, error) {
	return client.New(cfg)
}

// LoadCredentialsFile loads license activation credentials from a JSON file.
// The file should contain: {"email": "...", "client_id": "...", "license_key": "..."}
func LoadCredentialsFile(path string) (*CredentialsFile, error) {
	return client.LoadCredentialsFile(path)
}
