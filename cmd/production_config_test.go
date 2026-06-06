package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateProductionConfigRejectsUnsafeDefaults(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:       "sqlite",
		SQLitePath:        "licensing.db",
		TLSCert:           tempFile(t, "tls.crt"),
		TLSKey:            tempFile(t, "tls.key"),
		SigningProviderID: "file",
	})
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("expected relative sqlite path rejection, got %v", err)
	}
}

func TestValidateProductionConfigRejectsMissingTLS(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:       "sqlite",
		SQLitePath:        filepath.Join(t.TempDir(), "licensing.db"),
		SigningProviderID: "file",
	})
	if err == nil || !strings.Contains(err.Error(), "TLS") {
		t.Fatalf("expected TLS rejection, got %v", err)
	}
}

func TestValidateProductionConfigAllowsProxyTLSTermination(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:        "sqlite",
		SQLitePath:         filepath.Join(t.TempDir(), "licensing.db"),
		AllowInsecure:      true,
		ProxyTLSTerminated: true,
		AuditPath:          filepath.Join(t.TempDir(), "audit.db"),
		BackupMarkerPath:   filepath.Join(t.TempDir(), "latest.json"),
		SigningProviderID:  "file",
	})
	if err != nil {
		t.Fatalf("expected reverse proxy TLS termination config to pass, got %v", err)
	}
}

func TestValidateProductionConfigRejectsProxyTLSWithoutInternalHTTP(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:        "sqlite",
		SQLitePath:         filepath.Join(t.TempDir(), "licensing.db"),
		ProxyTLSTerminated: true,
		SigningProviderID:  "file",
	})
	if err == nil || !strings.Contains(err.Error(), "requires internal HTTP") {
		t.Fatalf("expected proxy TLS without internal HTTP rejection, got %v", err)
	}
}

func TestValidateProductionConfigRejectsLegacyEnvKeysByDefault(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:       "sqlite",
		SQLitePath:        filepath.Join(t.TempDir(), "licensing.db"),
		TLSCert:           tempFile(t, "tls.crt"),
		TLSKey:            tempFile(t, "tls.key"),
		SigningProviderID: "file",
		LegacyAPIKeys:     []string{"legacy"},
	})
	if err == nil || !strings.Contains(err.Error(), "legacy env API keys") {
		t.Fatalf("expected legacy key rejection, got %v", err)
	}
}

func TestValidateProductionConfigAllowsHardenedSQLite(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:       "sqlite",
		SQLitePath:        filepath.Join(t.TempDir(), "licensing.db"),
		TLSCert:           tempFile(t, "tls.crt"),
		TLSKey:            tempFile(t, "tls.key"),
		AuditPath:         filepath.Join(t.TempDir(), "audit.db"),
		BackupMarkerPath:  filepath.Join(t.TempDir(), "latest.json"),
		SigningProviderID: "file",
	})
	if err != nil {
		t.Fatalf("expected hardened sqlite config to pass, got %v", err)
	}
}

func TestValidateProductionConfigRejectsUnreadableTLSFiles(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:       "sqlite",
		SQLitePath:        filepath.Join(t.TempDir(), "licensing.db"),
		TLSCert:           filepath.Join(t.TempDir(), "missing.crt"),
		TLSKey:            tempFile(t, "tls.key"),
		SigningProviderID: "file",
	})
	if err == nil || !strings.Contains(err.Error(), "TLS certificate path is not readable") {
		t.Fatalf("expected unreadable TLS cert rejection, got %v", err)
	}
}

func TestValidateProductionConfigRejectsMissingFileSigningKey(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("LICENSE_SERVER_AUDIT_ENABLED", "true")

	err := validateProductionConfig(productionConfig{
		StorageMode:       "sqlite",
		SQLitePath:        filepath.Join(t.TempDir(), "licensing.db"),
		TLSCert:           tempFile(t, "tls.crt"),
		TLSKey:            tempFile(t, "tls.key"),
		SigningProviderID: "file",
		KeyProvider:       "file",
		KeyFile:           filepath.Join(t.TempDir(), "missing.pem"),
	})
	if err == nil || !strings.Contains(err.Error(), "signing key path is not readable") {
		t.Fatalf("expected missing signing key rejection, got %v", err)
	}
}

func tempFile(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatalf("write temp file failed: %v", err)
	}
	return path
}
