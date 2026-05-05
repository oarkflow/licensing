package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/client"
)

const (
	APP_NAME    = "MySecureApp"
	APP_VERSION = "1.0.0"

	EnvConfigDir          = "LICENSE_CLIENT_CONFIG_DIR"
	EnvLicenseFile        = "LICENSE_CLIENT_LICENSE_FILE"
	EnvHTTPTimeout        = "LICENSE_CLIENT_HTTP_TIMEOUT"
	EnvCACertPath         = "LICENSE_CLIENT_CA_CERT"
	EnvAllowInsecureHTTP  = "LICENSE_CLIENT_ALLOW_INSECURE_HTTP"
	EnvDeviceKeyProvider  = "LICENSE_CLIENT_DEVICE_KEY_PROVIDER"
	EnvDeviceKeyFile      = "LICENSE_CLIENT_DEVICE_KEY_FILE"
	EnvDeviceKeyName      = "LICENSE_CLIENT_DEVICE_KEY_NAME"
	EnvTPMDevice          = "LICENSE_CLIENT_TPM_DEVICE"
	defaultActivationMode = "auto"
)

var (
	activationMode      = flag.String("activation-mode", defaultActivationMode, "Activation strategy: auto, prompt, verify")
	configDirFlag       = flag.String("config-dir", "", fmt.Sprintf("Directory for license data (default $HOME/%s or $%s)", client.DefaultConfigDir, EnvConfigDir))
	licenseStoreFlag    = flag.String("license-store", "", fmt.Sprintf("License store file name (default %s or $%s)", client.DefaultLicenseFile, EnvLicenseFile))
	licenseInfoFileFlag = flag.String("license-file", "", "Path to JSON file with activation details (email, client ID, license key)")
	serverURLFlag       = flag.String("server-url", "http://localhost:6601", fmt.Sprintf("Licensing server URL (default $%s or %s; falls back to http://localhost:6601 when --allow-insecure-http is set)", client.EnvServerURL, client.DefaultServerURL))
	httpTimeoutFlag     = flag.Duration("http-timeout", 0, fmt.Sprintf("HTTP timeout (e.g. 15s). Defaults to internal value or $%s", EnvHTTPTimeout))
	caCertFlag          = flag.String("ca-cert", "", fmt.Sprintf("Path to PEM CA bundle for server validation (default $%s)", EnvCACertPath))
	allowInsecureFlag   = flag.Bool("allow-insecure-http", false, fmt.Sprintf("Allow HTTP URLs or skip TLS verification for development (default $%s)", EnvAllowInsecureHTTP))
	deviceKeyProvider   = flag.String("device-key-provider", "", fmt.Sprintf("Device proof key provider: auto, tpm, os, software (default $%s or auto)", EnvDeviceKeyProvider))
	deviceKeyFile       = flag.String("device-key-file", "", fmt.Sprintf("Software device key file (default $%s or client config dir)", EnvDeviceKeyFile))
	deviceKeyName       = flag.String("device-key-name", "", fmt.Sprintf("OS keyring account/key label (default $%s or app/product derived)", EnvDeviceKeyName))
	tpmDevice           = flag.String("tpm-device", "", fmt.Sprintf("TPM device path for device proof (default $%s or platform default)", EnvTPMDevice))
)

func resolveClientConfig() client.Config {
	cfg := client.Config{
		AppName:    APP_NAME,
		AppVersion: APP_VERSION,
	}

	if boolFromEnv(EnvAllowInsecureHTTP) || *allowInsecureFlag {
		cfg.AllowInsecureHTTP = true
	}

	if value := strings.TrimSpace(*configDirFlag); value != "" {
		cfg.ConfigDir = value
	} else if env := envOrEmpty(EnvConfigDir); env != "" {
		cfg.ConfigDir = env
	}

	if value := strings.TrimSpace(*licenseStoreFlag); value != "" {
		cfg.LicenseFile = value
	} else if env := envOrEmpty(EnvLicenseFile); env != "" {
		cfg.LicenseFile = env
	}

	if value := strings.TrimSpace(*serverURLFlag); value != "" {
		cfg.ServerURL = value
	} else if env := envOrEmpty(client.EnvServerURL); env != "" {
		cfg.ServerURL = env
	} else if cfg.AllowInsecureHTTP {
		cfg.ServerURL = "http://localhost:6601"
	} else {
		cfg.ServerURL = client.DefaultServerURL
	}

	if timeout := *httpTimeoutFlag; timeout > 0 {
		cfg.HTTPTimeout = timeout
	} else if envTimeout := durationFromEnv(EnvHTTPTimeout); envTimeout > 0 {
		cfg.HTTPTimeout = envTimeout
	}

	if value := strings.TrimSpace(*caCertFlag); value != "" {
		cfg.CACertPath = value
	} else if env := envOrEmpty(EnvCACertPath); env != "" {
		cfg.CACertPath = env
	}
	if value := strings.TrimSpace(*deviceKeyProvider); value != "" {
		cfg.DeviceKeyProvider = value
	} else if env := envOrEmpty(EnvDeviceKeyProvider); env != "" {
		cfg.DeviceKeyProvider = env
	}
	if value := strings.TrimSpace(*deviceKeyFile); value != "" {
		cfg.DeviceKeyFile = value
	} else if env := envOrEmpty(EnvDeviceKeyFile); env != "" {
		cfg.DeviceKeyFile = env
	}
	if value := strings.TrimSpace(*deviceKeyName); value != "" {
		cfg.DeviceKeyName = value
	} else if env := envOrEmpty(EnvDeviceKeyName); env != "" {
		cfg.DeviceKeyName = env
	}
	if value := strings.TrimSpace(*tpmDevice); value != "" {
		cfg.TPMDevice = value
	} else if env := envOrEmpty(EnvTPMDevice); env != "" {
		cfg.TPMDevice = env
	}

	return cfg
}

func envOrEmpty(key string) string {
	return strings.TrimSpace(os.Getenv(key))
}

func durationFromEnv(key string) time.Duration {
	raw := envOrEmpty(key)
	if raw == "" {
		return 0
	}
	dur, err := time.ParseDuration(raw)
	if err != nil {
		log.Printf("ignoring invalid duration for %s: %v", key, err)
		return 0
	}
	return dur
}

func boolFromEnv(key string) bool {
	val := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	switch val {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}
