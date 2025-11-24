package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/oarflow/licensing/pkg/client"
)

const (
	APP_NAME    = "MySecureApp"
	APP_VERSION = "1.0.0"

	EnvConfigDir          = "LICENSE_CLIENT_CONFIG_DIR"
	EnvLicenseFile        = "LICENSE_CLIENT_LICENSE_FILE"
	EnvHTTPTimeout        = "LICENSE_CLIENT_HTTP_TIMEOUT"
	EnvCACertPath         = "LICENSE_CLIENT_CA_CERT"
	EnvAllowInsecureHTTP  = "LICENSE_CLIENT_ALLOW_INSECURE_HTTP"
	defaultActivationMode = "auto"
)

var (
	activationMode      = flag.String("activation-mode", defaultActivationMode, "Activation strategy: auto, env, prompt, verify")
	configDirFlag       = flag.String("config-dir", "", fmt.Sprintf("Directory for license data (default $HOME/%s or $%s)", client.DefaultConfigDir, EnvConfigDir))
	licenseStoreFlag    = flag.String("license-store", "", fmt.Sprintf("License store file name (default %s or $%s)", client.DefaultLicenseFile, EnvLicenseFile))
	licenseInfoFileFlag = flag.String("license-file", "", "Path to JSON file with activation details (email, client ID, license key)")
	serverURLFlag       = flag.String("server-url", "", fmt.Sprintf("Licensing server URL (default $%s or %s; falls back to http://localhost:8801 when --allow-insecure-http is set)", client.EnvServerURL, client.DefaultServerURL))
	httpTimeoutFlag     = flag.Duration("http-timeout", 0, fmt.Sprintf("HTTP timeout (e.g. 15s). Defaults to internal value or $%s", EnvHTTPTimeout))
	caCertFlag          = flag.String("ca-cert", "", fmt.Sprintf("Path to PEM CA bundle for server validation (default $%s)", EnvCACertPath))
	allowInsecureFlag   = flag.Bool("allow-insecure-http", false, fmt.Sprintf("Allow HTTP URLs or skip TLS verification for development (default $%s)", EnvAllowInsecureHTTP))
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
		cfg.ServerURL = "http://localhost:8801"
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
