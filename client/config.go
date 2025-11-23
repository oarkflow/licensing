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
	defaultActivationMode = "auto"
)

var (
	activationMode  = flag.String("activation-mode", defaultActivationMode, "Activation strategy: auto, env, prompt, verify")
	configDirFlag   = flag.String("config-dir", "", fmt.Sprintf("Directory for license data (default $HOME/%s or $%s)", client.DefaultConfigDir, EnvConfigDir))
	licenseFileFlag = flag.String("license-file", "", fmt.Sprintf("License file name (default %s or $%s)", client.DefaultLicenseFile, EnvLicenseFile))
	serverURLFlag   = flag.String("server-url", "", fmt.Sprintf("Licensing server URL (default $%s or %s)", client.EnvServerURL, client.DefaultServerURL))
	httpTimeoutFlag = flag.Duration("http-timeout", 0, fmt.Sprintf("HTTP timeout (e.g. 15s). Defaults to internal value or $%s", EnvHTTPTimeout))
)

func resolveClientConfig() client.Config {
	cfg := client.Config{
		AppName:    APP_NAME,
		AppVersion: APP_VERSION,
	}

	if value := strings.TrimSpace(*configDirFlag); value != "" {
		cfg.ConfigDir = value
	} else if env := envOrEmpty(EnvConfigDir); env != "" {
		cfg.ConfigDir = env
	}

	if value := strings.TrimSpace(*licenseFileFlag); value != "" {
		cfg.LicenseFile = value
	} else if env := envOrEmpty(EnvLicenseFile); env != "" {
		cfg.LicenseFile = env
	}

	if value := strings.TrimSpace(*serverURLFlag); value != "" {
		cfg.ServerURL = value
	} else if env := envOrEmpty(client.EnvServerURL); env != "" {
		cfg.ServerURL = env
	}

	if timeout := *httpTimeoutFlag; timeout > 0 {
		cfg.HTTPTimeout = timeout
	} else if envTimeout := durationFromEnv(EnvHTTPTimeout); envTimeout > 0 {
		cfg.HTTPTimeout = envTimeout
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
