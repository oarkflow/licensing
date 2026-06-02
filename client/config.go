package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/oarkflow/licensing/pkg/client"
)

const (
	APP_NAME    = "MySecureApp"
	APP_VERSION = "1.0.0"

	defaultActivationMode = "auto"
)

var (
	activationMode      = flag.String("activation-mode", defaultActivationMode, "Activation strategy: auto, prompt, verify")
	configDirFlag       = flag.String("config-dir", "", fmt.Sprintf("Directory for license data (default $HOME/%s)", client.DefaultConfigDir))
	licenseStoreFlag    = flag.String("license-store", "", fmt.Sprintf("License store file name (default %s)", client.DefaultLicenseFile))
	licenseInfoFileFlag = flag.String("license-file", "", "Path to JSON file with activation details (email, client ID, license key)")
	serverURLFlag       = flag.String("server-url", "", fmt.Sprintf("Licensing server URL (default %s)", client.DefaultServerURL))
	httpTimeoutFlag     = flag.Duration("http-timeout", 0, "HTTP timeout (e.g. 15s)")
	caCertFlag          = flag.String("ca-cert", "", "Path to PEM CA bundle for server validation")
	allowInsecureFlag   = flag.Bool("allow-insecure-http", false, "Allow HTTP URLs or skip TLS verification for development")
	deviceKeyProvider   = flag.String("device-key-provider", "", "Device proof key provider: auto, tpm, os, software")
	deviceKeyFile       = flag.String("device-key-file", "", "Software device key file; use a persistent mounted path for containers")
	deviceKeyName       = flag.String("device-key-name", "", "OS keyring account/key label")
	tpmDevice           = flag.String("tpm-device", "", "TPM device path for device proof")
)

func resolveClientConfig() client.Config {
	cfg := client.Config{
		AppName:    APP_NAME,
		AppVersion: APP_VERSION,
	}

	if *allowInsecureFlag {
		cfg.AllowInsecureHTTP = true
	}

	if value := strings.TrimSpace(*configDirFlag); value != "" {
		cfg.ConfigDir = value
	}

	if value := strings.TrimSpace(*licenseStoreFlag); value != "" {
		cfg.LicenseFile = value
	}

	if value := strings.TrimSpace(*serverURLFlag); value != "" {
		cfg.ServerURL = value
	} else if cfg.AllowInsecureHTTP {
		cfg.ServerURL = "http://localhost:6601"
	} else {
		cfg.ServerURL = client.DefaultServerURL
	}

	if timeout := *httpTimeoutFlag; timeout > 0 {
		cfg.HTTPTimeout = timeout
	}

	if value := strings.TrimSpace(*caCertFlag); value != "" {
		cfg.CACertPath = value
	}
	if value := strings.TrimSpace(*deviceKeyProvider); value != "" {
		cfg.DeviceKeyProvider = value
	}
	if value := strings.TrimSpace(*deviceKeyFile); value != "" {
		cfg.DeviceKeyFile = value
	}
	if value := strings.TrimSpace(*deviceKeyName); value != "" {
		cfg.DeviceKeyName = value
	}
	if value := strings.TrimSpace(*tpmDevice); value != "" {
		cfg.TPMDevice = value
	}

	return cfg
}
