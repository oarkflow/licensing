package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/oarflow/licensing/pkg/activation"
	"github.com/oarflow/licensing/pkg/client"
	"github.com/oarflow/licensing/pkg/runner"
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

func main() {
	flag.Parse()
	showBanner()

	mode := strings.ToLower(strings.TrimSpace(*activationMode))
	clientCfg := resolveClientConfig()
	factory := func() (runner.Client[*client.LicenseData], error) {
		return client.NewClient(clientCfg)
	}

	activationStrategy := activation.Strategy(mode, activation.PromptIO{In: os.Stdin, Out: os.Stdout})

	appRunner, err := runner.NewRunner(runner.Config[*client.LicenseData]{
		ClientFactory: factory,
		Activation:    activationStrategy,
		Logger:        log.Default(),
	})
	if err != nil {
		log.Fatalf("Failed to configure licensing runner: %v", err)
	}

	appFn := runApplication
	if mode == "verify" {
		appFn = func(ctx context.Context, license *client.LicenseData) error {
			fmt.Println("\nVerification complete. No application code executed.")
			return nil
		}
	}

	if err := appRunner.Run(context.Background(), appFn); err != nil {
		log.Fatalf("\n❌ %v", err)
	}
}

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

func showLicenseInfo(license *client.LicenseData) {
	if license == nil {
		return
	}
	fmt.Println("\n📄 License Information:")
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Printf("  User: %s\n", license.Username)
	fmt.Printf("  Email: %s\n", license.Email)
	if license.ClientID != "" {
		fmt.Printf("  Client ID: %s\n", license.ClientID)
	}
	fmt.Printf("  License ID: %s\n", license.ID)
	if license.DeviceFingerprint != "" {
		fmt.Printf("  This device: %s...\n", truncateFingerprint(license.DeviceFingerprint))
	}
	fmt.Printf("  Issued: %s\n", license.IssuedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Expires: %s\n", license.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("  Activations: %d / %d\n", license.CurrentActivations, license.MaxActivations)
	if len(license.Devices) > 0 {
		fmt.Println("  Registered devices:")
		for _, device := range license.Devices {
			if device.Fingerprint == "" {
				continue
			}
			fmt.Printf("    • %s... | activated %s | last seen %s\n",
				truncateFingerprint(device.Fingerprint),
				formatTimestamp(device.ActivatedAt),
				formatTimestamp(device.LastSeenAt),
			)
		}
	}

	daysLeft := int(time.Until(license.ExpiresAt).Hours() / 24)
	if daysLeft > 0 {
		fmt.Printf("  Days remaining: %d\n", daysLeft)
	} else {
		fmt.Println("  Status: ⚠️  EXPIRED")
	}
	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
}

func runApplication(ctx context.Context, license *client.LicenseData) error {
	fmt.Println()
	fmt.Println("🚀 Starting application...")
	fmt.Println()
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Printf("║  Welcome, %s!%-25s║\n", license.Username, strings.Repeat(" ", max(0, 25-len(license.Username))))
	fmt.Println("║                                           ║")
	fmt.Println("║  Your application is running with a       ║")
	fmt.Println("║  valid TPM-protected license.             ║")
	fmt.Println("║                                           ║")
	fmt.Println("║  All operations are cryptographically     ║")
	fmt.Println("║  verified and device-locked.              ║")
	fmt.Println("╚═══════════════════════════════════════════╝")

	fmt.Println("\n📊 Application Status:")
	fmt.Println("  ✓ License verified")
	fmt.Println("  ✓ Device authenticated")
	fmt.Println("  ✓ Signature validated")
	fmt.Println("  ✓ All systems operational")

	showLicenseInfo(license)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "Hello, world! License holder: %s\n", license.Username)
	})

	server := &http.Server{Addr: ":8081", Handler: mux}
	errCh := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	fmt.Println("\n🌐 HTTP server listening on http://localhost:8081")
	fmt.Println("\nPress Ctrl+C to exit")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)

	select {
	case <-ctx.Done():
		fmt.Println("\n🛑 Context cancelled. Shutting down server...")
	case sig := <-sigCh:
		fmt.Printf("\n🛑 Received %s. Shutting down server...\n", sig)
	case err := <-errCh:
		return fmt.Errorf("http server error: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http server shutdown: %w", err)
	}

	fmt.Println("✅ Server stopped gracefully")
	return nil
}

func showBanner() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Printf("║  %s v%s%-20s║\n", APP_NAME, APP_VERSION, "")
	fmt.Println("║  TPM-Protected Licensed Application       ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
}

func truncateFingerprint(fp string) string {
	if len(fp) <= 16 {
		return fp
	}
	return fp[:16]
}

func formatTimestamp(ts time.Time) string {
	if ts.IsZero() {
		return "n/a"
	}
	return ts.Format("2006-01-02 15:04:05")
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
