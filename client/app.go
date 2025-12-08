package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/oarkflow/licensing/pkg/activation"
	"github.com/oarkflow/licensing/pkg/client"
	"github.com/oarkflow/licensing/pkg/runner"
)

var sharedClient *client.Client

func main() {
	os.Setenv(EnvAllowInsecureHTTP, "true")
	flag.Parse()
	activation.SetLicenseFilePath(strings.TrimSpace(*licenseInfoFileFlag))

	mode := strings.ToLower(strings.TrimSpace(*activationMode))
	clientCfg := resolveClientConfig()
	factory := func() (runner.Client[*client.LicenseData], error) {
		if sharedClient != nil {
			return sharedClient, nil
		}
		cli, err := client.New(clientCfg)
		if err != nil {
			return nil, err
		}
		sharedClient = cli
		return sharedClient, nil
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

func runApplication(ctx context.Context, license *client.LicenseData) error {
	fmt.Println()
	fmt.Println("🚀 Starting application...")
	var licenseState atomic.Value
	licenseState.Store(license)
	t, _ := json.MarshalIndent(license, "", "  ")
	fmt.Println("Current License State:")
	fmt.Println(string(t))
	bgCtx, bgCancel := context.WithCancel(ctx)
	defer bgCancel()

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		current := license
		if stored := licenseState.Load(); stored != nil {
			if latest, ok := stored.(*client.LicenseData); ok && latest != nil {
				current = latest
			}
		}
		ctx := context.WithValue(r.Context(), "license", current)
		r = r.WithContext(ctx)
		data, _ := json.Marshal(current)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
	})

	server := &http.Server{Addr: ":8081", Handler: mux}
	errCh := make(chan error, 2)
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	if sharedClient != nil && strings.EqualFold(strings.TrimSpace(license.CheckMode), "custom") {
		go func() {
			err := sharedClient.RunBackgroundVerification(bgCtx, license, log.Printf, func(updated *client.LicenseData) {
				licenseState.Store(updated)
			})
			if err != nil && !errors.Is(err, context.Canceled) {
				errCh <- fmt.Errorf("background verification error: %w", err)
			}
		}()
	}

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
		return fmt.Errorf("runtime error: %w", err)
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("http server shutdown: %w", err)
	}

	fmt.Println("✅ Server stopped gracefully")
	return nil
}
