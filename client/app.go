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
	"syscall"
	"time"

	"github.com/oarflow/licensing/pkg/activation"
	"github.com/oarflow/licensing/pkg/client"
	"github.com/oarflow/licensing/pkg/runner"
)

func main() {
	flag.Parse()
	activation.SetLicenseFilePath(strings.TrimSpace(*licenseInfoFileFlag))

	mode := strings.ToLower(strings.TrimSpace(*activationMode))
	clientCfg := resolveClientConfig()
	factory := func() (runner.Client[*client.LicenseData], error) {
		return client.New(clientCfg)
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

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Add license information to request context
		ctx := context.WithValue(r.Context(), "license", license)
		r = r.WithContext(ctx)
		data, _ := json.Marshal(license)
		w.Header().Set("Content-Type", "application/json")
		w.Write(data)
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
