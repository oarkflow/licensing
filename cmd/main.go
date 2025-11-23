package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/oarflow/licensing/pkg/licensing"
	"github.com/oarflow/licensing/pkg/utils"
)

// ==================== Main ====================

func main() {
	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    License Manager Server                 ║")
	fmt.Println("║    Hardware-Secured Licensing System      ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	// Initialize storage + License Manager
	ctx := context.Background()
	storage, storageMode, err := licensing.BuildStorageFromEnv()
	if err != nil {
		log.Fatalf("Failed to configure storage: %v", err)
	}
	lm, err := licensing.NewLicenseManager(storage)
	if err != nil {
		log.Fatalf("Failed to initialize License Manager: %v", err)
	}
	defer func() {
		if err := lm.Close(); err != nil {
			log.Printf("Error closing license manager: %v", err)
		}
	}()
	log.Printf("📦 Storage backend: %s", storageMode)
	if pubPath := lm.PublicKeyPath(); pubPath != "" {
		log.Printf("🔑 Public key stored at %s", pubPath)
	}
	log.Printf("🔏 Signing provider: %s", lm.SigningProviderID())
	adminUser, bootstrapPassword, bootstrapKey, err := lm.EnsureDefaultAdmin(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize admin user: %v", err)
	}
	if adminUser != nil {
		log.Printf("🆕 Default admin user created: %s", adminUser.Username)
		log.Printf("   Temporary password: %s", bootstrapPassword)
		log.Printf("   Bootstrap API key: %s", bootstrapKey)
		log.Printf("   Rotate these credentials immediately after logging in.")
	}

	if shouldBootstrapDemoData() {
		if err := createDemoData(ctx, lm); err != nil {
			log.Printf("⚠️ Failed to bootstrap demo data: %v", err)
		}
	} else {
		log.Printf("📋 Demo bootstrap skipped (set LICENSE_SERVER_BOOTSTRAP_DEMO=true to enable)")
	}

	rawAPIKeys := os.Getenv("LICENSE_SERVER_API_KEYS")
	apiKeys := utils.ParseAPIKeys(rawAPIKeys)
	if len(apiKeys) == 0 {
		if single := strings.TrimSpace(os.Getenv("LICENSE_SERVER_API_KEY")); single != "" {
			apiKeys = append(apiKeys, single)
		}
	}
	if len(apiKeys) > 0 {
		log.Printf("🔐 Loaded %d legacy admin API key(s) from environment", len(apiKeys))
	} else {
		log.Printf("🔐 No legacy API keys configured - relying on stored user API keys")
	}
	rateLimiter := licensing.NewRateLimiter(30, time.Minute)
	tlsCert := os.Getenv("LICENSE_SERVER_TLS_CERT")
	tlsKey := os.Getenv("LICENSE_SERVER_TLS_KEY")
	clientCA := os.Getenv("LICENSE_SERVER_CLIENT_CA")
	if tlsCert == "" || tlsKey == "" {
		log.Printf("⚠️ TLS disabled - set LICENSE_SERVER_TLS_CERT and LICENSE_SERVER_TLS_KEY to enable HTTPS")
	} else if clientCA != "" {
		log.Printf("🔒 mTLS enabled - client CA set to %s", clientCA)
	} else {
		log.Printf("🔒 TLS certificate configured (server-only mode)")
	}
	server, err := licensing.NewServer(lm, ":8080", apiKeys, rateLimiter, tlsCert, tlsKey, clientCA)
	if err != nil {
		log.Fatalf("Failed to initialize server: %v", err)
	}

	// Start HTTP server
	if err := server.Start(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func shouldBootstrapDemoData() bool {
	flag := strings.TrimSpace(os.Getenv("LICENSE_SERVER_BOOTSTRAP_DEMO"))
	if flag == "" {
		return false
	}
	switch strings.ToLower(flag) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func createDemoData(ctx context.Context, lm *licensing.LicenseManager) error {
	log.Printf("📋 Creating demo clients and licenses...")
	type seed struct {
		email    string
		user     string
		duration time.Duration
		max      int
	}
	seeds := []seed{
		{"john@example.com", "john_doe", 365 * 24 * time.Hour, 3},
		{"jane@example.com", "jane_smith", 30 * 24 * time.Hour, 5},
		{"bob@example.com", "bob_jones", 90 * 24 * time.Hour, 2},
	}
	for _, s := range seeds {
		client, err := lm.CreateClient(ctx, s.email, s.user)
		if err != nil {
			return err
		}
		license, err := lm.GenerateLicense(ctx, client.ID, s.duration, s.max)
		if err != nil {
			return err
		}
		log.Printf("   ✓ Client: %s | License: %s", client.Email, license.LicenseKey)
	}
	return nil
}
