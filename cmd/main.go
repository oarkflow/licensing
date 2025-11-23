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
	fmt.Println("║    TPM-Based Licensing System             ║")
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
	log.Printf("📦 Storage backend: %s", storageMode)
	if pubPath := lm.PublicKeyPath(); pubPath != "" {
		log.Printf("🔑 Public key stored at %s", pubPath)
	}
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

	// Create demo clients and licenses
	fmt.Println("📋 Creating demo clients and licenses...")

	client1, _ := lm.CreateClient(ctx, "john@example.com", "john_doe")
	license1, _ := lm.GenerateLicense(ctx, client1.ID, 365*24*time.Hour, 3)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client1.Email, license1.LicenseKey)

	client2, _ := lm.CreateClient(ctx, "jane@example.com", "jane_smith")
	license2, _ := lm.GenerateLicense(ctx, client2.ID, 30*24*time.Hour, 5)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client2.Email, license2.LicenseKey)

	client3, _ := lm.CreateClient(ctx, "bob@example.com", "bob_jones")
	license3, _ := lm.GenerateLicense(ctx, client3.ID, 90*24*time.Hour, 2)
	fmt.Printf("   ✓ Client: %s | License: %s\n", client3.Email, license3.LicenseKey)

	fmt.Println()

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
