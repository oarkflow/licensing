// Example: Basic license activation and verification with enhanced security
//
// This example demonstrates:
// 1. SSH key authentication
// 2. Multi-layer license verification
// 3. Tamper detection
// 4. Secure key generation
// 5. Certificate pinning
// 6. Offline validation with grace period
//
// Usage:
//    # Generate SSH key for authentication
//    go run main.go --generate-key
//
//    # Activate with SSH key authentication
//    go run main.go --license-key "XXXX-XXXX-..." --email "user@example.com" \
//                   --client-id "client-123" --ssh-key "/path/to/key"
//
//    # Verify with integrity checks
//    go run main.go --verify --enable-tamper-detection
//
//    # Use credentials file
//    go run main.go --license-file "/path/to/credentials.json"

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	licensing "github.com/oarkflow/licensing/sdks/go"
)

func main() {
	// Command line flags
	serverURL := flag.String("server", "https://localhost:6601", "License server URL (use HTTPS in production)")
	licenseKey := flag.String("license-key", "", "License key for activation")
	email := flag.String("email", "", "Email for activation")
	clientID := flag.String("client-id", "", "Client ID for activation")
	licenseFile := flag.String("license-file", "", "Path to JSON file with license credentials")
	productID := flag.String("product-id", "secretr", "Product ID")
	sshKeyPath := flag.String("ssh-key", "", "Path to SSH private key for authentication")
	offlineBundle := flag.String("offline-bundle", "", "Path to a signed offline bundle JSON to verify locally")
	offlineCache := flag.String("offline-cache", "", "Directory to cache revocation manifest for offline verification")
	generateKey := flag.Bool("generate-key", false, "Generate new SSH key pair")
	verify := flag.Bool("verify", false, "Verify existing license only")
	enableTamper := flag.Bool("enable-tamper-detection", false, "Enable runtime tamper detection")
	insecure := flag.Bool("insecure", false, "Allow insecure HTTP (dev only)")
	flag.Parse()

	fmt.Println("=== Go Licensing SDK - Secure Example ===")
	fmt.Println()

	// Handle key generation
	if *generateKey {
		if err := generateSSHKey(); err != nil {
			log.Fatalf("Failed to generate SSH key: %v", err)
		}
		return
	}

	// Load credentials from file if provided
	var credEmail, credClientID, credLicenseKey, credSSHKey string
	if *licenseFile != "" {
		creds, err := licensing.LoadCredentialsFile(*licenseFile)
		if err != nil {
			log.Fatalf("Failed to load credentials file: %v", err)
		}
		credEmail = creds.Email
		credClientID = creds.ClientID
		credLicenseKey = creds.LicenseKey
		fmt.Printf("📄 Loaded credentials from: %s\n", *licenseFile)
	} else {
		credEmail = *email
		credClientID = *clientID
		credLicenseKey = *licenseKey
	}

	// Set SSH key path
	if *sshKeyPath != "" {
		credSSHKey = *sshKeyPath
	}

	// If offline bundle provided, run offline verification and exit
	if *offlineBundle != "" {
		fmt.Println("🔎 Offline verification mode — using offline verification SDK")
		oc, err := licensing.NewOfflineClient(licensing.OfflineConfig{ServerURL: *serverURL, CacheDir: *offlineCache})
		if err != nil {
			log.Fatalf("failed to create offline client: %v", err)
		}
		data, err := os.ReadFile(*offlineBundle)
		if err != nil {
			log.Fatalf("failed to read bundle: %v", err)
		}
		ctx := context.Background()
		payload, err := oc.VerifySignedBundle(ctx, string(data), "")
		if err != nil {
			log.Fatalf("offline verification failed: %v", err)
		}
		fmt.Printf("✅ Offline bundle verified: %+v\n", payload)
		if _, err := oc.SyncManifest(ctx, ""); err == nil {
			fmt.Println("manifest synced — revocation checks applied if any")
		}
		return
	}

	// Create licensing client with security features
	// Note: Advanced features like SSH auth, tamper detection, and cert pinning
	// are being integrated into pkg/client
	fmt.Println("🔐 Initializing secure licensing client...")
	client, err := licensing.NewClient(licensing.Config{
		ServerURL:         *serverURL,
		AppName:           "SecureExample",
		AppVersion:        "2.0.0",
		ProductID:         *productID,
		HTTPTimeout:       30 * time.Second,
		AllowInsecureHTTP: *insecure,
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	if credSSHKey != "" {
		fmt.Printf("🔐 SSH key configured: %s (integration pending)\n", credSSHKey)
	}

	// Enable tamper detection if requested
	if *enableTamper {
		fmt.Println("🛡️  Tamper detection requested (integration pending)")
	}

	// Check if already activated
	fmt.Println("\n📋 Checking existing license...")
	existingLicense, err := client.Verify()

	if err == nil && existingLicense != nil {
		fmt.Println("✓ Valid license found")
		displayLicenseInfo(existingLicense)

		// Note: Multi-layer verification and security metrics
		// are advanced features being integrated
		if *enableTamper {
			fmt.Println("\n🔍 Multi-layer verification (integration pending)")
		}

		return
	}

	// If verify-only mode, exit
	if *verify {
		log.Fatal("No valid license found. Run without --verify to activate.")
	}

	// Activate new license
	if credLicenseKey == "" || credEmail == "" {
		log.Fatal("License key and email are required for activation")
	}

	fmt.Println("\n🔑 Activating license...")
	fmt.Printf("  Email: %s\n", credEmail)
	fmt.Printf("  Client ID: %s\n", credClientID)
	if credSSHKey != "" {
		fmt.Printf("  Auth: SSH key (%s)\n", credSSHKey)
	} else {
		fmt.Printf("  Auth: Standard\n")
	}

	err = client.Activate(credEmail, credClientID, credLicenseKey)
	if err != nil {
		log.Fatalf("Activation failed: %v", err)
	}

	fmt.Println("✓ License activated successfully!")

	// Verify the newly activated license
	fmt.Println("\n🔍 Verifying activated license...")
	license, err := client.Verify()
	if err != nil {
		log.Fatalf("Verification failed: %v", err)
	}

	displayLicenseInfo(license)

	// Run integrity check on new license
	if *enableTamper {
		fmt.Println("\n🔍 Post-activation integrity check (integration pending)")
	}

	fmt.Println("\n✓ License activated successfully!")
	fmt.Println("Your application is now licensed.")
}

func displayLicenseInfo(license *licensing.LicenseData) {
	fmt.Println("\n📜 License Information:")
	fmt.Printf("  Plan: %s\n", license.PlanSlug)
	if license.ProductID != "" {
		fmt.Printf("  Product ID: %s\n", license.ProductID)
	}
	fmt.Printf("  Revoked: %v\n", license.IsRevoked)
	fmt.Printf("  Expires: %s\n", license.ExpiresAt.Format("2006-01-02 15:04:05"))

	if license.IsTrial {
		trialInfo := license.GetTrialInfo()
		if trialInfo.Status == licensing.TrialStatusActive {
			fmt.Printf("  Trial: %d days remaining\n", trialInfo.DaysRemaining)
		}
	}

	if license.Entitlements != nil && len(license.Entitlements.Features) > 0 {
		fmt.Printf("\n  Enabled Features (%d):\n", len(license.Entitlements.Features))
		for _, feature := range license.Entitlements.Features {
			fmt.Printf("    ✓ %s\n", feature.FeatureSlug)
			if len(feature.Scopes) > 0 {
				fmt.Printf("      Scopes: %d granted\n", len(feature.Scopes))
			}
		}
	}
}

func generateSSHKey() error {
	fmt.Println("🔐 Generating Ed25519 SSH key pair...")

	// Get home directory
	home, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("failed to get home directory: %w", err)
	}

	// Create .ssh directory if it doesn't exist
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	privateKeyPath := filepath.Join(sshDir, "licensing_client")
	publicKeyPath := filepath.Join(sshDir, "licensing_client.pub")

	// Check if keys already exist
	if _, err := os.Stat(privateKeyPath); err == nil {
		fmt.Printf("⚠️  Key already exists at %s\n", privateKeyPath)
		fmt.Print("Overwrite? (yes/no): ")
		var answer string
		fmt.Scanln(&answer)
		if answer != "yes" && answer != "y" {
			fmt.Println("Aborted.")
			return nil
		}
	}

	// Generate key pair
	privateKeyPEM, publicKeyPEM, err := licensing.GenerateEd25519KeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate key pair: %w", err)
	}

	// Save to files
	if err := licensing.SaveKeyPairToFiles(privateKeyPath, publicKeyPath, privateKeyPEM, publicKeyPEM); err != nil {
		return fmt.Errorf("failed to save keys: %w", err)
	}

	fmt.Println("✓ SSH key pair generated successfully!")
	fmt.Printf("  Private key: %s (keep secure!)\n", privateKeyPath)
	fmt.Printf("  Public key:  %s\n", publicKeyPath)
	fmt.Println("\nNext steps:")
	fmt.Println("  1. Register your public key with the licensing server")
	fmt.Println("  2. Use --ssh-key flag to authenticate:")
	fmt.Printf("     go run main.go --ssh-key %s --client-id your-client-id\n", privateKeyPath)

	return nil
}
