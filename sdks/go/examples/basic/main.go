// Example: Basic license activation and verification with security
//
// This example shows the minimal code needed to:
// 1. Request a trial license (if eligible)
// 2. Activate a license with credentials
// 3. Verify the license is valid
// 4. Handle trial expiration with subscription prompts
// 5. Access license data and check features
// 6. Use SSH key authentication (recommended)
//
// Usage:
//    go run main.go --license-key "XXXX-XXXX-..." --email "user@example.com" --client-id "client-123"
//
// Or using a credentials file:
//    go run main.go --license-file "/path/to/credentials.json"
//
// Or start a trial:
//    go run main.go --trial --email "user@example.com"
//
// With SSH authentication (recommended):
//    go run main.go --license-key "XXXX-XXXX-..." --email "user@example.com" --client-id "client-123" --ssh-key ~/.ssh/licensing_client
//
// Credentials file format:
//    {"email": "user@example.com", "client_id": "client-123", "license_key": "XXXX-XXXX-..."}

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
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
	startTrial := flag.Bool("trial", false, "Start a trial license")
	productID := flag.String("product-id", "", "Product ID for trial (optional)")
	subscriptionURL := flag.String("subscription-url", "https://example.com/subscribe", "URL to subscribe after trial")
	sshKeyPath := flag.String("ssh-key", "", "Path to SSH private key for authentication (recommended)")
	insecure := flag.Bool("insecure", false, "Allow insecure HTTP (dev only, not recommended)")
	flag.Parse()

	fmt.Println("=== Go Licensing SDK - Basic Example ===")
	fmt.Println()

	// Load credentials from file if provided
	var credEmail, credClientID, credLicenseKey string
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
		// Use command line flags
		credEmail = *email
		credClientID = *clientID
		credLicenseKey = *licenseKey
	}

	// Create licensing client
	client, err := licensing.NewClient(licensing.Config{
		ServerURL:         *serverURL,
		AppName:           "BasicExample",
		AppVersion:        "1.0.0",
		HTTPTimeout:       15 * time.Second,
		AllowInsecureHTTP: *insecure,
		ProductID:         "secretr",
	})
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}

	if *sshKeyPath != "" {
		fmt.Printf("🔐 SSH key path provided: %s (Note: SSH auth integration pending)\n", *sshKeyPath)
	}

	// Step 1: Check if already activated
	if client.IsActivated() {
		fmt.Println("✅ License already exists locally")
	} else {
		fmt.Println("📝 No local license found")

		// Check if user wants to start a trial
		if *startTrial {
			if credEmail == "" {
				fmt.Println("❌ Email is required for trial. Use --email flag.")
				os.Exit(1)
			}

			fmt.Println("🎁 Requesting trial license...")

			// Check trial eligibility first
			eligibility, err := client.CheckTrialEligibility(*productID)
			if err != nil {
				log.Fatalf("❌ Failed to check trial eligibility: %v", err)
			}

			if !eligibility.Eligible {
				fmt.Printf("❌ Trial not available: %s\n", eligibility.Message)
				if eligibility.HasUsedTrial {
					fmt.Println()
					fmt.Println("═══════════════════════════════════════════════════════════════")
					fmt.Println("⚠️  This device has already used a trial.")
					fmt.Println()
					fmt.Printf("🔗 Subscribe now: %s\n", *subscriptionURL)
					fmt.Println()
					fmt.Println("Or enter your license credentials:")
					fmt.Println("  go run main.go --license-key KEY --email EMAIL --client-id ID")
					fmt.Println("═══════════════════════════════════════════════════════════════")
				}
				os.Exit(1)
			}

			// Request trial license
			_, err = client.RequestTrial(credEmail, *productID, "", 14)
			if err != nil {
				log.Fatalf("❌ Trial activation failed: %v", err)
			}
			fmt.Println("✅ Trial license activated successfully!")
		} else {
			// Validate credentials for regular activation
			if credLicenseKey == "" || credEmail == "" || credClientID == "" {
				fmt.Println()
				fmt.Println("Usage: go run main.go --license-key KEY --email EMAIL --client-id ID")
				fmt.Println("   or: go run main.go --license-file /path/to/credentials.json")
				fmt.Println("   or: go run main.go --trial --email EMAIL")
				fmt.Println()
				fmt.Println("Credentials file format:")
				fmt.Println(`  {"email": "...", "client_id": "...", "license_key": "..."}`)
				fmt.Println()
				fmt.Println("To get credentials:")
				fmt.Println("1. Start the license server: go run cmd/server/main.go")
				fmt.Println("2. Create a client via API")
				fmt.Println("3. Create a license via API")
				fmt.Println("4. Use the license_key from the response")
				fmt.Println()
				fmt.Println("Or start a 14-day trial:")
				fmt.Println("  go run main.go --trial --email user@example.com")
				os.Exit(1)
			}

			// Step 2: Activate the license
			fmt.Println("🔑 Activating license...")
			err := client.Activate(credEmail, credClientID, credLicenseKey)
			if err != nil {
				log.Fatalf("❌ Activation failed: %v", err)
			}
			fmt.Println("✅ License activated successfully!")
		}
	}

	// Step 3: Verify the license and get license data
	fmt.Println()
	fmt.Println("🔍 Verifying license...")
	license, err := client.Verify()
	if err != nil {
		log.Fatalf("❌ Verification failed: %v", err)
	}
	fmt.Println("✅ License is valid!")

	// Step 4: Check for trial status and handle expiration
	if license.IsTrial {
		trialInfo := license.GetTrialInfo()
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Println("🎁 TRIAL LICENSE")
		fmt.Println("═══════════════════════════════════════════════════════════════")

		if trialInfo.IsExpired {
			// Trial has expired - show subscription prompt
			fmt.Println("⚠️  Your trial has expired!")
			fmt.Println()
			fmt.Printf("🔗 Subscribe now: %s\n", *subscriptionURL)
			fmt.Println()
			fmt.Println("Or enter your license credentials:")
			fmt.Println("  go run main.go --license-key KEY --email EMAIL --client-id ID")
			fmt.Println("═══════════════════════════════════════════════════════════════")
			os.Exit(1)
		}

		// Trial is still active
		fmt.Printf("📅 %s\n", trialInfo.Message)
		if trialInfo.DaysRemaining <= 3 {
			fmt.Println()
			fmt.Println("⚠️  Your trial is ending soon!")
			fmt.Printf("🔗 Subscribe to continue: %s\n", *subscriptionURL)
		}
		fmt.Println("═══════════════════════════════════════════════════════════════")
	}

	// Display license info
	fmt.Println()
	fmt.Println("=== License Information ===")
	fmt.Printf("ID:          %s\n", license.ID)
	fmt.Printf("Email:       %s\n", license.Email)
	fmt.Printf("Plan:        %s\n", license.PlanSlug)
	if license.IsTrial {
		fmt.Printf("Type:        🎁 Trial\n")
		fmt.Printf("Trial Ends:  %s\n", license.TrialExpiresAt.Format("2006-01-02 15:04:05"))
	} else {
		fmt.Printf("Type:        Licensed\n")
	}
	fmt.Printf("Issued:      %s\n", license.IssuedAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Expires:     %s\n", license.ExpiresAt.Format("2006-01-02 15:04:05"))
	fmt.Printf("Max Devices: %d\n", license.MaxDevices)
	fmt.Printf("Activated:   %d device(s)\n", license.CurrentActivations)

	// Step 5: Check features (if entitlements are configured)
	fmt.Println()
	fmt.Println("=== Feature Access ===")

	if license.Entitlements != nil {
		fmt.Printf("Product: %s\n", license.Entitlements.ProductSlug)
		fmt.Printf("Plan:    %s\n", license.Entitlements.PlanSlug)
		fmt.Println()

		// List all features
		for slug, feature := range license.Entitlements.Features {
			status := "❌ Disabled"
			if feature.Enabled {
				status = "✅ Enabled"
			}
			fmt.Printf("  Feature: %s - %s\n", slug, status)

			// List scopes
			for scopeSlug, scope := range feature.Scopes {
				permission := string(scope.Permission)
				if scope.Limit > 0 {
					permission = fmt.Sprintf("%s (limit: %d)", permission, scope.Limit)
				}
				fmt.Printf("    - %s: %s\n", scopeSlug, permission)
			}
		}
	} else {
		fmt.Println("No feature entitlements configured for this license.")
		fmt.Println("Configure a product, plan, and features in the license server")
		fmt.Println("to enable feature-based access control.")
	}

	// Step 6: Demonstrate feature checking
	fmt.Println()
	fmt.Println("=== Feature Checks ===")

	features := []string{"gui", "cli", "api", "premium"}
	for _, feat := range features {
		if license.HasFeature(feat) {
			fmt.Printf("✅ Feature '%s' is available\n", feat)
		} else {
			fmt.Printf("❌ Feature '%s' is not available\n", feat)
		}
	}

	// Step 7: Demonstrate scope checking
	fmt.Println()
	fmt.Println("=== Scope Checks ===")

	scopes := [][2]string{
		{"gui", "list"},
		{"gui", "create"},
		{"gui", "update"},
		{"gui", "delete"},
		{"api", "read"},
		{"api", "write"},
	}

	for _, scope := range scopes {
		feature, scopeName := scope[0], scope[1]
		allowed, limit := license.CanPerform(feature, scopeName)
		if allowed {
			if limit > 0 {
				fmt.Printf("✅ Can %s:%s (limit: %d)\n", feature, scopeName, limit)
			} else {
				fmt.Printf("✅ Can %s:%s\n", feature, scopeName)
			}
		} else {
			fmt.Printf("❌ Cannot %s:%s\n", feature, scopeName)
		}
	}

	fmt.Println()
	fmt.Println("=== Done ===")

	// Display credentials for saving (only if we have them from activation)
	if credEmail != "" && credClientID != "" && credLicenseKey != "" {
		fmt.Println()
		fmt.Println("═══════════════════════════════════════════════════════════════")
		fmt.Println("📄 Save the following credentials for future use:")
		fmt.Printf("   File: license-%s.json\n", license.ClientID)
		fmt.Println("   Content:")
		fmt.Println("   ─────────────────────────────────────────────────────────────")
		credJSON := fmt.Sprintf(`{
  "email": "%s",
  "client_id": "%s",
  "license_key": "%s"
}`, credEmail, credClientID, credLicenseKey)
		fmt.Println(credJSON)
		fmt.Println("   ─────────────────────────────────────────────────────────────")
		fmt.Printf("   Usage: go run main.go --license-file license-%s.json\n", license.ClientID)
		fmt.Println("═══════════════════════════════════════════════════════════════")
	}
}
