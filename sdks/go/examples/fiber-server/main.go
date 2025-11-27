// Example: Fiber HTTP server with license-protected routes
//
// This example demonstrates how to integrate the licensing SDK
// into a GoFiber web application with:
// - License activation middleware
// - Feature-gated routes
// - Scope-based permission checking
// - Background license verification
//
// Prerequisites:
// 1. Run the licensing server:
//    cd /path/to/licensing && go run cmd/server/main.go
// 2. Create a client and license via the admin API
// 3. Run this example with the license key
//
// Usage:
//    go run main.go --license-key "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" \
//                   --email "user@example.com" \
//                   --client-id "client-123"
//
// Or using a credentials file:
//    go run main.go --license-file "/path/to/credentials.json"
//
// Credentials file format:
//    {"email": "user@example.com", "client_id": "client-123", "license_key": "XXXX-XXXX-..."}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"

	licensing "github.com/oarkflow/licensing/sdks/go"
)

// LicenseMiddleware stores the licensing client for route handlers
type LicenseMiddleware struct {
	client  *licensing.Client
	license *licensing.LicenseData
}

func main() {
	// Parse command line flags
	serverURL := flag.String("server", "http://localhost:8801", "License server URL")
	licenseKey := flag.String("license-key", "", "License key for activation")
	email := flag.String("email", "", "Email for activation")
	clientID := flag.String("client-id", "", "Client ID for activation")
	licenseFile := flag.String("license-file", "", "Path to JSON file with license credentials")
	httpAddr := flag.String("http", ":3000", "HTTP server address")
	configDir := flag.String("config-dir", "", "Configuration directory (default: ~/.myapp)")
	flag.Parse()

	// Set defaults
	if *configDir == "" {
		home, _ := os.UserHomeDir()
		*configDir = home + "/.myapp-example"
	}

	// Load credentials from file if provided
	var credEmail, credClientID, credLicenseKey string
	if *licenseFile != "" {
		creds, err := licensing.LoadCredentialsFile(*licenseFile)
		if err != nil {
			log.Fatalf("❌ Failed to load credentials file: %v", err)
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

	fmt.Println("╔═══════════════════════════════════════════╗")
	fmt.Println("║    Fiber Server with License Protection   ║")
	fmt.Println("║    Using Go Licensing SDK                 ║")
	fmt.Println("╚═══════════════════════════════════════════╝")
	fmt.Println()

	// Create licensing client
	client, err := licensing.NewClient(licensing.Config{
		ServerURL:         *serverURL,
		ConfigDir:         *configDir,
		LicenseFile:       ".license.dat",
		AppName:           "FiberExample",
		AppVersion:        "1.0.0",
		HTTPTimeout:       15 * time.Second,
		AllowInsecureHTTP: true, // Only for development!
	})
	if err != nil {
		log.Fatalf("❌ Failed to create licensing client: %v", err)
	}

	// Check if we need to activate
	if !client.IsActivated() {
		if credLicenseKey == "" || credEmail == "" || credClientID == "" {
			log.Fatal("❌ No license found. Please provide --license-key, --email, and --client-id or --license-file")
		}

		log.Printf("🔑 Activating license...")
		err := client.Activate(credEmail, credClientID, credLicenseKey)
		if err != nil {
			log.Fatalf("❌ Activation failed: %v", err)
		}
		log.Printf("✅ License activated successfully!")
	}

	// Verify license and get license data
	log.Printf("🔍 Verifying license...")
	license, err := client.Verify()
	if err != nil {
		log.Fatalf("❌ License verification failed: %v", err)
	}

	log.Printf("✅ License valid!")
	log.Printf("   ID: %s", license.ID)
	log.Printf("   Plan: %s", license.PlanSlug)
	log.Printf("   Email: %s", license.Email)
	log.Printf("   Expires: %s", license.ExpiresAt.Format("2006-01-02"))
	if license.Entitlements != nil {
		log.Printf("   Product: %s", license.Entitlements.ProductSlug)
		log.Printf("   Features: %d", len(license.Entitlements.Features))
	}

	// Create middleware
	lm := &LicenseMiddleware{
		client:  client,
		license: license,
	}

	// Start background verification
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go client.RunBackgroundVerification(ctx, license, log.Printf, func(updated *licensing.LicenseData) {
		lm.license = updated
		log.Printf("📋 License data refreshed")
	})

	// Create Fiber app
	app := fiber.New(fiber.Config{
		AppName:      "Licensed Fiber App",
		ErrorHandler: customErrorHandler,
	})

	// Global middleware
	app.Use(recover.New())
	app.Use(logger.New())

	// Public routes (no license check needed)
	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Welcome to the Licensed Fiber Server",
			"status":  "running",
		})
	})

	app.Get("/health", func(c *fiber.Ctx) error {
		// Re-verify to check current status
		_, verifyErr := client.Verify()
		return c.JSON(fiber.Map{
			"status":  "healthy",
			"license": verifyErr == nil,
		})
	})

	// License info endpoint
	app.Get("/license", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"id":         lm.license.ID,
			"plan":       lm.license.PlanSlug,
			"email":      lm.license.Email,
			"expires_at": lm.license.ExpiresAt,
			"product_id": lm.license.ProductID,
			"plan_id":    lm.license.PlanID,
		})
	})

	// Protected API group - requires valid license
	api := app.Group("/api", lm.RequireLicense())

	// Basic protected route
	api.Get("/data", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "This is protected data",
			"time":    time.Now(),
		})
	})

	// Feature-gated routes
	api.Get("/gui", lm.RequireFeature("gui"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "GUI feature is enabled",
			"feature": "gui",
		})
	})

	api.Get("/cli", lm.RequireFeature("cli"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "CLI feature is enabled",
			"feature": "cli",
		})
	})

	api.Get("/premium", lm.RequireFeature("premium"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Premium feature is enabled",
			"feature": "premium",
		})
	})

	// Scope-gated routes
	api.Get("/secrets", lm.RequireScope("gui", "list"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "List secrets - allowed by gui:list scope",
			"secrets": []string{"secret1", "secret2", "secret3"},
		})
	})

	api.Post("/secrets", lm.RequireScope("gui", "create"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message": "Create secret - allowed by gui:create scope",
			"created": true,
		})
	})

	api.Put("/secrets/:id", lm.RequireScope("gui", "update"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message":   "Update secret - allowed by gui:update scope",
			"secret_id": c.Params("id"),
			"updated":   true,
		})
	})

	api.Delete("/secrets/:id", lm.RequireScope("gui", "delete"), func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message":   "Delete secret - allowed by gui:delete scope",
			"secret_id": c.Params("id"),
			"deleted":   true,
		})
	})

	// Rate-limited route example
	api.Get("/limited", lm.RequireScopeWithLimit("api", "requests"), func(c *fiber.Ctx) error {
		limit := c.Locals("scope_limit").(int)
		return c.JSON(fiber.Map{
			"message": "Rate-limited endpoint",
			"limit":   limit,
		})
	})

	// Entitlements inspection endpoint
	api.Get("/entitlements", func(c *fiber.Ctx) error {
		lic := c.Locals("license").(*licensing.LicenseData)
		if lic.Entitlements == nil {
			return c.JSON(fiber.Map{
				"message": "No entitlements configured for this license",
			})
		}

		features := make(map[string]interface{})
		for slug, feat := range lic.Entitlements.Features {
			scopes := make(map[string]string)
			for scopeSlug, scope := range feat.Scopes {
				scopes[scopeSlug] = string(scope.Permission)
			}
			features[slug] = fiber.Map{
				"enabled":  feat.Enabled,
				"category": feat.Category,
				"scopes":   scopes,
			}
		}

		return c.JSON(fiber.Map{
			"product_id":   lic.Entitlements.ProductID,
			"product_slug": lic.Entitlements.ProductSlug,
			"plan_id":      lic.Entitlements.PlanID,
			"plan_slug":    lic.Entitlements.PlanSlug,
			"features":     features,
		})
	})

	// Graceful shutdown
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
		<-sigChan

		log.Println("🛑 Shutting down server...")
		cancel()
		_ = app.Shutdown()
	}()

	// Start server
	log.Printf("🚀 Server starting on %s", *httpAddr)
	log.Printf("📋 Available endpoints:")
	log.Printf("   GET  /              - Welcome message")
	log.Printf("   GET  /health        - Health check")
	log.Printf("   GET  /license       - License info")
	log.Printf("   GET  /api/data      - Protected data (requires license)")
	log.Printf("   GET  /api/gui       - GUI feature (requires gui feature)")
	log.Printf("   GET  /api/cli       - CLI feature (requires cli feature)")
	log.Printf("   GET  /api/secrets   - List secrets (requires gui:list scope)")
	log.Printf("   POST /api/secrets   - Create secret (requires gui:create scope)")
	log.Printf("   GET  /api/entitlements - View all entitlements")
	fmt.Println()

	// Display credentials for saving (only if we have them from activation)
	if credEmail != "" && credClientID != "" && credLicenseKey != "" {
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
		fmt.Println()
	}

	if err := app.Listen(*httpAddr); err != nil {
		log.Fatalf("❌ Server error: %v", err)
	}
}

// RequireLicense middleware checks if the license is valid
func (lm *LicenseMiddleware) RequireLicense() fiber.Handler {
	return func(c *fiber.Ctx) error {
		// Re-verify license
		license, err := lm.client.Verify()
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "license_invalid",
				"message": "Valid license required to access this resource",
			})
		}

		// Update cached license
		lm.license = license

		// Store license in context for handlers
		c.Locals("license", license)
		return c.Next()
	}
}

// RequireFeature middleware checks if a specific feature is enabled
func (lm *LicenseMiddleware) RequireFeature(featureSlug string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		license := c.Locals("license")
		if license == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "no_license",
				"message": "License context not found",
			})
		}

		lic := license.(*licensing.LicenseData)
		if !lic.HasFeature(featureSlug) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "feature_disabled",
				"message": fmt.Sprintf("Feature '%s' is not enabled for your plan", featureSlug),
				"feature": featureSlug,
				"plan":    lic.PlanSlug,
			})
		}

		return c.Next()
	}
}

// RequireScope middleware checks if a specific scope is allowed
func (lm *LicenseMiddleware) RequireScope(featureSlug, scopeSlug string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		license := c.Locals("license")
		if license == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "no_license",
				"message": "License context not found",
			})
		}

		lic := license.(*licensing.LicenseData)
		if !lic.HasScope(featureSlug, scopeSlug) {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "scope_denied",
				"message": fmt.Sprintf("Scope '%s:%s' is not allowed for your plan", featureSlug, scopeSlug),
				"feature": featureSlug,
				"scope":   scopeSlug,
				"plan":    lic.PlanSlug,
			})
		}

		return c.Next()
	}
}

// RequireScopeWithLimit middleware checks scope and provides limit info
func (lm *LicenseMiddleware) RequireScopeWithLimit(featureSlug, scopeSlug string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		license := c.Locals("license")
		if license == nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"error":   "no_license",
				"message": "License context not found",
			})
		}

		lic := license.(*licensing.LicenseData)
		allowed, limit := lic.CanPerform(featureSlug, scopeSlug)
		if !allowed {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":   "scope_denied",
				"message": fmt.Sprintf("Scope '%s:%s' is not allowed for your plan", featureSlug, scopeSlug),
				"feature": featureSlug,
				"scope":   scopeSlug,
				"plan":    lic.PlanSlug,
			})
		}

		// Store limit in context for handler
		c.Locals("scope_limit", limit)
		return c.Next()
	}
}

func customErrorHandler(c *fiber.Ctx, err error) error {
	code := fiber.StatusInternalServerError
	if e, ok := err.(*fiber.Error); ok {
		code = e.Code
	}
	return c.Status(code).JSON(fiber.Map{
		"error":   "server_error",
		"message": err.Error(),
	})
}
