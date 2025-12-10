package main

import (
	"fmt"
	"log"

	"github.com/oarkflow/licensing/pkg/licensing"
)

// Example: Using email templates with embedded and filesystem modes

func main() {
	fmt.Println("=== Email Template Loader Examples ===\n")

	// Example 1: Using embedded templates (production mode)
	fmt.Println("1. Loading from embedded templates:")
	embeddedLoader := licensing.NewEmailTemplateLoader(licensing.TemplatesFS)
	if err := embeddedLoader.LoadTemplates(); err != nil {
		log.Fatalf("Failed to load embedded templates: %v", err)
	}
	fmt.Println("   ✓ Embedded templates loaded successfully")

	data := licensing.EmailTemplateData{
		ClientName:  "John Doe",
		PlanName:    "Enterprise",
		ProductName: "Acme Software",
		Email:       "john@example.com",
	}

	html, err := embeddedLoader.RenderTemplate("welcome_email", data)
	if err != nil {
		log.Fatalf("Failed to render: %v", err)
	}
	fmt.Printf("   ✓ Rendered template length: %d bytes\n\n", len(html))

	// Example 2: Using filesystem templates (development mode)
	fmt.Println("2. Loading from filesystem:")
	fsLoader := licensing.NewEmailTemplateLoader()
	if err := fsLoader.LoadTemplates(); err != nil {
		log.Printf("   ⚠ Filesystem fallback failed: %v", err)
		fmt.Println("   (This is expected if running outside the repo)")
	} else {
		fmt.Println("   ✓ Filesystem templates loaded successfully")
		html, err := fsLoader.RenderTemplate("welcome_email", data)
		if err != nil {
			log.Fatalf("Failed to render: %v", err)
		}
		fmt.Printf("   ✓ Rendered template length: %d bytes\n", len(html))
	}

	fmt.Println("\nBoth modes work! The server automatically prefers embedded templates.")
	fmt.Println("To override, set EMAIL_TEMPLATES_DIR environment variable.")
}
