package main

import (
	"fmt"

	"github.com/oarkflow/licensing/pkg/licensing"
)

// Small debug utility to render and print email templates
func main() {
	loader := licensing.NewEmailTemplateLoader()
	if err := loader.LoadTemplates(); err != nil {
		fmt.Printf("failed to load templates: %v\n", err)
		return
	}

	welcomeData := licensing.EmailTemplateData{
		ClientName:  "John Doe",
		PlanName:    "Premium",
		ProductName: "Acme Software",
		Email:       "john@example.com",
		SupportURL:  "https://support.acme.com",
		DocsURL:     "https://docs.acme.com",
	}

	w, err := loader.RenderTemplate("welcome_email", welcomeData)
	if err != nil {
		fmt.Printf("render welcome failed: %v\n", err)
		return
	}
	fmt.Println("-----WELCOME-----")
	fmt.Println(w)

	licenseData := licensing.EmailTemplateData{
		ClientName:  "Jane Smith",
		ProductName: "Acme Pro",
		Email:       "jane@example.com",
		LicenseJSON: `{"license_key": "ABC123", "expires_at": "2024-12-31"}`,
		SupportURL:  "https://support.acme.com",
		DocsURL:     "https://docs.acme.com",
	}

	l, err := loader.RenderTemplate("license_email", licenseData)
	if err != nil {
		fmt.Printf("render license failed: %v\n", err)
		return
	}
	fmt.Println("-----LICENSE-----")
	fmt.Println(l)
}
