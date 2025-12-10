package licensing

import (
	"strings"
	"testing"
)

func TestEmailTemplateLoader(t *testing.T) {
	// Create a new template loader
	loader := NewEmailTemplateLoader()

	// Load templates
	err := loader.LoadTemplates()
	if err != nil {
		t.Fatalf("Failed to load email templates: %v", err)
	}

	// Test that we have the expected templates
	expectedTemplates := []string{"welcome_email", "license_email"}
	for _, templateName := range expectedTemplates {
		if _, exists := loader.templates[templateName]; !exists {
			t.Errorf("Expected template %s not found", templateName)
		}
	}

	// Test rendering welcome email template
	welcomeData := EmailTemplateData{
		ClientName:  "John Doe",
		PlanName:    "Premium",
		ProductName: "Acme Software",
		Email:       "john@example.com",
		SupportURL:  "https://support.acme.com",
		DocsURL:     "https://docs.acme.com",
	}

	welcomeHTML, err := loader.RenderTemplate("welcome_email", welcomeData)
	if err != nil {
		t.Errorf("Failed to render welcome email template: %v", err)
	} else {

		// Verify the rendered HTML contains expected content
		if !strings.Contains(welcomeHTML, "John Doe") {
			t.Error("Welcome email doesn't contain client name")
		}
		if !strings.Contains(welcomeHTML, "Premium") {
			t.Error("Welcome email doesn't contain plan name")
		}
		if !strings.Contains(welcomeHTML, "Acme Software") {
			t.Error("Welcome email doesn't contain product name")
		}
	}

	// Test rendering license email template
	licenseData := EmailTemplateData{
		ClientName:  "Jane Smith",
		ProductName: "Acme Pro",
		Email:       "jane@example.com",
		LicenseJSON: `{"license_key": "ABC123", "expires_at": "2024-12-31"}`,
		SupportURL:  "https://support.acme.com",
		DocsURL:     "https://docs.acme.com",
	}

	licenseHTML, err := loader.RenderTemplate("license_email", licenseData)
	if err != nil {
		t.Errorf("Failed to render license email template: %v", err)
	} else {

		// Verify the rendered HTML contains expected content
		if !strings.Contains(licenseHTML, "Jane Smith") {
			t.Error("License email doesn't contain client name")
		}
		if !strings.Contains(licenseHTML, "Acme Pro") {
			t.Error("License email doesn't contain product name")
		}
		if !strings.Contains(licenseHTML, "ABC123") {
			t.Error("License email doesn't contain license key")
		}
	}
}
