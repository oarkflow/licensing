package licensing

import (
	"strings"
	"testing"
)

func TestEmailTemplateLoaderEmbedded(t *testing.T) {
	// Test with embedded filesystem
	loader := NewEmailTemplateLoader(TemplatesFS)
	err := loader.LoadTemplates()
	if err != nil {
		t.Fatalf("Failed to load embedded templates: %v", err)
	}

	// Test that we have the expected templates
	expectedTemplates := []string{"welcome_email", "license_email"}
	for _, templateName := range expectedTemplates {
		if _, exists := loader.templates[templateName]; !exists {
			t.Errorf("Expected embedded template %s not found", templateName)
		}
	}

	// Test rendering with embedded templates
	welcomeData := EmailTemplateData{
		ClientName:  "Test User",
		PlanName:    "Pro",
		ProductName: "Test Product",
		Email:       "test@example.com",
	}

	html, err := loader.RenderTemplate("welcome_email", welcomeData)
	if err != nil {
		t.Errorf("Failed to render embedded template: %v", err)
	}

	if !strings.Contains(html, "Test User") {
		t.Logf("Rendered html:\n%s", html)
		t.Error("Rendered embedded template doesn't contain expected content")
	}
}

func TestEmailTemplateLoaderFilesystemFallback(t *testing.T) {
	// Test without embedded filesystem (should fall back to filesystem)
	loader := NewEmailTemplateLoader()
	err := loader.LoadTemplates()
	if err != nil {
		t.Fatalf("Failed to load templates from filesystem: %v", err)
	}

	// Test that we have the expected templates
	expectedTemplates := []string{"welcome_email", "license_email"}
	for _, templateName := range expectedTemplates {
		if _, exists := loader.templates[templateName]; !exists {
			t.Errorf("Expected filesystem template %s not found", templateName)
		}
	}
}
