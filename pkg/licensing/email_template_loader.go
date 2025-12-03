package licensing

import (
	"bytes"
	"fmt"
	"html/template"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// EmailTemplateData holds data for rendering email templates
type EmailTemplateData struct {
	ClientName   string
	ClientLabel  string
	PlanName     string
	PlanLabel    string
	ProductName  string
	ProductLabel string
	Email        string
	LicenseJSON  string
	Year         string
	CompanyName  string
	SupportURL   string
	DocsURL      string
}

// EmailTemplateLoader loads and renders email templates
type EmailTemplateLoader struct {
	templates map[string]*template.Template
}

// NewEmailTemplateLoader creates a new template loader
func NewEmailTemplateLoader() *EmailTemplateLoader {
	return &EmailTemplateLoader{
		templates: make(map[string]*template.Template),
	}
}

// LoadTemplates loads email templates from the templates directory
func (etl *EmailTemplateLoader) LoadTemplates() error {
	// Get the directory of the current file
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		return fmt.Errorf("failed to get current file path")
	}

	// Navigate to the email_templates directory
	templatesDir := filepath.Join(filepath.Dir(currentFile), "email_templates")

	// Read all HTML files from the templates directory
	files, err := os.ReadDir(templatesDir)
	if err != nil {
		return fmt.Errorf("failed to read templates directory: %w", err)
	}

	// Load each template file
	for _, file := range files {
		if !file.IsDir() && strings.HasSuffix(file.Name(), ".html") {
			templateName := strings.TrimSuffix(file.Name(), ".html")
			templatePath := filepath.Join(templatesDir, file.Name())

			content, err := os.ReadFile(templatePath)
			if err != nil {
				return fmt.Errorf("failed to read template %s: %w", templateName, err)
			}

			tmpl, err := template.New(templateName).Funcs(etl.templateFuncs()).Parse(string(content))
			if err != nil {
				return fmt.Errorf("failed to parse template %s: %w", templateName, err)
			}

			etl.templates[templateName] = tmpl
		}
	}

	return nil
}

// RenderTemplate renders a template with the given data
func (etl *EmailTemplateLoader) RenderTemplate(templateName string, data EmailTemplateData) (string, error) {
	tmpl, ok := etl.templates[templateName]
	if !ok {
		return "", fmt.Errorf("template %s not found", templateName)
	}

	// Set default values
	if data.Year == "" {
		data.Year = time.Now().Format("2006")
	}
	if data.CompanyName == "" {
		data.CompanyName = "Licensing Inc."
	}
	if data.SupportURL == "" {
		data.SupportURL = "https://support.example.com"
	}
	if data.DocsURL == "" {
		data.DocsURL = "https://docs.example.com"
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template %s: %w", templateName, err)
	}

	return buf.String(), nil
}

// templateFuncs returns template functions for email templates
func (etl *EmailTemplateLoader) templateFuncs() template.FuncMap {
	return template.FuncMap{
		"upper":   strings.ToUpper,
		"lower":   strings.ToLower,
		"trim":    strings.TrimSpace,
		"replace": strings.ReplaceAll,
		"now":     time.Now,
		"formatTime": func(t time.Time, layout string) string {
			if layout == "" {
				layout = time.RFC3339
			}
			return t.Format(layout)
		},
	}
}
