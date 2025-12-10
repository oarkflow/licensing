package licensing

import (
	"bytes"
	"embed"
	"fmt"
	"html/template"
	"io/fs"
	"os"
	"path/filepath"
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
	embedFS   embed.FS // optional embedded filesystem
}

// NewEmailTemplateLoader creates a new template loader
// Pass an optional embed.FS to load templates from compiled binary.
// If embedFS has content, it will be preferred over filesystem templates.
func NewEmailTemplateLoader(embedFS ...embed.FS) *EmailTemplateLoader {
	loader := &EmailTemplateLoader{
		templates: make(map[string]*template.Template),
	}
	if len(embedFS) > 0 {
		loader.embedFS = embedFS[0]
	}
	return loader
}

// LoadTemplates loads email templates from the templates directory
func (etl *EmailTemplateLoader) LoadTemplates() error {
	// First, try loading from embedded filesystem if available
	if etl.loadFromEmbedded() == nil {
		return nil // Successfully loaded from embed.FS
	}

	// Fallback to filesystem-based loading
	// Search upwards from the current working directory for a templates/email dir
	templatesDir := ""
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get working dir: %w", err)
	}

	// Walk up the directory tree looking for templates/email
	var candidates []string
	cur := cwd
	for i := 0; i < 8; i++ {
		cand := filepath.Join(cur, "templates", "email")
		if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
			candidates = append(candidates, cand)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			break
		}
		cur = parent
	}

	// 1) If an explicit directory is provided via env, prefer it. This is useful when running
	//    compiled binaries or in containerized environments where there's no repo metadata.
	if env := os.Getenv("EMAIL_TEMPLATES_DIR"); env != "" {
		if fi, err := os.Stat(env); err == nil && fi.IsDir() {
			templatesDir = env
		}
	}

	// 2) If we still don't have a templates dir, check next to the running executable. This
	//    supports compiled binaries that ship templates alongside the binary (e.g. /opt/app/templates/email).
	if templatesDir == "" {
		if exePath, err := os.Executable(); err == nil {
			exeDir := filepath.Dir(exePath)
			cand := filepath.Join(exeDir, "templates", "email")
			if fi, err := os.Stat(cand); err == nil && fi.IsDir() {
				templatesDir = cand
			}
		}
	}

	// If we still don't have a templatesDir but found candidates earlier, pick the highest-level candidate
	if templatesDir == "" && len(candidates) > 0 {
		templatesDir = candidates[len(candidates)-1]
	}

	// fallback to project-relative path if nothing found
	if templatesDir == "" {
		templatesDir = filepath.Join("templates", "email")
	}
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

// loadFromEmbedded loads templates from the embedded filesystem
func (etl *EmailTemplateLoader) loadFromEmbedded() error {
	// Check if embedFS is set and has content
	if etl.embedFS == (embed.FS{}) {
		return fmt.Errorf("no embedded filesystem available")
	}

	// Try to read from templates/email path in embed.FS
	entries, err := fs.ReadDir(etl.embedFS, "templates/email")
	if err != nil {
		return fmt.Errorf("failed to read embedded templates: %w", err)
	}

	// Load each template file
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".html") {
			templateName := strings.TrimSuffix(entry.Name(), ".html")
			templatePath := filepath.Join("templates/email", entry.Name())

			content, err := fs.ReadFile(etl.embedFS, templatePath)
			if err != nil {
				return fmt.Errorf("failed to read embedded template %s: %w", templateName, err)
			}

			tmpl, err := template.New(templateName).Funcs(etl.templateFuncs()).Parse(string(content))
			if err != nil {
				return fmt.Errorf("failed to parse embedded template %s: %w", templateName, err)
			}

			etl.templates[templateName] = tmpl
		}
	}

	if len(etl.templates) == 0 {
		return fmt.Errorf("no templates loaded from embedded filesystem")
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
