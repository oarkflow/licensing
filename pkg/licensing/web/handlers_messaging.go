package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	texttmpl "text/template"

	"github.com/google/uuid"
	email "github.com/oarkflow/licensing/pkg/email"
	"github.com/oarkflow/licensing/pkg/licensing"
)

var providerTypeOptions = []email.ProviderType{
	email.ProviderTypeSMTP,
	email.ProviderTypeSendGrid,
	email.ProviderTypeSES,
	email.ProviderTypeCustom,
}

var emailAddressRegex = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)

type providerFormView struct {
	Provider      *email.EmailProvider
	ConfigJSON    string
	MetadataJSON  string
	Mode          string
	TestEmail     string
	ProviderTypes []email.ProviderType
}

type templateFormView struct {
	Template        *email.EmailTemplate
	MetadataJSON    string
	Mode            string
	ProviderOptions []*email.EmailProvider
}

type composePreview struct {
	Recipient string
	Subject   string
	HTML      string
	Text      string
}

type composeView struct {
	Templates          []*email.EmailTemplate
	Clients            []*licensing.Client
	SelectedTemplateID string
	SelectedTemplate   *email.EmailTemplate
	SelectedClientIDs  []string
	AdditionalEmails   string
	VariablesJSON      string
	Preview            *composePreview
}

type composeRecipient struct {
	Email  string
	Client *licensing.Client
}

func (ws *WebServer) handleEmailProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		action := r.FormValue("action")
		providerID := strings.TrimSpace(r.FormValue("provider_id"))
		if providerID == "" {
			ws.renderError(w, http.StatusBadRequest, "provider_id is required")
			return
		}
		var err error
		switch action {
		case "toggle":
			err = ws.toggleEmailProvider(ctx, providerID)
		case "delete":
			err = ws.lm.Storage().DeleteEmailProvider(ctx, providerID)
		case "set_default":
			err = ws.setDefaultEmailProvider(ctx, providerID)
		default:
			err = fmt.Errorf("unknown action: %s", action)
		}
		if err != nil {
			ws.renderError(w, http.StatusBadRequest, err.Error())
			return
		}
		http.Redirect(w, r, "/messaging/providers", http.StatusSeeOther)
		return
	}

	providers, err := ws.lm.Storage().ListEmailProviders(ctx, true)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	data := map[string]any{
		"Providers": providers,
	}

	ws.render(w, "messaging_providers.html", TemplateData{
		Title:       "Email Providers",
		CurrentPath: "/messaging/providers",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleNewEmailProvider(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	view := providerFormView{
		Mode:          "create",
		ProviderTypes: providerTypeOptions,
		ConfigJSON:    defaultSMTPConfigTemplate(),
	}

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		action := r.FormValue("action")
		provider := &email.EmailProvider{
			ID:        uuid.NewString(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		if err := bindProviderForm(provider, r); err != nil {
			view.Provider = provider
			view.ConfigJSON = strings.TrimSpace(r.FormValue("config_json"))
			view.MetadataJSON = strings.TrimSpace(r.FormValue("metadata_json"))
			ws.render(w, "messaging_provider_form.html", TemplateData{
				Title:       "New Email Provider",
				CurrentPath: "/messaging/providers",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		view.Provider = provider
		view.ConfigJSON = stringifyJSON(provider.Config)
		view.MetadataJSON = stringifyStringMap(provider.Metadata)
		view.TestEmail = strings.TrimSpace(r.FormValue("test_email"))
		if action == "test" {
			if view.TestEmail == "" {
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       "New Email Provider",
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       "Test email is required",
				})
				return
			}
			if err := ws.testEmailProvider(ctx, provider, view.TestEmail); err != nil {
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       "New Email Provider",
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			ws.render(w, "messaging_provider_form.html", TemplateData{
				Title:       "New Email Provider",
				CurrentPath: "/messaging/providers",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Flash: &FlashMessage{
					Type:    "success",
					Message: fmt.Sprintf("Test email sent to %s", view.TestEmail),
				},
			})
			return
		}

		if err := ws.lm.Storage().SaveEmailProvider(ctx, provider); err != nil {
			ws.render(w, "messaging_provider_form.html", TemplateData{
				Title:       "New Email Provider",
				CurrentPath: "/messaging/providers",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		if provider.IsDefault {
			if err := ws.setDefaultEmailProvider(ctx, provider.ID); err != nil {
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       "New Email Provider",
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
		}
		http.Redirect(w, r, "/messaging/providers", http.StatusSeeOther)
		return
	}

	ws.render(w, "messaging_provider_form.html", TemplateData{
		Title:       "New Email Provider",
		CurrentPath: "/messaging/providers",
		User:        ws.getSessionFromContext(r),
		Data:        view,
	})
}

func (ws *WebServer) handleEmailProviderDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/messaging/providers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	providerID := parts[0]
	provider, err := ws.lm.Storage().GetEmailProvider(ctx, providerID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Email provider not found")
		return
	}
	view := providerFormView{
		Provider:      provider,
		Mode:          "edit",
		ProviderTypes: providerTypeOptions,
		ConfigJSON:    stringifyJSON(provider.Config),
		MetadataJSON:  stringifyStringMap(provider.Metadata),
	}

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		action := r.FormValue("action")
		view.TestEmail = strings.TrimSpace(r.FormValue("test_email"))
		switch action {
		case "delete":
			if err := ws.lm.Storage().DeleteEmailProvider(ctx, providerID); err != nil {
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       provider.Name,
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			http.Redirect(w, r, "/messaging/providers", http.StatusSeeOther)
			return
		case "test":
			if err := bindProviderForm(provider, r); err != nil {
				view.Provider = provider
				view.ConfigJSON = strings.TrimSpace(r.FormValue("config_json"))
				view.MetadataJSON = strings.TrimSpace(r.FormValue("metadata_json"))
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       provider.Name,
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			if view.TestEmail == "" {
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       provider.Name,
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       "Test email is required",
				})
				return
			}
			if err := ws.testEmailProvider(ctx, provider, view.TestEmail); err != nil {
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       provider.Name,
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			ws.render(w, "messaging_provider_form.html", TemplateData{
				Title:       provider.Name,
				CurrentPath: "/messaging/providers",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Flash: &FlashMessage{
					Type:    "success",
					Message: fmt.Sprintf("Test email sent to %s", view.TestEmail),
				},
			})
			return
		default:
			if err := bindProviderForm(provider, r); err != nil {
				view.Provider = provider
				view.ConfigJSON = strings.TrimSpace(r.FormValue("config_json"))
				view.MetadataJSON = strings.TrimSpace(r.FormValue("metadata_json"))
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       provider.Name,
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			if err := ws.lm.Storage().UpdateEmailProvider(ctx, provider); err != nil {
				ws.render(w, "messaging_provider_form.html", TemplateData{
					Title:       provider.Name,
					CurrentPath: "/messaging/providers",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			if provider.IsDefault {
				if err := ws.setDefaultEmailProvider(ctx, provider.ID); err != nil {
					ws.render(w, "messaging_provider_form.html", TemplateData{
						Title:       provider.Name,
						CurrentPath: "/messaging/providers",
						User:        ws.getSessionFromContext(r),
						Data:        view,
						Error:       err.Error(),
					})
					return
				}
			}
			http.Redirect(w, r, "/messaging/providers", http.StatusSeeOther)
			return
		}
	}

	ws.render(w, "messaging_provider_form.html", TemplateData{
		Title:       provider.Name,
		CurrentPath: "/messaging/providers",
		User:        ws.getSessionFromContext(r),
		Data:        view,
	})
}

func (ws *WebServer) handleEmailTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		action := r.FormValue("action")
		templateID := strings.TrimSpace(r.FormValue("template_id"))
		if templateID == "" {
			ws.renderError(w, http.StatusBadRequest, "template_id is required")
			return
		}
		if action == "delete" {
			if err := ws.lm.Storage().DeleteEmailTemplate(ctx, templateID); err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
			http.Redirect(w, r, "/messaging/templates", http.StatusSeeOther)
			return
		}
		ws.renderError(w, http.StatusBadRequest, "unknown action")
		return
	}

	templates, err := ws.lm.Storage().ListEmailTemplates(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	providers, _ := ws.lm.Storage().ListEmailProviders(ctx, true)
	providerMap := make(map[string]*email.EmailProvider)
	for _, provider := range providers {
		providerMap[provider.ID] = provider
	}

	data := map[string]any{
		"Templates":   templates,
		"Providers":   providerMap,
		"HasProvider": len(providers) > 0,
	}

	ws.render(w, "messaging_templates.html", TemplateData{
		Title:       "Email Templates",
		CurrentPath: "/messaging/templates",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleNewEmailTemplate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	providers, _ := ws.lm.Storage().ListEmailProviders(ctx, true)
	view := templateFormView{
		Mode:            "create",
		ProviderOptions: providers,
		Template: &email.EmailTemplate{
			Category: "general",
		},
		MetadataJSON: "",
	}

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		tpl := &email.EmailTemplate{
			ID:        uuid.NewString(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}
		metadataJSON, err := bindTemplateForm(tpl, r)
		view.Template = tpl
		view.MetadataJSON = metadataJSON
		if err != nil {
			ws.render(w, "messaging_template_form.html", TemplateData{
				Title:       "New Email Template",
				CurrentPath: "/messaging/templates",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		if err := ws.lm.Storage().SaveEmailTemplate(ctx, tpl); err != nil {
			ws.render(w, "messaging_template_form.html", TemplateData{
				Title:       "New Email Template",
				CurrentPath: "/messaging/templates",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		http.Redirect(w, r, "/messaging/templates", http.StatusSeeOther)
		return
	}

	ws.render(w, "messaging_template_form.html", TemplateData{
		Title:       "New Email Template",
		CurrentPath: "/messaging/templates",
		User:        ws.getSessionFromContext(r),
		Data:        view,
	})
}

func (ws *WebServer) handleEmailTemplateDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/messaging/templates/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	templateID := parts[0]
	tpl, err := ws.lm.Storage().GetEmailTemplate(ctx, templateID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Email template not found")
		return
	}
	providers, _ := ws.lm.Storage().ListEmailProviders(ctx, true)
	view := templateFormView{
		Template:        tpl,
		Mode:            "edit",
		ProviderOptions: providers,
		MetadataJSON:    stringifyJSON(tpl.Metadata),
	}

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		action := r.FormValue("action")
		if action == "delete" {
			if err := ws.lm.Storage().DeleteEmailTemplate(ctx, templateID); err != nil {
				ws.render(w, "messaging_template_form.html", TemplateData{
					Title:       tpl.Name,
					CurrentPath: "/messaging/templates",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			http.Redirect(w, r, "/messaging/templates", http.StatusSeeOther)
			return
		}
		metadataJSON, err := bindTemplateForm(tpl, r)
		view.MetadataJSON = metadataJSON
		if err != nil {
			ws.render(w, "messaging_template_form.html", TemplateData{
				Title:       tpl.Name,
				CurrentPath: "/messaging/templates",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		if err := ws.lm.Storage().UpdateEmailTemplate(ctx, tpl); err != nil {
			ws.render(w, "messaging_template_form.html", TemplateData{
				Title:       tpl.Name,
				CurrentPath: "/messaging/templates",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		http.Redirect(w, r, "/messaging/templates", http.StatusSeeOther)
		return
	}

	ws.render(w, "messaging_template_form.html", TemplateData{
		Title:       tpl.Name,
		CurrentPath: "/messaging/templates",
		User:        ws.getSessionFromContext(r),
		Data:        view,
	})
}

func (ws *WebServer) handleEmailCompose(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	templates, err := ws.lm.Storage().ListEmailTemplates(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	clients, err := ws.lm.ListClients(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}
	sort.Slice(clients, func(i, j int) bool {
		nameI := strings.TrimSpace(clients[i].Name)
		nameJ := strings.TrimSpace(clients[j].Name)
		if nameI == "" {
			nameI = clients[i].Email
		}
		if nameJ == "" {
			nameJ = clients[j].Email
		}
		if strings.EqualFold(nameI, nameJ) {
			return clients[i].Email < clients[j].Email
		}
		return strings.ToLower(nameI) < strings.ToLower(nameJ)
	})
	view := composeView{
		Templates: templates,
		Clients:   clients,
	}
	if tplID := strings.TrimSpace(r.URL.Query().Get("template_id")); tplID != "" {
		view.SelectedTemplateID = tplID
	}

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}
		action := r.FormValue("action")
		view.SelectedTemplateID = strings.TrimSpace(r.FormValue("template_id"))
		view.SelectedClientIDs = r.Form["client_ids"]
		view.AdditionalEmails = strings.TrimSpace(r.FormValue("additional_emails"))
		view.VariablesJSON = strings.TrimSpace(r.FormValue("variables_json"))
		if view.SelectedTemplateID == "" {
			ws.render(w, "messaging_compose.html", TemplateData{
				Title:       "Compose Email",
				CurrentPath: "/messaging/compose",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       "Please select a template",
			})
			return
		}
		tpl, err := ws.lm.Storage().GetEmailTemplate(ctx, view.SelectedTemplateID)
		if err != nil {
			ws.render(w, "messaging_compose.html", TemplateData{
				Title:       "Compose Email",
				CurrentPath: "/messaging/compose",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       "Template not found",
			})
			return
		}
		view.SelectedTemplate = tpl
		vars, err := parseGenericMap(view.VariablesJSON)
		if err != nil {
			ws.render(w, "messaging_compose.html", TemplateData{
				Title:       "Compose Email",
				CurrentPath: "/messaging/compose",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		recipients, err := buildComposeRecipients(view.SelectedClientIDs, clients, view.AdditionalEmails)
		if err != nil {
			ws.render(w, "messaging_compose.html", TemplateData{
				Title:       "Compose Email",
				CurrentPath: "/messaging/compose",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       err.Error(),
			})
			return
		}
		if len(recipients) == 0 {
			ws.render(w, "messaging_compose.html", TemplateData{
				Title:       "Compose Email",
				CurrentPath: "/messaging/compose",
				User:        ws.getSessionFromContext(r),
				Data:        view,
				Error:       "Select at least one recipient",
			})
			return
		}
		if action == "preview" {
			previewRecipient := recipients[0]
			subject, htmlBody, textBody, err := renderEmailTemplate(tpl, previewRecipient.Client, previewRecipient.Email, vars)
			if err != nil {
				ws.render(w, "messaging_compose.html", TemplateData{
					Title:       "Compose Email",
					CurrentPath: "/messaging/compose",
					User:        ws.getSessionFromContext(r),
					Data:        view,
					Error:       err.Error(),
				})
				return
			}
			view.Preview = &composePreview{
				Recipient: previewRecipient.Email,
				Subject:   subject,
				HTML:      htmlBody,
				Text:      textBody,
			}
			ws.render(w, "messaging_compose.html", TemplateData{
				Title:       "Compose Email",
				CurrentPath: "/messaging/compose",
				User:        ws.getSessionFromContext(r),
				Data:        view,
			})
			return
		}
		if action == "send" {
			queued := 0
			for _, recipient := range recipients {
				if err := ws.queueTemplateEmail(ctx, tpl, recipient.Client, recipient.Email, vars); err != nil {
					ws.render(w, "messaging_compose.html", TemplateData{
						Title:       "Compose Email",
						CurrentPath: "/messaging/compose",
						User:        ws.getSessionFromContext(r),
						Data:        view,
						Error:       err.Error(),
					})
					return
				}
				queued++
			}
			ws.render(w, "messaging_compose.html", TemplateData{
				Title:       "Compose Email",
				CurrentPath: "/messaging/compose",
				User:        ws.getSessionFromContext(r),
				Data: composeView{
					Templates: templates,
					Clients:   clients,
				},
				Flash: &FlashMessage{
					Type:    "success",
					Message: fmt.Sprintf("Queued %d email(s) for delivery", queued),
				},
			})
			return
		}
		ws.render(w, "messaging_compose.html", TemplateData{
			Title:       "Compose Email",
			CurrentPath: "/messaging/compose",
			User:        ws.getSessionFromContext(r),
			Data:        view,
			Error:       "Unknown action",
		})
		return
	}

	ws.render(w, "messaging_compose.html", TemplateData{
		Title:       "Compose Email",
		CurrentPath: "/messaging/compose",
		User:        ws.getSessionFromContext(r),
		Data:        view,
	})
}

func bindProviderForm(provider *email.EmailProvider, r *http.Request) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}
	provider.Name = strings.TrimSpace(r.FormValue("name"))
	provider.Slug = strings.TrimSpace(r.FormValue("slug"))
	provider.Type = email.ProviderType(strings.TrimSpace(strings.ToLower(r.FormValue("type"))))
	if !isSupportedProviderType(provider.Type) {
		return fmt.Errorf("unsupported provider type: %s", provider.Type)
	}
	provider.Priority = parseInt(r.FormValue("priority"), 100)
	provider.MaxRetries = parseInt(r.FormValue("max_retries"), 3)
	provider.RetryBaseMS = parseInt(r.FormValue("retry_base_ms"), 1000)
	provider.RetryMaxMS = parseInt(r.FormValue("retry_max_ms"), 60000)
	provider.RetryJitterPct = parseFloat(r.FormValue("retry_jitter_pct"), 0.25)
	provider.IsDefault = r.FormValue("is_default") == "on"
	provider.Enabled = r.FormValue("enabled") == "on"

	configJSON := strings.TrimSpace(r.FormValue("config_json"))
	if configJSON == "" {
		configJSON = "{}"
	}
	var config map[string]any
	if err := json.Unmarshal([]byte(configJSON), &config); err != nil {
		return fmt.Errorf("invalid config JSON: %w", err)
	}
	provider.Config = config

	metadataJSON := strings.TrimSpace(r.FormValue("metadata_json"))
	if metadataJSON != "" {
		meta, err := parseStringMap(metadataJSON)
		if err != nil {
			return err
		}
		provider.Metadata = meta
	} else {
		provider.Metadata = nil
	}

	if provider.Name == "" || provider.Slug == "" || provider.Type == "" {
		return fmt.Errorf("name, slug, and type are required")
	}
	return nil
}

func isSupportedProviderType(t email.ProviderType) bool {
	for _, allowed := range providerTypeOptions {
		if allowed == t {
			return true
		}
	}
	return false
}

func parseStringMap(raw string) (map[string]string, error) {
	var m map[string]string
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("invalid metadata JSON: %w", err)
	}
	return m, nil
}

func stringifyJSON(m map[string]any) string {
	if len(m) == 0 {
		return "{}"
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(b)
}

func stringifyStringMap(m map[string]string) string {
	if len(m) == 0 {
		return ""
	}
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return ""
	}
	return string(b)
}

func (ws *WebServer) toggleEmailProvider(ctx context.Context, providerID string) error {
	provider, err := ws.lm.Storage().GetEmailProvider(ctx, providerID)
	if err != nil {
		return err
	}
	provider.Enabled = !provider.Enabled
	return ws.lm.Storage().UpdateEmailProvider(ctx, provider)
}

func (ws *WebServer) setDefaultEmailProvider(ctx context.Context, providerID string) error {
	providers, err := ws.lm.Storage().ListEmailProviders(ctx, true)
	if err != nil {
		return err
	}
	if len(providers) == 0 {
		return fmt.Errorf("no email providers configured")
	}
	var found bool
	for _, provider := range providers {
		shouldBeDefault := provider.ID == providerID
		if provider.IsDefault == shouldBeDefault {
			if shouldBeDefault {
				found = true
			}
			continue
		}
		provider.IsDefault = shouldBeDefault
		if err := ws.lm.Storage().UpdateEmailProvider(ctx, provider); err != nil {
			return err
		}
		if shouldBeDefault {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("email provider not found")
	}
	return nil
}

func (ws *WebServer) testEmailProvider(ctx context.Context, provider *email.EmailProvider, testEmail string) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}
	switch provider.Type {
	case email.ProviderTypeSMTP:
		return testSMTPProvider(ctx, provider, testEmail)
	default:
		return fmt.Errorf("test not implemented for provider type %s", provider.Type)
	}
}

func testSMTPProvider(ctx context.Context, provider *email.EmailProvider, testEmail string) error {
	config := provider.Config
	host := getString(config, "host")
	port := getInt(config, "port", 587)
	username := getString(config, "username")
	password := getString(config, "password")
	fromEmail := getString(config, "from_email")
	useTLS := getBool(config, "use_tls")
	startTLS := getBool(config, "start_tls")
	skipVerify := getBool(config, "skip_tls_verify")
	timeout := time.Duration(getInt(config, "timeout_seconds", 10)) * time.Second
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	if host == "" {
		return fmt.Errorf("smtp host is required in config")
	}
	if fromEmail == "" {
		return fmt.Errorf("from_email is required in config for test sends")
	}
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}
	var conn net.Conn
	var err error
	if useTLS {
		tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("smtp dial failed: %w", err)
	}
	defer conn.Close()
	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp client init failed: %w", err)
	}
	defer client.Close()
	if !useTLS && startTLS {
		if ok, _ := client.Extension("STARTTLS"); !ok {
			log.Printf("Warning: SMTP server does not advertise STARTTLS support, continuing without TLS")
			// Don't fail the test for missing STARTTLS support
		} else {
			tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}
			if err := client.StartTLS(tlsCfg); err != nil {
				log.Printf("Warning: SMTP STARTTLS failed (but test may still succeed): %v", err)
				// Don't fail the test for STARTTLS failures
			}
		}
	}
	if username != "" {
		auth := smtp.PlainAuth("", username, password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}
	if err := client.Mail(fromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(testEmail); err != nil {
		return fmt.Errorf("smtp RCPT TO failed: %w", err)
	}
	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA failed: %w", err)
	}
	defer wc.Close()
	body := fmt.Sprintf("To: %s\r\nSubject: %s\r\n\r\nProvider %s (%s) test successful at %s.\r\n", testEmail, "Licensing Provider Test", provider.Name, provider.Slug, time.Now().Format(time.RFC3339))
	if _, err := io.WriteString(wc, body); err != nil {
		return fmt.Errorf("smtp write failed: %w", err)
	}
	// Try to quit gracefully, but don't fail the test if quit fails
	// Some SMTP servers may not support QUIT or may have already closed the connection
	if err := client.Quit(); err != nil {
		log.Printf("Warning: SMTP quit failed (but test succeeded): %v", err)
		// Don't return error for quit failures
	}
	return nil
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key]
	if !ok || val == nil {
		return ""
	}
	switch typed := val.(type) {
	case string:
		return strings.TrimSpace(typed)
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	case json.Number:
		return typed.String()
	default:
		return fmt.Sprintf("%v", typed)
	}
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	val, ok := m[key]
	if !ok {
		return false
	}
	switch v := val.(type) {
	case bool:
		return v
	case string:
		lower := strings.ToLower(strings.TrimSpace(v))
		return lower == "true" || lower == "1" || lower == "yes"
	case float64:
		return v != 0
	case json.Number:
		n, _ := v.Float64()
		return n != 0
	default:
		return false
	}
}

func getInt(m map[string]any, key string, fallback int) int {
	if m == nil {
		return fallback
	}
	val, ok := m[key]
	if !ok || val == nil {
		return fallback
	}
	switch v := val.(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	case json.Number:
		if n, err := v.Int64(); err == nil {
			return int(n)
		}
	case string:
		if parsed, err := strconv.Atoi(strings.TrimSpace(v)); err == nil {
			return parsed
		}
	}
	return fallback
}

func parseFloat(raw string, fallback float64) float64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	val, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return fallback
	}
	return val
}

func defaultSMTPConfigTemplate() string {
	config := map[string]any{
		"host":            "smtp.example.com",
		"port":            587,
		"username":        "api@example.com",
		"password":        "change-me",
		"from_email":      "noreply@example.com",
		"use_tls":         false,
		"start_tls":       true,
		"skip_tls_verify": false,
		"timeout_seconds": 10,
	}
	return stringifyJSON(config)
}

func bindTemplateForm(tpl *email.EmailTemplate, r *http.Request) (string, error) {
	if tpl == nil {
		return "", fmt.Errorf("template is nil")
	}
	tpl.Name = strings.TrimSpace(r.FormValue("name"))
	tpl.Slug = strings.TrimSpace(r.FormValue("slug"))
	tpl.Category = strings.TrimSpace(r.FormValue("category"))
	if tpl.Category == "" {
		tpl.Category = "general"
	}
	tpl.Subject = strings.TrimSpace(r.FormValue("subject"))
	tpl.HTMLBody = strings.TrimSpace(r.FormValue("html_body"))
	tpl.TextBody = strings.TrimSpace(r.FormValue("text_body"))
	tpl.Description = strings.TrimSpace(r.FormValue("description"))
	tpl.DefaultProviderID = strings.TrimSpace(r.FormValue("default_provider_id"))
	maxRetriesStr := strings.TrimSpace(r.FormValue("max_retries_override"))
	if maxRetriesStr != "" {
		value := parseInt(maxRetriesStr, -1)
		if value <= 0 {
			return maxRetriesStr, fmt.Errorf("max retries override must be greater than zero")
		}
		tpl.MaxRetriesOverride = &value
	} else {
		tpl.MaxRetriesOverride = nil
	}
	metadataJSON := strings.TrimSpace(r.FormValue("metadata_json"))
	if metadataJSON != "" {
		meta, err := parseGenericMap(metadataJSON)
		if err != nil {
			return metadataJSON, err
		}
		tpl.Metadata = meta
	} else {
		tpl.Metadata = nil
	}
	if tpl.Name == "" || tpl.Slug == "" || tpl.Category == "" || tpl.Subject == "" {
		return metadataJSON, fmt.Errorf("name, slug, category, and subject are required")
	}
	return metadataJSON, nil
}

func parseGenericMap(raw string) (map[string]any, error) {
	if strings.TrimSpace(raw) == "" {
		return nil, nil
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return m, nil
}

func renderEmailTemplate(tpl *email.EmailTemplate, client *licensing.Client, recipient string, vars map[string]any) (string, string, string, error) {
	ctx := map[string]any{
		"Client": client,
		"Vars":   vars,
		"Email":  recipient,
		"Now":    time.Now(),
	}
	subject, err := renderTextBlock("subject", tpl.Subject, ctx)
	if err != nil {
		return "", "", "", err
	}
	htmlBody, err := renderTextBlock("html", tpl.HTMLBody, ctx)
	if err != nil {
		return "", "", "", err
	}
	textBody, err := renderTextBlock("text", tpl.TextBody, ctx)
	if err != nil {
		return "", "", "", err
	}
	return subject, htmlBody, textBody, nil
}

func renderTextBlock(name, content string, ctx any) (string, error) {
	if strings.TrimSpace(content) == "" {
		return "", nil
	}
	tmpl, err := texttmpl.New(name).Funcs(messagingTemplateFuncs).Parse(content)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

var messagingTemplateFuncs = texttmpl.FuncMap{
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

func (ws *WebServer) queueTemplateEmail(ctx context.Context, tpl *email.EmailTemplate, client *licensing.Client, emailAddr string, vars map[string]any) error {
	provider, err := ws.resolveProviderForTemplate(ctx, tpl)
	if err != nil {
		return err
	}
	subject, htmlBody, textBody, err := renderEmailTemplate(tpl, client, emailAddr, vars)
	if err != nil {
		return err
	}
	now := time.Now()
	metadata := map[string]string{
		"template_slug":     tpl.Slug,
		"template_category": tpl.Category,
	}
	if client != nil {
		metadata["client_id"] = client.ID
	}
	msg := &email.EmailMessage{
		ID:            uuid.NewString(),
		TemplateID:    tpl.ID,
		ProviderID:    provider.ID,
		To:            emailAddr,
		Subject:       subject,
		RenderedHTML:  htmlBody,
		RenderedText:  textBody,
		Variables:     cloneAnyMap(vars),
		Metadata:      metadata,
		Status:        email.MessageStatusQueued,
		MaxRetries:    provider.MaxRetries,
		NextAttemptAt: now,
		CreatedAt:     now,
		UpdatedAt:     now,
	}
	if msg.MaxRetries <= 0 {
		msg.MaxRetries = 3
	}
	if tpl.MaxRetriesOverride != nil && *tpl.MaxRetriesOverride > 0 {
		msg.MaxRetries = *tpl.MaxRetriesOverride
	}
	return ws.lm.Storage().EnqueueEmail(ctx, msg)
}

func (ws *WebServer) resolveProviderForTemplate(ctx context.Context, tpl *email.EmailTemplate) (*email.EmailProvider, error) {
	if tpl.DefaultProviderID != "" {
		provider, err := ws.lm.Storage().GetEmailProvider(ctx, tpl.DefaultProviderID)
		if err == nil && provider != nil && provider.Enabled {
			return provider, nil
		}
	}
	providers, err := ws.lm.Storage().ListEmailProviders(ctx, false)
	if err != nil {
		return nil, err
	}
	for _, provider := range providers {
		if provider.IsDefault {
			return provider, nil
		}
	}
	if len(providers) > 0 {
		return providers[0], nil
	}
	return nil, fmt.Errorf("no enabled email providers available")
}

func buildComposeRecipients(clientIDs []string, clients []*licensing.Client, additional string) ([]composeRecipient, error) {
	clientIndex := make(map[string]*licensing.Client)
	for _, client := range clients {
		clientIndex[client.ID] = client
	}
	seen := make(map[string]struct{})
	recipients := make([]composeRecipient, 0)
	for _, id := range clientIDs {
		id = strings.TrimSpace(id)
		if id == "" {
			continue
		}
		client := clientIndex[id]
		if client == nil || strings.TrimSpace(client.Email) == "" {
			continue
		}
		emailKey := strings.ToLower(strings.TrimSpace(client.Email))
		if _, exists := seen[emailKey]; exists {
			continue
		}
		recipients = append(recipients, composeRecipient{Email: client.Email, Client: client})
		seen[emailKey] = struct{}{}
	}
	for _, extra := range splitRecipientInput(additional) {
		emailAddr := strings.TrimSpace(extra)
		if emailAddr == "" {
			continue
		}
		if !emailAddressRegex.MatchString(emailAddr) {
			return nil, fmt.Errorf("invalid email address: %s", emailAddr)
		}
		emailKey := strings.ToLower(emailAddr)
		if _, exists := seen[emailKey]; exists {
			continue
		}
		recipients = append(recipients, composeRecipient{Email: emailAddr})
		seen[emailKey] = struct{}{}
	}
	return recipients, nil
}

func splitRecipientInput(raw string) []string {
	replacer := strings.NewReplacer(";", ",", "\n", ",", "\r", ",")
	clean := replacer.Replace(raw)
	parts := strings.Split(clean, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

func cloneAnyMap(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	clone := make(map[string]any, len(src))
	for k, v := range src {
		clone[k] = v
	}
	return clone
}

// API Handlers for React frontend
func (ws *WebServer) handleAPIEmailProviders(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List providers
		includeDisabled := r.URL.Query().Get("include_disabled") == "1"
		providers, err := ws.lm.Storage().ListEmailProviders(ctx, includeDisabled)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, providers)

	case http.MethodPost:
		// Create new provider
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		provider := &email.EmailProvider{
			ID:        uuid.NewString(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if err := bindProviderFormFromMap(provider, req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := ws.lm.Storage().SaveEmailProvider(ctx, provider); err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}

		ws.respondJSON(w, http.StatusCreated, provider)

	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIEmailProviderDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/email/providers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		ws.respondAPIError(w, http.StatusNotFound, "Provider ID required")
		return
	}
	providerID := parts[0]

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get the provider first
	provider, err := ws.lm.Storage().GetEmailProvider(ctx, providerID)
	if err != nil {
		ws.respondAPIError(w, http.StatusNotFound, "Provider not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get provider details
		ws.respondJSON(w, http.StatusOK, provider)

	case http.MethodPut:
		// Update provider
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if err := bindProviderFormFromMap(provider, req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		provider.UpdatedAt = time.Now()

		if err := ws.lm.Storage().UpdateEmailProvider(ctx, provider); err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}

		ws.respondJSON(w, http.StatusOK, provider)

	case http.MethodDelete:
		// Delete provider
		if err := ws.lm.Storage().DeleteEmailProvider(ctx, providerID); err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, map[string]string{"message": "Provider deleted"})

	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIEmailProviderTest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Provider  map[string]any `json:"provider"`
		TestEmail string         `json:"test_email"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.TestEmail == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "Test email is required")
		return
	}

	// Convert the provider map to an EmailProvider struct
	provider := &email.EmailProvider{
		ID:        uuid.NewString(),
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	}

	// Bind the provider data from the request
	if err := bindProviderFormFromMap(provider, req.Provider); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Test the provider
	if err := ws.testEmailProvider(ctx, provider, req.TestEmail); err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ws.respondJSON(w, http.StatusOK, map[string]any{
		"success": true,
		"message": fmt.Sprintf("Test email sent to %s", req.TestEmail),
	})
}

func (ws *WebServer) handleAPIEmailProviderDefault(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/email/providers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || parts[1] != "default" {
		ws.respondAPIError(w, http.StatusNotFound, "Invalid endpoint")
		return
	}
	providerID := parts[0]

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if err := ws.setDefaultEmailProvider(ctx, providerID); err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Return the updated provider
	provider, err := ws.lm.Storage().GetEmailProvider(ctx, providerID)
	if err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ws.respondJSON(w, http.StatusOK, provider)
}

func (ws *WebServer) handleAPIEmailProviderToggle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/email/providers/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) < 2 || parts[1] != "toggle" {
		ws.respondAPIError(w, http.StatusNotFound, "Invalid endpoint")
		return
	}
	providerID := parts[0]

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		Enabled bool `json:"enabled"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	provider, err := ws.lm.Storage().GetEmailProvider(ctx, providerID)
	if err != nil {
		ws.respondAPIError(w, http.StatusNotFound, "Provider not found")
		return
	}

	provider.Enabled = req.Enabled
	provider.UpdatedAt = time.Now()

	if err := ws.lm.Storage().UpdateEmailProvider(ctx, provider); err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ws.respondJSON(w, http.StatusOK, provider)
}

func (ws *WebServer) handleAPIEmailTemplates(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case http.MethodGet:
		// List templates
		templates, err := ws.lm.Storage().ListEmailTemplates(ctx)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, templates)

	case http.MethodPost:
		// Create new template
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		template := &email.EmailTemplate{
			ID:        uuid.NewString(),
			CreatedAt: time.Now(),
			UpdatedAt: time.Now(),
		}

		if err := bindTemplateFormFromMap(template, req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := ws.lm.Storage().SaveEmailTemplate(ctx, template); err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}

		ws.respondJSON(w, http.StatusCreated, template)

	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIEmailTemplateDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/email/templates/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		ws.respondAPIError(w, http.StatusNotFound, "Template ID required")
		return
	}
	templateID := parts[0]

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Get the template first
	template, err := ws.lm.Storage().GetEmailTemplate(ctx, templateID)
	if err != nil {
		ws.respondAPIError(w, http.StatusNotFound, "Template not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		// Get template details
		ws.respondJSON(w, http.StatusOK, template)

	case http.MethodPut:
		// Update template
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}

		if err := bindTemplateFormFromMap(template, req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}

		template.UpdatedAt = time.Now()

		if err := ws.lm.Storage().UpdateEmailTemplate(ctx, template); err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}

		ws.respondJSON(w, http.StatusOK, template)

	case http.MethodDelete:
		// Delete template
		if err := ws.lm.Storage().DeleteEmailTemplate(ctx, templateID); err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, map[string]string{"message": "Template deleted"})

	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func bindProviderFormFromMap(provider *email.EmailProvider, data map[string]any) error {
	if provider == nil {
		return fmt.Errorf("provider is nil")
	}

	provider.Name = getString(data, "name")
	provider.Slug = getString(data, "slug")
	provider.Type = email.ProviderType(strings.TrimSpace(strings.ToLower(getString(data, "type"))))
	if !isSupportedProviderType(provider.Type) {
		return fmt.Errorf("unsupported provider type: %s", provider.Type)
	}
	provider.Priority = getInt(data, "priority", 100)
	provider.MaxRetries = getInt(data, "max_retries", 3)
	provider.RetryBaseMS = getInt(data, "retry_base_ms", 1000)
	provider.RetryMaxMS = getInt(data, "retry_max_ms", 60000)
	provider.RetryJitterPct = parseFloat(getString(data, "retry_jitter_pct"), 0.25)
	provider.IsDefault = getBool(data, "is_default")
	provider.Enabled = getBool(data, "enabled")

	// Handle config
	configData := getAnyMap(data, "config")
	if configData == nil {
		configData = make(map[string]any)
	}
	provider.Config = configData

	// Handle metadata
	metadataData := getAnyMap(data, "metadata")
	if metadataData != nil {
		meta := make(map[string]string)
		for k, v := range metadataData {
			meta[k] = fmt.Sprintf("%v", v)
		}
		provider.Metadata = meta
	} else {
		provider.Metadata = nil
	}

	if provider.Name == "" || provider.Slug == "" || provider.Type == "" {
		return fmt.Errorf("name, slug, and type are required")
	}
	return nil
}

func bindTemplateFormFromMap(template *email.EmailTemplate, data map[string]any) error {
	if template == nil {
		return fmt.Errorf("template is nil")
	}

	template.Name = getString(data, "name")
	template.Slug = getString(data, "slug")
	template.Category = getString(data, "category")
	if template.Category == "" {
		template.Category = "general"
	}
	template.Subject = getString(data, "subject")
	template.HTMLBody = getString(data, "html_body")
	template.TextBody = getString(data, "text_body")
	template.Description = getString(data, "description")
	template.DefaultProviderID = getString(data, "default_provider_id")

	// Handle max_retries_override
	maxRetriesStr := getString(data, "max_retries_override")
	if maxRetriesStr != "" {
		value := parseInt(maxRetriesStr, -1)
		if value <= 0 {
			return fmt.Errorf("max retries override must be greater than zero")
		}
		template.MaxRetriesOverride = &value
	} else {
		template.MaxRetriesOverride = nil
	}

	// Handle metadata
	metadataData := getAnyMap(data, "metadata")
	if metadataData != nil {
		template.Metadata = metadataData
	} else {
		template.Metadata = nil
	}

	if template.Name == "" || template.Slug == "" || template.Category == "" || template.Subject == "" {
		return fmt.Errorf("name, slug, category, and subject are required")
	}
	return nil
}

func getAnyMap(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	val, ok := m[key]
	if !ok || val == nil {
		return nil
	}
	switch typed := val.(type) {
	case map[string]any:
		return typed
	default:
		return nil
	}
}

// sendEmailImmediately sends an email directly without queueing
func sendEmailImmediately(ctx context.Context, provider *email.EmailProvider, toEmail, subject, htmlBody, textBody string, attachments []*email.EmailAttachment) error {
	config := provider.Config
	host := getString(config, "host")
	port := getInt(config, "port", 587)
	username := getString(config, "username")
	password := getString(config, "password")
	fromEmail := getString(config, "from_email")
	useTLS := getBool(config, "use_tls")
	startTLS := getBool(config, "start_tls")
	skipVerify := getBool(config, "skip_tls_verify")
	timeout := time.Duration(getInt(config, "timeout_seconds", 10)) * time.Second

	if timeout <= 0 {
		timeout = 10 * time.Second
	}

	if host == "" {
		return fmt.Errorf("smtp host is required in config")
	}

	if fromEmail == "" {
		return fmt.Errorf("from_email is required in config")
	}

	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	var err error
	if useTLS {
		tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}

	if err != nil {
		return fmt.Errorf("smtp dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return fmt.Errorf("smtp client init failed: %w", err)
	}
	defer client.Close()

	if !useTLS && startTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}
			if err := client.StartTLS(tlsCfg); err != nil {
				log.Printf("Warning: SMTP STARTTLS failed: %v", err)
				// Continue without TLS if STARTTLS fails
			}
		}
	}

	if username != "" {
		auth := smtp.PlainAuth("", username, password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("smtp auth failed: %w", err)
		}
	}

	if err := client.Mail(fromEmail); err != nil {
		return fmt.Errorf("smtp MAIL FROM failed: %w", err)
	}

	if err := client.Rcpt(toEmail); err != nil {
		return fmt.Errorf("smtp RCPT TO failed: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return fmt.Errorf("smtp DATA failed: %w", err)
	}
	defer wc.Close()

	// Build email message with MIME support for attachments
	boundary := fmt.Sprintf("----=_Part_%s", uuid.NewString())

	var emailMessage strings.Builder
	emailMessage.WriteString(fmt.Sprintf("From: %s\r\n", fromEmail))
	emailMessage.WriteString(fmt.Sprintf("To: %s\r\n", toEmail))
	emailMessage.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	emailMessage.WriteString("MIME-Version: 1.0\r\n")

	if len(attachments) > 0 {
		// Multipart message with attachments
		emailMessage.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
		emailMessage.WriteString("\r\n")

		// HTML body part
		emailMessage.WriteString(fmt.Sprintf("--%s\r\n", boundary))
		emailMessage.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		emailMessage.WriteString("Content-Transfer-Encoding: quoted-printable\r\n")
		emailMessage.WriteString("\r\n")
		emailMessage.WriteString(htmlBody)
		emailMessage.WriteString("\r\n")

		// Attachments
		for _, att := range attachments {
			emailMessage.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			contentType := att.ContentType
			if contentType == "" {
				contentType = "application/octet-stream"
			}
			emailMessage.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", contentType, att.Filename))
			emailMessage.WriteString("Content-Transfer-Encoding: base64\r\n")
			emailMessage.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n", att.Filename))
			emailMessage.WriteString("\r\n")

			// Use the base64 data directly if available, otherwise encode the raw data
			if att.DataBase64 != "" {
				emailMessage.WriteString(att.DataBase64)
			} else if len(att.Data) > 0 {
				encoded := base64.StdEncoding.EncodeToString(att.Data)
				// Split base64 into lines of 76 characters
				for i := 0; i < len(encoded); i += 76 {
					end := i + 76
					if end > len(encoded) {
						end = len(encoded)
					}
					emailMessage.WriteString(encoded[i:end])
					emailMessage.WriteString("\r\n")
				}
			}
		}

		// Closing boundary
		emailMessage.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Simple HTML message without attachments
		emailMessage.WriteString("Content-Type: text/html; charset=utf-8\r\n")
		emailMessage.WriteString("\r\n")
		emailMessage.WriteString(htmlBody)
	}

	if _, err := io.WriteString(wc, emailMessage.String()); err != nil {
		return fmt.Errorf("smtp write failed: %w", err)
	}

	// Try to quit gracefully, but don't fail if it fails
	if err := client.Quit(); err != nil {
		log.Printf("Warning: SMTP quit failed: %v", err)
	}

	return nil
}

// Email Compose API Handlers
func (ws *WebServer) handleAPIEmailComposePreview(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	var req struct {
		TemplateID       string         `json:"template_id"`
		ClientIDs        []string       `json:"client_ids"`
		AdditionalEmails []string       `json:"additional_emails"`
		Variables        map[string]any `json:"variables"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.TemplateID == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "template_id is required")
		return
	}

	// Get the template
	template, err := ws.lm.Storage().GetEmailTemplate(ctx, req.TemplateID)
	if err != nil {
		ws.respondAPIError(w, http.StatusNotFound, "Template not found")
		return
	}

	// Get clients if needed
	var clients []*licensing.Client
	if len(req.ClientIDs) > 0 {
		clients, err = ws.lm.ListClients(ctx)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, "Failed to load clients")
			return
		}
	}

	// Build recipient list for preview
	recipients, err := buildComposeRecipients(req.ClientIDs, clients, strings.Join(req.AdditionalEmails, ", "))
	if err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(recipients) == 0 {
		ws.respondAPIError(w, http.StatusBadRequest, "No valid recipients")
		return
	}

	// Use first recipient for preview
	previewRecipient := recipients[0]

	// Render the template
	subject, htmlBody, textBody, err := renderEmailTemplate(template, previewRecipient.Client, previewRecipient.Email, req.Variables)
	if err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}

	ws.respondJSON(w, http.StatusOK, map[string]any{
		"preview": map[string]any{
			"recipient": previewRecipient.Email,
			"subject":   subject,
			"html":      htmlBody,
			"text":      textBody,
		},
	})
}

func (ws *WebServer) handleAPIEmailComposeSend(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	// Define attachment structure for request parsing
	type attachmentRequest struct {
		Filename    string `json:"filename"`
		ContentType string `json:"content_type"`
		DataBase64  string `json:"data_base64"`
	}

	var req struct {
		TemplateID       string              `json:"template_id"`
		ClientIDs        []string            `json:"client_ids"`
		AdditionalEmails []string            `json:"additional_emails"`
		Variables        map[string]any      `json:"variables"`
		Attachments      []attachmentRequest `json:"attachments"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if req.TemplateID == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "template_id is required")
		return
	}

	// Convert attachment requests to email attachments
	var attachments []*email.EmailAttachment
	for _, att := range req.Attachments {
		if att.Filename == "" || att.DataBase64 == "" {
			continue
		}
		attachments = append(attachments, &email.EmailAttachment{
			Filename:    att.Filename,
			ContentType: att.ContentType,
			DataBase64:  att.DataBase64,
		})
	}

	// Get the template
	template, err := ws.lm.Storage().GetEmailTemplate(ctx, req.TemplateID)
	if err != nil {
		ws.respondAPIError(w, http.StatusNotFound, "Template not found")
		return
	}

	// Get clients if needed
	var clients []*licensing.Client
	if len(req.ClientIDs) > 0 {
		clients, err = ws.lm.ListClients(ctx)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, "Failed to load clients")
			return
		}
	}

	// Build recipient list
	recipients, err := buildComposeRecipients(req.ClientIDs, clients, strings.Join(req.AdditionalEmails, ", "))
	if err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}

	if len(recipients) == 0 {
		ws.respondAPIError(w, http.StatusBadRequest, "No valid recipients")
		return
	}

	// Send emails immediately in goroutines
	queuedCount := 0
	var messageIDs []string

	for _, recipient := range recipients {
		messageID := uuid.NewString()
		messageIDs = append(messageIDs, messageID)
		queuedCount++

		// Send email in goroutine for immediate delivery
		// Use background context since the HTTP request context will be canceled after the response is sent
		go func(msgID string, recipient composeRecipient, atts []*email.EmailAttachment) {
			// Use a background context with timeout for the async email sending
			sendCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()

			// Resolve provider for this template
			provider, err := ws.resolveProviderForTemplate(sendCtx, template)
			if err != nil {
				log.Printf("DEBUG: Failed to resolve provider for email %s: %v", msgID, err)
				return
			}

			// Debug: Log provider details
			log.Printf("DEBUG: Using provider %s (%s) for email %s", provider.Name, provider.Type, msgID)
			log.Printf("DEBUG: Provider config: %+v", provider.Config)

			// Render the email template
			subject, htmlBody, textBody, err := renderEmailTemplate(template, recipient.Client, recipient.Email, req.Variables)
			if err != nil {
				log.Printf("Failed to render template for email %s: %v", msgID, err)
				return
			}

			// Send the email immediately with attachments
			if err := sendEmailImmediately(sendCtx, provider, recipient.Email, subject, htmlBody, textBody, atts); err != nil {
				log.Printf("Failed to send email %s: %v", msgID, err)
				return
			}

			log.Printf("Successfully sent email %s to %s", msgID, recipient.Email)
		}(messageID, recipient, attachments)
	}

	ws.respondJSON(w, http.StatusOK, map[string]any{
		"queued_count":      queuedCount,
		"message_ids":       messageIDs,
		"attachments_count": len(attachments),
	})
}
