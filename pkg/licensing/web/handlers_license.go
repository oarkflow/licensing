package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/licensing"
)

// License handlers

func (ws *WebServer) handleLicenses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		action := r.FormValue("action")
		licenseID := r.FormValue("license_id")

		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		switch action {
		case "revoke":
			reason := strings.TrimSpace(r.FormValue("reason"))
			_, err := ws.lm.RevokeLicense(ctx, licenseID, reason)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		case "reinstate":
			_, err := ws.lm.ReinstateLicense(ctx, licenseID)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		http.Redirect(w, r, "/licenses", http.StatusSeeOther)
		return
	}

	licenses, err := ws.lm.ListLicenses(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Sort by issued date descending
	sort.Slice(licenses, func(i, j int) bool {
		return licenses[i].IssuedAt.After(licenses[j].IssuedAt)
	})

	// Get filter from query
	filter := r.URL.Query().Get("filter")
	now := time.Now()

	var filteredLicenses []*licensing.License
	for _, lic := range licenses {
		switch filter {
		case "active":
			if !lic.IsRevoked && lic.ExpiresAt.After(now) {
				filteredLicenses = append(filteredLicenses, lic)
			}
		case "revoked":
			if lic.IsRevoked {
				filteredLicenses = append(filteredLicenses, lic)
			}
		case "expired":
			if !lic.IsRevoked && lic.ExpiresAt.Before(now) {
				filteredLicenses = append(filteredLicenses, lic)
			}
		default:
			filteredLicenses = append(filteredLicenses, lic)
		}
	}

	data := map[string]interface{}{
		"Licenses":      filteredLicenses,
		"TotalCount":    len(licenses),
		"CurrentFilter": filter,
	}

	ws.render(w, "licenses.html", TemplateData{
		Title:       "Licenses",
		CurrentPath: "/licenses",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleNewLicense(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		clientID := strings.TrimSpace(r.FormValue("client_id"))
		productID := strings.TrimSpace(r.FormValue("product_id"))
		planID := strings.TrimSpace(r.FormValue("plan_id"))
		planSlug := strings.TrimSpace(r.FormValue("plan_slug"))
		durationDays := parseInt(r.FormValue("duration_days"), 365)
		maxDevices := parseInt(r.FormValue("max_devices"), 1)
		checkMode := strings.TrimSpace(r.FormValue("check_mode"))

		if clientID == "" || planSlug == "" {
			ws.renderError(w, http.StatusBadRequest, "Client and plan are required")
			return
		}

		mode := licensing.ParseLicenseCheckMode(checkMode)
		duration := time.Duration(durationDays) * 24 * time.Hour

		opts := &licensing.GenerateLicenseOptions{
			ProductID: productID,
			PlanID:    planID,
		}

		_, err := ws.lm.GenerateLicenseWithOptions(ctx, clientID, duration, maxDevices, planSlug, mode, 0, opts)
		if err != nil {
			ws.renderError(w, http.StatusBadRequest, err.Error())
			return
		}

		http.Redirect(w, r, "/licenses", http.StatusSeeOther)
		return
	}

	// GET - show form
	clients, _ := ws.lm.ListClients(ctx)
	products, _ := ws.lm.Storage().ListProducts(ctx)

	// Build plans map per product
	productPlans := make(map[string][]*licensing.Plan)
	for _, prod := range products {
		plans, _ := ws.lm.Storage().ListPlansByProduct(ctx, prod.ID)
		productPlans[prod.ID] = plans
	}

	data := map[string]interface{}{
		"Clients":      clients,
		"Products":     products,
		"ProductPlans": productPlans,
		"CheckModes": []string{
			string(licensing.LicenseCheckModeNone),
			string(licensing.LicenseCheckModeEachRun),
			string(licensing.LicenseCheckModeMonthly),
			string(licensing.LicenseCheckModeYearly),
			string(licensing.LicenseCheckModeCustom),
		},
	}

	ws.render(w, "license_new.html", TemplateData{
		Title:       "New License",
		CurrentPath: "/licenses",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleLicenseDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Extract license ID from path
	path := strings.TrimPrefix(r.URL.Path, "/licenses/")
	parts := strings.Split(path, "/")
	licenseID := parts[0]

	if licenseID == "" {
		http.NotFound(w, r)
		return
	}

	// Handle actions
	if len(parts) > 1 {
		action := parts[1]
		if r.Method == http.MethodPost && ws.validateCSRF(r) {
			switch action {
			case "revoke":
				reason := strings.TrimSpace(r.FormValue("reason"))
				_, err := ws.lm.RevokeLicense(ctx, licenseID, reason)
				if err != nil {
					ws.renderError(w, http.StatusBadRequest, err.Error())
					return
				}
			case "reinstate":
				_, err := ws.lm.ReinstateLicense(ctx, licenseID)
				if err != nil {
					ws.renderError(w, http.StatusBadRequest, err.Error())
					return
				}
			case "deactivate-device":
				fingerprint := strings.TrimSpace(r.FormValue("fingerprint"))
				err := ws.lm.DeactivateDevice(ctx, licenseID, fingerprint)
				if err != nil {
					ws.renderError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
			http.Redirect(w, r, "/licenses/"+licenseID, http.StatusSeeOther)
			return
		}
	}

	license, err := ws.lm.Storage().GetLicense(ctx, licenseID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "License not found")
		return
	}

	activations, _ := ws.lm.ListActivations(ctx, licenseID)

	// Get client info
	var client *licensing.Client
	if license.ClientID != "" {
		client, _ = ws.lm.GetClient(ctx, license.ClientID)
	}

	// Get product and plan info
	var product *licensing.Product
	var plan *licensing.Plan
	if license.ProductID != "" {
		product, _ = ws.lm.Storage().GetProduct(ctx, license.ProductID)
	}
	if license.PlanID != "" {
		plan, _ = ws.lm.Storage().GetPlan(ctx, license.PlanID)
	}

	data := map[string]interface{}{
		"License":     license,
		"Client":      client,
		"Product":     product,
		"Plan":        plan,
		"Activations": activations,
	}

	ws.render(w, "license_detail.html", TemplateData{
		Title:       "License Details",
		CurrentPath: "/licenses",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

// Client handlers

func (ws *WebServer) handleClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		action := r.FormValue("action")
		clientID := r.FormValue("client_id")

		switch action {
		case "ban":
			reason := strings.TrimSpace(r.FormValue("reason"))
			_, err := ws.lm.BanClient(ctx, clientID, reason)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		case "unban":
			_, err := ws.lm.UnbanClient(ctx, clientID)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		http.Redirect(w, r, "/clients", http.StatusSeeOther)
		return
	}

	clients, err := ws.lm.ListClients(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Sort by created date descending
	sort.Slice(clients, func(i, j int) bool {
		return clients[i].CreatedAt.After(clients[j].CreatedAt)
	})

	filter := r.URL.Query().Get("filter")
	var filteredClients []*licensing.Client
	for _, client := range clients {
		switch filter {
		case "active":
			if client.Status == licensing.ClientStatusActive {
				filteredClients = append(filteredClients, client)
			}
		case "banned":
			if client.Status == licensing.ClientStatusBanned {
				filteredClients = append(filteredClients, client)
			}
		default:
			filteredClients = append(filteredClients, client)
		}
	}

	data := map[string]interface{}{
		"Clients":       filteredClients,
		"TotalCount":    len(clients),
		"CurrentFilter": filter,
	}

	ws.render(w, "clients.html", TemplateData{
		Title:       "Clients",
		CurrentPath: "/clients",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleNewClient(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		email := strings.TrimSpace(r.FormValue("email"))
		if email == "" {
			ws.render(w, "client_new.html", TemplateData{
				Title:       "New Client",
				CurrentPath: "/clients",
				User:        ws.getSessionFromContext(r),
				Error:       "Email is required",
			})
			return
		}

		_, err := ws.lm.CreateClient(ctx, email)
		if err != nil {
			ws.render(w, "client_new.html", TemplateData{
				Title:       "New Client",
				CurrentPath: "/clients",
				User:        ws.getSessionFromContext(r),
				Error:       err.Error(),
			})
			return
		}

		http.Redirect(w, r, "/clients", http.StatusSeeOther)
		return
	}

	ws.render(w, "client_new.html", TemplateData{
		Title:       "New Client",
		CurrentPath: "/clients",
		User:        ws.getSessionFromContext(r),
	})
}

func (ws *WebServer) handleClientDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	clientID := strings.TrimPrefix(r.URL.Path, "/clients/")
	parts := strings.Split(clientID, "/")
	clientID = parts[0]

	if clientID == "" {
		http.NotFound(w, r)
		return
	}

	// Handle actions
	if len(parts) > 1 && r.Method == http.MethodPost && ws.validateCSRF(r) {
		action := parts[1]
		switch action {
		case "ban":
			reason := strings.TrimSpace(r.FormValue("reason"))
			_, err := ws.lm.BanClient(ctx, clientID, reason)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		case "unban":
			_, err := ws.lm.UnbanClient(ctx, clientID)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		}
		http.Redirect(w, r, "/clients/"+clientID, http.StatusSeeOther)
		return
	}

	client, err := ws.lm.GetClient(ctx, clientID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Client not found")
		return
	}

	// Get client's licenses
	allLicenses, _ := ws.lm.ListLicenses(ctx)
	var clientLicenses []*licensing.License
	for _, lic := range allLicenses {
		if lic.ClientID == clientID {
			clientLicenses = append(clientLicenses, lic)
		}
	}

	data := map[string]interface{}{
		"Client":   client,
		"Licenses": clientLicenses,
	}

	ws.render(w, "client_detail.html", TemplateData{
		Title:       "Client Details",
		CurrentPath: "/clients",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

// Helper to parse int with default
func parseInt(s string, defaultVal int) int {
	if s == "" {
		return defaultVal
	}
	var val int
	for _, c := range s {
		if c < '0' || c > '9' {
			return defaultVal
		}
		val = val*10 + int(c-'0')
	}
	return val
}
