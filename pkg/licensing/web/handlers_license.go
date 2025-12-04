package web

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/licensing"
)

// ==================== License APIs ====================

func (ws *WebServer) handleAPILicenses(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		licenses, err := ws.lm.ListLicenses(ctx)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		filtered := filterLicensesByQuery(licenses, r.URL.Query().Get("filter"))
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].IssuedAt.After(filtered[j].IssuedAt)
		})
		ws.respondJSON(w, http.StatusOK, filtered)
	case http.MethodPost:
		var req struct {
			ClientID            string `json:"client_id"`
			ProductID           string `json:"product_id"`
			PlanID              string `json:"plan_id"`
			PlanSlug            string `json:"plan_slug"`
			DurationDays        int    `json:"duration_days"`
			MaxDevices          int    `json:"max_devices"`
			CheckMode           string `json:"check_mode"`
			CheckIntervalSecond int64  `json:"check_interval_seconds"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.TrimSpace(req.ClientID) == "" || strings.TrimSpace(req.PlanSlug) == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "client_id and plan_slug are required")
			return
		}
		if req.DurationDays <= 0 {
			req.DurationDays = 365
		}
		if req.MaxDevices <= 0 {
			req.MaxDevices = 1
		}
		mode := licensing.ParseLicenseCheckMode(req.CheckMode)
		interval := time.Duration(req.CheckIntervalSecond) * time.Second
		var opts *licensing.GenerateLicenseOptions
		if strings.TrimSpace(req.ProductID) != "" || strings.TrimSpace(req.PlanID) != "" {
			opts = &licensing.GenerateLicenseOptions{
				ProductID: req.ProductID,
				PlanID:    req.PlanID,
			}
		}
		license, err := ws.lm.GenerateLicenseWithOptions(
			ctx,
			req.ClientID,
			time.Duration(req.DurationDays)*24*time.Hour,
			req.MaxDevices,
			req.PlanSlug,
			mode,
			interval,
			opts,
		)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusCreated, license)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPILicenseDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/licenses/")
	if path == "" || path == r.URL.Path {
		ws.respondAPIError(w, http.StatusNotFound, "License ID is required")
		return
	}
	parts := strings.Split(path, "/")
	licenseID := strings.TrimSpace(parts[0])
	if licenseID == "" {
		ws.respondAPIError(w, http.StatusNotFound, "License ID is required")
		return
	}
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		license, err := ws.lm.Storage().GetLicense(ctx, licenseID)
		if err != nil {
			ws.respondAPIError(w, http.StatusNotFound, "License not found")
			return
		}
		ws.respondJSON(w, http.StatusOK, license)
		return
	}
	action := parts[1]
	switch action {
	case "revoke":
		ws.handleAPILicenseRevoke(w, r, ctx, licenseID)
	case "reinstate":
		ws.handleAPILicenseReinstate(w, r, ctx, licenseID)
	case "deactivate-device":
		ws.handleAPILicenseDeactivateDevice(w, r, ctx, licenseID)
	case "activations":
		ws.handleAPILicenseActivations(w, r, ctx, licenseID)
	default:
		ws.respondAPIError(w, http.StatusNotFound, "Invalid license action")
	}
}

func (ws *WebServer) handleAPILicenseRevoke(w http.ResponseWriter, r *http.Request, ctx context.Context, licenseID string) {
	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	license, err := ws.lm.RevokeLicense(ctx, licenseID, strings.TrimSpace(req.Reason))
	if err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusOK, license)
}

func (ws *WebServer) handleAPILicenseReinstate(w http.ResponseWriter, r *http.Request, ctx context.Context, licenseID string) {
	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	license, err := ws.lm.ReinstateLicense(ctx, licenseID)
	if err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusOK, license)
}

func (ws *WebServer) handleAPILicenseDeactivateDevice(w http.ResponseWriter, r *http.Request, ctx context.Context, licenseID string) {
	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	var req struct {
		Fingerprint string `json:"fingerprint"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Fingerprint) == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "fingerprint is required")
		return
	}
	if err := ws.lm.DeactivateDevice(ctx, licenseID, req.Fingerprint); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusOK, map[string]string{"message": "Device deactivated"})
}

func (ws *WebServer) handleAPILicenseActivations(w http.ResponseWriter, r *http.Request, ctx context.Context, licenseID string) {
	if r.Method != http.MethodGet {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	records, err := ws.lm.ListActivations(ctx, licenseID)
	if err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusOK, records)
}

func filterLicensesByQuery(licenses []*licensing.License, filter string) []*licensing.License {
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "active":
		now := time.Now()
		var filtered []*licensing.License
		for _, lic := range licenses {
			if !lic.IsRevoked && lic.ExpiresAt.After(now) {
				filtered = append(filtered, lic)
			}
		}
		return filtered
	case "revoked":
		var filtered []*licensing.License
		for _, lic := range licenses {
			if lic.IsRevoked {
				filtered = append(filtered, lic)
			}
		}
		return filtered
	case "expired":
		now := time.Now()
		var filtered []*licensing.License
		for _, lic := range licenses {
			if !lic.IsRevoked && lic.ExpiresAt.Before(now) {
				filtered = append(filtered, lic)
			}
		}
		return filtered
	default:
		return licenses
	}
}

// ==================== Client APIs ====================

func (ws *WebServer) handleAPIClients(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		clients, err := ws.lm.ListClients(ctx)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		filtered := filterClientsByQuery(clients, r.URL.Query().Get("filter"))
		sort.Slice(filtered, func(i, j int) bool {
			return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
		})
		ws.respondJSON(w, http.StatusOK, filtered)
	case http.MethodPost:
		var req struct {
			Email string `json:"email"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.TrimSpace(req.Email) == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "email is required")
			return
		}
		client, err := ws.lm.CreateClient(ctx, req.Email)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusCreated, client)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIClientDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	clientID := strings.TrimPrefix(r.URL.Path, "/api/clients/")
	if clientID == "" || clientID == r.URL.Path {
		ws.respondAPIError(w, http.StatusNotFound, "Client ID is required")
		return
	}
	parts := strings.Split(clientID, "/")
	id := strings.TrimSpace(parts[0])
	if id == "" {
		ws.respondAPIError(w, http.StatusNotFound, "Client ID is required")
		return
	}
	if len(parts) > 1 {
		switch parts[1] {
		case "ban":
			ws.handleAPIClientBan(w, r, id)
		case "unban":
			ws.handleAPIClientUnban(w, r, id)
		case "licenses":
			ws.handleAPIClientLicenses(w, r, id)
		default:
			ws.respondAPIError(w, http.StatusNotFound, "Unknown client action")
		}
		return
	}
	if r.Method != http.MethodGet {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	client, err := ws.lm.GetClient(ctx, id)
	if err != nil {
		ws.respondAPIError(w, http.StatusNotFound, "Client not found")
		return
	}
	ws.respondJSON(w, http.StatusOK, client)
}

func (ws *WebServer) handleAPIClientBan(w http.ResponseWriter, r *http.Request, clientID string) {
	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx := r.Context()
	var req struct {
		Reason string `json:"reason"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req)
	client, err := ws.lm.BanClient(ctx, clientID, strings.TrimSpace(req.Reason))
	if err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusOK, client)
}

func (ws *WebServer) handleAPIClientUnban(w http.ResponseWriter, r *http.Request, clientID string) {
	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx := r.Context()
	client, err := ws.lm.UnbanClient(ctx, clientID)
	if err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusOK, client)
}

func (ws *WebServer) handleAPIClientLicenses(w http.ResponseWriter, r *http.Request, clientID string) {
	if r.Method != http.MethodGet {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx := r.Context()
	licenses, err := ws.lm.ListLicenses(ctx)
	if err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var clientLicenses []*licensing.License
	for _, lic := range licenses {
		if lic.ClientID == clientID {
			clientLicenses = append(clientLicenses, lic)
		}
	}
	ws.respondJSON(w, http.StatusOK, clientLicenses)
}

func filterClientsByQuery(clients []*licensing.Client, filter string) []*licensing.Client {
	switch strings.ToLower(strings.TrimSpace(filter)) {
	case "active":
		var filtered []*licensing.Client
		for _, client := range clients {
			if client.Status == licensing.ClientStatusActive {
				filtered = append(filtered, client)
			}
		}
		return filtered
	case "banned":
		var filtered []*licensing.Client
		for _, client := range clients {
			if client.Status == licensing.ClientStatusBanned {
				filtered = append(filtered, client)
			}
		}
		return filtered
	default:
		return clients
	}
}
