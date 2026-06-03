package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/licensing"
)

type adminUserResponse struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type apiKeyResponse struct {
	ID             string   `json:"id"`
	UserID         string   `json:"user_id"`
	Prefix         string   `json:"prefix"`
	Scopes         []string `json:"scopes,omitempty"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	ExpiresAt      string   `json:"expires_at,omitempty"`
	CreatedAt      string   `json:"created_at"`
	LastUsed       string   `json:"last_used_at,omitempty"`
}

func sanitizeAdminUser(user *licensing.AdminUser) adminUserResponse {
	return adminUserResponse{
		ID:        user.ID,
		Username:  user.Username,
		CreatedAt: user.CreatedAt.Format(time.RFC3339),
		UpdatedAt: user.UpdatedAt.Format(time.RFC3339),
	}
}

func sanitizeAPIKey(key *licensing.APIKeyRecord) apiKeyResponse {
	resp := apiKeyResponse{
		ID:             key.ID,
		UserID:         key.UserID,
		Prefix:         key.Prefix,
		Scopes:         key.Scopes,
		AllowedIPs:     key.AllowedIPs,
		AllowedOrigins: key.AllowedOrigins,
		CreatedAt:      key.CreatedAt.Format(time.RFC3339),
	}
	if !key.ExpiresAt.IsZero() {
		resp.ExpiresAt = key.ExpiresAt.Format(time.RFC3339)
	}
	if !key.LastUsed.IsZero() {
		resp.LastUsed = key.LastUsed.Format(time.RFC3339)
	}
	return resp
}

type createAPIKeyRequest struct {
	UserID         string   `json:"user_id"`
	Scopes         []string `json:"scopes,omitempty"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	ExpiresAt      string   `json:"expires_at,omitempty"`
	TTLHours       int      `json:"ttl_hours,omitempty"`
}

func normalizeRequestList(values []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

func apiKeyOptionsFromRequest(req createAPIKeyRequest) (licensing.APIKeyOptions, error) {
	opts := licensing.APIKeyOptions{
		Scopes:         normalizeRequestList(req.Scopes),
		AllowedIPs:     normalizeRequestList(req.AllowedIPs),
		AllowedOrigins: normalizeRequestList(req.AllowedOrigins),
	}
	if len(opts.Scopes) == 0 {
		opts.Scopes = []string{"admin:*"}
	}
	for _, raw := range opts.AllowedIPs {
		if strings.Contains(raw, "/") {
			if _, _, err := net.ParseCIDR(raw); err != nil {
				return opts, fmt.Errorf("invalid allowed IP CIDR %q", raw)
			}
			continue
		}
		if net.ParseIP(raw) == nil {
			return opts, fmt.Errorf("invalid allowed IP %q", raw)
		}
	}
	if strings.TrimSpace(req.ExpiresAt) != "" {
		expiresAt, err := time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			return opts, fmt.Errorf("expires_at must be RFC3339")
		}
		opts.ExpiresAt = expiresAt
	}
	if req.TTLHours > 0 {
		opts.ExpiresAt = time.Now().Add(time.Duration(req.TTLHours) * time.Hour)
	}
	return opts, nil
}

func (ws *WebServer) handleAPIAdminUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		users, err := ws.lm.ListAdminUsers(ctx)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}

		sort.Slice(users, func(i, j int) bool {
			return users[i].CreatedAt.After(users[j].CreatedAt)
		})

		resp := make([]adminUserResponse, 0, len(users))
		for _, user := range users {
			resp = append(resp, sanitizeAdminUser(user))
		}
		ws.respondJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req struct {
			Username        string `json:"username"`
			Password        string `json:"password"`
			ConfirmPassword string `json:"confirm_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
				"expected": "JSON object with username and password fields",
				"example": map[string]string{
					"username":         "admin",
					"password":         "securepassword123",
					"confirm_password": "securepassword123",
				},
				"error_type":       "json_decode_failed",
				"parse_error":      err.Error(),
				"suggested_action": "Ensure the request body is valid JSON with required fields (username, password) and optional confirm_password",
			})
			return
		}

		if strings.TrimSpace(req.Username) == "" || strings.TrimSpace(req.Password) == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "Username and password are required")
			return
		}
		if req.ConfirmPassword != "" && req.Password != req.ConfirmPassword {
			ws.respondAPIError(w, http.StatusBadRequest, "Passwords do not match")
			return
		}

		user, err := ws.lm.CreateAdminUser(ctx, req.Username, req.Password)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusCreated, sanitizeAdminUser(user))
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIAdminUserDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/users/")
	if path == "" || path == r.URL.Path {
		ws.respondAPIError(w, http.StatusNotFound, "User ID is required")
		return
	}
	parts := strings.Split(path, "/")
	userID := strings.TrimSpace(parts[0])
	if userID == "" {
		ws.respondAPIError(w, http.StatusNotFound, "User ID is required")
		return
	}

	if len(parts) > 1 {
		switch parts[1] {
		case "password":
			if r.Method != http.MethodPost {
				ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
				return
			}
			var req struct {
				CurrentPassword string `json:"currentPassword"`
				NewPassword     string `json:"newPassword"`
				ConfirmPassword string `json:"confirmPassword"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
					"expected": "JSON object with currentPassword and newPassword fields",
					"example": map[string]string{
						"currentPassword": "oldpassword123",
						"newPassword":     "newpassword456",
						"confirmPassword": "newpassword456",
					},
					"error_type":       "json_decode_failed",
					"parse_error":      err.Error(),
					"suggested_action": "Ensure the request body is valid JSON with required fields (currentPassword, newPassword) and optional confirmPassword",
				})
				return
			}
			if req.NewPassword == "" || req.CurrentPassword == "" {
				ws.respondAPIError(w, http.StatusBadRequest, "Current and new passwords are required")
				return
			}
			if req.ConfirmPassword != "" && req.NewPassword != req.ConfirmPassword {
				ws.respondAPIError(w, http.StatusBadRequest, "Passwords do not match")
				return
			}
			if err := ws.lm.ChangeAdminPassword(ctx, userID, req.CurrentPassword, req.NewPassword); err != nil {
				ws.respondAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			ws.respondJSON(w, http.StatusOK, map[string]string{"message": "Password updated"})
		default:
			ws.respondAPIError(w, http.StatusNotFound, "Unknown user action")
		}
		return
	}

	switch r.Method {
	case http.MethodGet:
		user, err := ws.lm.GetAdminUser(ctx, userID)
		if err != nil {
			ws.respondAPIError(w, http.StatusNotFound, "User not found")
			return
		}
		ws.respondJSON(w, http.StatusOK, sanitizeAdminUser(user))
	case http.MethodPut:
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
				"expected": "JSON object with admin user update data",
				"example": map[string]interface{}{
					"username": "new-admin-username",
				},
				"error_type":       "json_decode_failed",
				"parse_error":      err.Error(),
				"suggested_action": "Ensure the request body contains valid JSON with a 'username' field",
			})
			return
		}
		if strings.TrimSpace(req.Username) == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "Username is required")
			return
		}
		user, err := ws.lm.UpdateAdminUser(ctx, userID, req.Username)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, sanitizeAdminUser(user))
	case http.MethodDelete:
		if err := ws.lm.DeleteAdminUser(ctx, userID); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIAdminAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if userID == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "user_id query parameter is required")
			return
		}
		keys, err := ws.lm.ListAPIKeysByUser(ctx, userID)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		sort.Slice(keys, func(i, j int) bool {
			return keys[i].CreatedAt.After(keys[j].CreatedAt)
		})
		resp := make([]apiKeyResponse, 0, len(keys))
		for _, key := range keys {
			resp = append(resp, sanitizeAPIKey(key))
		}
		ws.respondJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req createAPIKeyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
				"expected": "JSON object with user_id and optional scopes/restrictions",
				"example": map[string]interface{}{
					"user_id":     "admin-user-uuid",
					"scopes":      []string{"licenses:read", "clients:read"},
					"allowed_ips": []string{"203.0.113.10", "10.0.0.0/24"},
					"ttl_hours":   24,
				},
				"error_type":       "json_decode_failed",
				"parse_error":      err.Error(),
				"suggested_action": "Ensure the request body contains valid JSON",
			})
			return
		}
		if strings.TrimSpace(req.UserID) == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "user_id is required")
			return
		}
		opts, err := apiKeyOptionsFromRequest(req)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		token, metadata, err := ws.lm.GenerateAPIKeyWithOptions(ctx, req.UserID, opts)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusCreated, map[string]interface{}{
			"token":    token,
			"metadata": sanitizeAPIKey(metadata),
		})
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIAdminAPIKeyDetail(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx := r.Context()
	keyID := strings.TrimPrefix(r.URL.Path, "/api/admin/api-keys/")
	keyID = strings.TrimSpace(keyID)
	if keyID == "" || keyID == r.URL.Path {
		ws.respondAPIError(w, http.StatusNotFound, "API key ID is required")
		return
	}
	if err := ws.lm.DeleteAPIKey(ctx, keyID); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (ws *WebServer) handleAPIProfile(w http.ResponseWriter, r *http.Request) {
	session := ws.getSessionFromContext(r)
	if session == nil {
		ws.respondAPIError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		user, err := ws.lm.GetAdminUser(ctx, session.UserID)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, sanitizeAdminUser(user))
	case http.MethodPut:
		var req struct {
			Username string `json:"username"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
				"expected": "JSON object with profile update data",
				"example": map[string]interface{}{
					"username": "new-profile-username",
				},
				"error_type":       "json_decode_failed",
				"parse_error":      err.Error(),
				"suggested_action": "Ensure the request body contains valid JSON with a 'username' field",
			})
			return
		}
		if strings.TrimSpace(req.Username) == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "Username is required")
			return
		}
		user, err := ws.lm.UpdateAdminUser(ctx, session.UserID, req.Username)
		if err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		session.Username = user.Username
		ws.respondJSON(w, http.StatusOK, sanitizeAdminUser(user))
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIProfilePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	session := ws.getSessionFromContext(r)
	if session == nil {
		ws.respondAPIError(w, http.StatusUnauthorized, "Authentication required")
		return
	}
	ctx := r.Context()
	var req struct {
		CurrentPassword string `json:"currentPassword"`
		NewPassword     string `json:"newPassword"`
		ConfirmPassword string `json:"confirmPassword"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
			"expected": "JSON object with currentPassword and newPassword fields",
			"example": map[string]string{
				"currentPassword": "oldpassword123",
				"newPassword":     "newpassword456",
				"confirmPassword": "newpassword456",
			},
			"error_type":       "json_decode_failed",
			"parse_error":      err.Error(),
			"suggested_action": "Ensure the request body is valid JSON with required fields (currentPassword, newPassword) and optional confirmPassword",
		})
		return
	}
	if req.NewPassword == "" || req.CurrentPassword == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "Current and new passwords are required")
		return
	}
	if req.ConfirmPassword != "" && req.NewPassword != req.ConfirmPassword {
		ws.respondAPIError(w, http.StatusBadRequest, "Passwords do not match")
		return
	}
	if err := ws.lm.ChangeAdminPassword(ctx, session.UserID, req.CurrentPassword, req.NewPassword); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusOK, map[string]string{"message": "Password updated"})
}
