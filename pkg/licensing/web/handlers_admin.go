package web

import (
	"net/http"
	"sort"
	"strings"

	"github.com/oarkflow/licensing/pkg/licensing"
)

// Admin User handlers

func (ws *WebServer) handleUsers(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := ws.lm.ListAdminUsers(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Sort by created date descending
	sort.Slice(users, func(i, j int) bool {
		return users[i].CreatedAt.After(users[j].CreatedAt)
	})

	// Get API key counts for each user
	userKeyCount := make(map[string]int)
	for _, user := range users {
		keys, _ := ws.lm.ListAPIKeysByUser(ctx, user.ID)
		userKeyCount[user.ID] = len(keys)
	}

	data := map[string]interface{}{
		"Users":        users,
		"UserKeyCount": userKeyCount,
	}

	ws.render(w, "admin_users.html", TemplateData{
		Title:       "Admin Users",
		CurrentPath: "/admin/users",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleNewUser(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := strings.TrimSpace(r.FormValue("password"))
		confirmPassword := strings.TrimSpace(r.FormValue("confirm_password"))

		if username == "" || password == "" {
			ws.render(w, "admin_user_new.html", TemplateData{
				Title:       "New Admin User",
				CurrentPath: "/admin/users",
				User:        ws.getSessionFromContext(r),
				Error:       "Username and password are required",
			})
			return
		}

		if password != confirmPassword {
			ws.render(w, "admin_user_new.html", TemplateData{
				Title:       "New Admin User",
				CurrentPath: "/admin/users",
				User:        ws.getSessionFromContext(r),
				Error:       "Passwords do not match",
			})
			return
		}

		if len(password) < 8 {
			ws.render(w, "admin_user_new.html", TemplateData{
				Title:       "New Admin User",
				CurrentPath: "/admin/users",
				User:        ws.getSessionFromContext(r),
				Error:       "Password must be at least 8 characters",
			})
			return
		}

		_, err := ws.lm.CreateAdminUser(ctx, username, password)
		if err != nil {
			ws.render(w, "admin_user_new.html", TemplateData{
				Title:       "New Admin User",
				CurrentPath: "/admin/users",
				User:        ws.getSessionFromContext(r),
				Error:       err.Error(),
			})
			return
		}

		http.Redirect(w, r, "/admin/users", http.StatusSeeOther)
		return
	}

	ws.render(w, "admin_user_new.html", TemplateData{
		Title:       "New Admin User",
		CurrentPath: "/admin/users",
		User:        ws.getSessionFromContext(r),
	})
}

func (ws *WebServer) handleUserDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	path := strings.TrimPrefix(r.URL.Path, "/admin/users/")
	parts := strings.Split(path, "/")
	userID := parts[0]

	if userID == "" {
		http.NotFound(w, r)
		return
	}

	user, err := ws.lm.GetAdminUser(ctx, userID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "User not found")
		return
	}

	// Handle API key generation
	if len(parts) > 1 && parts[1] == "api-keys" && r.Method == http.MethodPost && ws.validateCSRF(r) {
		action := r.FormValue("action")

		switch action {
		case "generate":
			token, _, err := ws.lm.GenerateAPIKey(ctx, userID)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
			// Show the generated token once
			keys, _ := ws.lm.ListAPIKeysByUser(ctx, userID)
			ws.render(w, "admin_user_edit.html", TemplateData{
				Title:       user.Username,
				CurrentPath: "/admin/users",
				User:        ws.getSessionFromContext(r),
				Data: map[string]interface{}{
					"AdminUser":   user,
					"APIKeys":     keys,
					"NewAPIToken": token,
				},
			})
			return
		case "revoke":
			keyID := r.FormValue("key_id")
			err := ws.lm.RevokeAPIKey(ctx, keyID)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		http.Redirect(w, r, "/admin/users/"+userID, http.StatusSeeOther)
		return
	}

	// Handle password change
	if len(parts) > 1 && parts[1] == "password" && r.Method == http.MethodPost && ws.validateCSRF(r) {
		currentPassword := strings.TrimSpace(r.FormValue("current_password"))
		newPassword := strings.TrimSpace(r.FormValue("new_password"))
		confirmPassword := strings.TrimSpace(r.FormValue("confirm_password"))

		if newPassword != confirmPassword {
			ws.render(w, "admin_user_edit.html", TemplateData{
				Title:       user.Username,
				CurrentPath: "/admin/users",
				User:        ws.getSessionFromContext(r),
				Data:        map[string]interface{}{"AdminUser": user},
				Error:       "Passwords do not match",
			})
			return
		}

		err := ws.lm.ChangeAdminPassword(ctx, userID, currentPassword, newPassword)
		if err != nil {
			ws.render(w, "admin_user_edit.html", TemplateData{
				Title:       user.Username,
				CurrentPath: "/admin/users",
				User:        ws.getSessionFromContext(r),
				Data:        map[string]interface{}{"AdminUser": user},
				Error:       err.Error(),
			})
			return
		}

		http.Redirect(w, r, "/admin/users/"+userID, http.StatusSeeOther)
		return
	}

	keys, _ := ws.lm.ListAPIKeysByUser(ctx, userID)

	data := map[string]interface{}{
		"AdminUser": user,
		"APIKeys":   keys,
	}

	ws.render(w, "admin_user_edit.html", TemplateData{
		Title:       user.Username,
		CurrentPath: "/admin/users",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

// API Keys list handler
func (ws *WebServer) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	users, err := ws.lm.ListAdminUsers(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type keyWithUser struct {
		Key  *licensing.APIKeyRecord
		User *licensing.AdminUser
	}

	var allKeys []keyWithUser
	userMap := make(map[string]*licensing.AdminUser)

	for _, user := range users {
		userMap[user.ID] = user
		keys, _ := ws.lm.ListAPIKeysByUser(ctx, user.ID)
		for _, key := range keys {
			allKeys = append(allKeys, keyWithUser{Key: key, User: user})
		}
	}

	// Sort by created date descending
	sort.Slice(allKeys, func(i, j int) bool {
		return allKeys[i].Key.CreatedAt.After(allKeys[j].Key.CreatedAt)
	})

	data := map[string]interface{}{
		"Keys":    allKeys,
		"UserMap": userMap,
	}

	ws.render(w, "admin_api_keys.html", TemplateData{
		Title:       "API Keys",
		CurrentPath: "/admin/api-keys",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

// handleNewAPIKey handles generating new API keys
func (ws *WebServer) handleNewAPIKey(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := ws.getSessionFromContext(r)

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		description := strings.TrimSpace(r.FormValue("description"))
		_ = name        // Will be used in future
		_ = description // Will be used in future

		// Generate API key for the current user
		token, _, err := ws.lm.GenerateAPIKey(ctx, session.UserID)
		if err != nil {
			ws.renderError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Show the created key page with the raw token
		keys, _ := ws.lm.ListAPIKeysByUser(ctx, session.UserID)
		var newKey *licensing.APIKeyRecord
		for _, k := range keys {
			if len(keys) > 0 {
				newKey = k
				break
			}
		}

		ws.render(w, "admin_api_key_created.html", TemplateData{
			Title:       "API Key Created",
			CurrentPath: "/admin/api-keys",
			User:        session,
			Data: map[string]interface{}{
				"APIKey":  newKey,
				"RawKey":  token,
				"BaseURL": "http://localhost:8080",
			},
		})
		return
	}

	ws.render(w, "admin_api_key_new.html", TemplateData{
		Title:       "Generate API Key",
		CurrentPath: "/admin/api-keys",
		User:        session,
	})
}

// handleProfile handles the user profile page
func (ws *WebServer) handleProfile(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	session := ws.getSessionFromContext(r)

	user, err := ws.lm.GetAdminUser(ctx, session.UserID)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, "Failed to load user data")
		return
	}

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		action := r.URL.Path
		if strings.HasSuffix(action, "/password") {
			// Handle password change
			currentPassword := strings.TrimSpace(r.FormValue("current_password"))
			newPassword := strings.TrimSpace(r.FormValue("new_password"))
			confirmPassword := strings.TrimSpace(r.FormValue("confirm_password"))

			if newPassword != confirmPassword {
				ws.render(w, "profile.html", TemplateData{
					Title:       "Profile",
					CurrentPath: "/profile",
					User:        session,
					Error:       "Passwords do not match",
				})
				return
			}

			err := ws.lm.ChangeAdminPassword(ctx, user.ID, currentPassword, newPassword)
			if err != nil {
				ws.render(w, "profile.html", TemplateData{
					Title:       "Profile",
					CurrentPath: "/profile",
					User:        session,
					Error:       err.Error(),
				})
				return
			}

			http.Redirect(w, r, "/profile", http.StatusSeeOther)
			return
		}

		// Handle username update
		username := strings.TrimSpace(r.FormValue("username"))
		if username != "" && username != user.Username {
			// For now, just redirect since we need to add update method
			// TODO: Add UpdateAdminUser to LicenseManager
		}

		http.Redirect(w, r, "/profile", http.StatusSeeOther)
		return
	}

	ws.render(w, "profile.html", TemplateData{
		Title:       "Profile",
		CurrentPath: "/profile",
		User:        session,
		Data: map[string]interface{}{
			"AdminUser": user,
		},
	})
}
