package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/licensing/pkg/licensing"
)

type Session struct {
	ID        string
	UserID    string
	Username  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

// SessionStore defines the interface for session persistence
type SessionStore interface {
	SaveSession(ctx context.Context, session *licensing.AdminSession) error
	GetSession(ctx context.Context, sessionID string) (*licensing.AdminSession, error)
	DeleteSession(ctx context.Context, sessionID string) error
	DeleteExpiredSessions(ctx context.Context) error
}

// WebServer handles the admin UI
type WebServer struct {
	lm            *licensing.LicenseManager
	server        *licensing.Server   // Reference to the main server for email functionality
	sessions      map[string]*Session // In-memory cache for fast lookups
	sessionsMu    sync.RWMutex
	sessionMaxAge time.Duration
	sessionStore  SessionStore // Persistent session storage
	distDir       string
}

// NewWebServer creates a new web server instance
func NewWebServer(lm *licensing.LicenseManager) (*WebServer, error) {
	ws := &WebServer{
		lm:            lm,
		sessions:      make(map[string]*Session),
		sessionMaxAge: 24 * time.Hour,
	}

	// Try to get session store from LicenseManager's storage
	if store, ok := lm.Storage().(SessionStore); ok {
		ws.sessionStore = store
		// Load existing sessions from storage
		ws.loadSessionsFromStorage()
	}

	distDir := strings.TrimSpace(os.Getenv("LICENSE_SERVER_WEB_DIST"))
	if distDir == "" {
		distDir = "dist"
	}
	absDist, err := filepath.Abs(distDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve dist directory: %w", err)
	}
	ws.distDir = absDist
	if _, err := os.Stat(ws.distDir); err != nil {
		log.Printf("Warning: React build directory %s not accessible (%v)", ws.distDir, err)
	} else {
		log.Printf("Serving React frontend from %s", ws.distDir)
	}

	// Start session cleanup goroutine
	go ws.cleanupSessions()

	return ws, nil
}

// SetServer sets the reference to the main licensing server for email functionality
func (ws *WebServer) SetServer(server *licensing.Server) {
	ws.server = server
	log.Printf("📧 WebServer: Server reference set for email functionality")
}

// loadSessionsFromStorage loads non-expired sessions from persistent storage
func (ws *WebServer) loadSessionsFromStorage() {
	if ws.sessionStore == nil {
		return
	}
	ctx := context.Background()
	// Clean up expired sessions first
	if err := ws.sessionStore.DeleteExpiredSessions(ctx); err != nil {
		log.Printf("Warning: failed to cleanup expired sessions: %v", err)
	}
}

func (ws *WebServer) cleanupSessions() {
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		ws.sessionsMu.Lock()
		now := time.Now()
		for id, session := range ws.sessions {
			if session.ExpiresAt.Before(now) {
				delete(ws.sessions, id)
			}
		}
		ws.sessionsMu.Unlock()

		// Also cleanup from persistent storage
		if ws.sessionStore != nil {
			ctx := context.Background()
			if err := ws.sessionStore.DeleteExpiredSessions(ctx); err != nil {
				log.Printf("Warning: failed to cleanup expired sessions from storage: %v", err)
			}
		}

	}
}

// CreateSession creates a new session for a user
func (ws *WebServer) CreateSession(userID, username string) *Session {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	sessionID := hex.EncodeToString(bytes)

	session := &Session{
		ID:        sessionID,
		UserID:    userID,
		Username:  username,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(ws.sessionMaxAge),
	}

	ws.sessionsMu.Lock()
	ws.sessions[sessionID] = session
	ws.sessionsMu.Unlock()

	// Persist to storage if available
	if ws.sessionStore != nil {
		ctx := context.Background()
		adminSession := &licensing.AdminSession{
			ID:        session.ID,
			UserID:    session.UserID,
			Username:  session.Username,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
		}
		if err := ws.sessionStore.SaveSession(ctx, adminSession); err != nil {
			log.Printf("Warning: failed to persist session: %v", err)
		}
	}

	return session
}

// GetSession retrieves a session by ID
func (ws *WebServer) GetSession(sessionID string) *Session {
	// Try in-memory cache first
	ws.sessionsMu.RLock()
	session, ok := ws.sessions[sessionID]
	ws.sessionsMu.RUnlock()

	if ok {
		if session.ExpiresAt.Before(time.Now()) {
			// Session expired, remove it
			ws.DeleteSession(sessionID)
			return nil
		}
		return session
	}

	// Try persistent storage
	if ws.sessionStore != nil {
		ctx := context.Background()
		adminSession, err := ws.sessionStore.GetSession(ctx, sessionID)
		if err == nil && adminSession != nil {
			if adminSession.ExpiresAt.Before(time.Now()) {
				// Session expired, remove it
				ws.DeleteSession(sessionID)
				return nil
			}
			// Cache it in memory
			session = &Session{
				ID:        adminSession.ID,
				UserID:    adminSession.UserID,
				Username:  adminSession.Username,
				CreatedAt: adminSession.CreatedAt,
				ExpiresAt: adminSession.ExpiresAt,
			}
			ws.sessionsMu.Lock()
			ws.sessions[sessionID] = session
			ws.sessionsMu.Unlock()
			return session
		}
	}

	return nil
}

// ValidateSession implements the licensing.SessionValidator interface
func (ws *WebServer) ValidateSession(sessionID string) (userID string, username string, ok bool) {
	session := ws.GetSession(sessionID)
	if session == nil {
		return "", "", false
	}
	return session.UserID, session.Username, true
}

func (ws *WebServer) hasAdminUser(ctx context.Context) bool {
	users, err := ws.lm.ListAdminUsers(ctx)
	if err != nil {
		log.Printf("Failed to list admin users: %v", err)
		return true
	}
	return len(users) > 0
}

// DeleteSession removes a session
func (ws *WebServer) DeleteSession(sessionID string) {
	ws.sessionsMu.Lock()
	delete(ws.sessions, sessionID)
	ws.sessionsMu.Unlock()

	// Also delete from persistent storage
	if ws.sessionStore != nil {
		ctx := context.Background()
		_ = ws.sessionStore.DeleteSession(ctx, sessionID) // Ignore errors on delete
	}
}

// Handler returns the HTTP handler for the web server
func (ws *WebServer) Handler() http.Handler {
	mux := http.NewServeMux()

	// JSON API Auth endpoints for React frontend
	mux.HandleFunc("/api/auth/login", ws.handleAPILogin)
	mux.HandleFunc("/api/auth/logout", ws.handleAPILogout)
	mux.HandleFunc("/api/auth/session", ws.handleAPISession)
	mux.HandleFunc("/api/auth/setup", ws.handleAPISetup)
	mux.HandleFunc("/api/auth/setup-required", ws.handleAPISetupRequired)

	// JSON API endpoints that use session auth
	mux.HandleFunc("/api/dashboard/stats", ws.requireAPIAuth(ws.handleAPIDashboardStats))

	// Messaging API endpoints
	mux.HandleFunc("/api/email/providers", ws.requireAPIAuth(ws.handleAPIEmailProviders))
	mux.HandleFunc("/api/email/providers/", ws.requireAPIAuth(ws.handleAPIEmailProviderDetail))
	mux.HandleFunc("/api/email/providers/test", ws.requireAPIAuth(ws.handleAPIEmailProviderTest))
	mux.HandleFunc("/api/email/providers/{id}/default", ws.requireAPIAuth(ws.handleAPIEmailProviderDefault))
	mux.HandleFunc("/api/email/providers/{id}/toggle", ws.requireAPIAuth(ws.handleAPIEmailProviderToggle))
	mux.HandleFunc("/api/email/templates", ws.requireAPIAuth(ws.handleAPIEmailTemplates))
	mux.HandleFunc("/api/email/templates/", ws.requireAPIAuth(ws.handleAPIEmailTemplateDetail))
	mux.HandleFunc("/api/email/compose/preview", ws.requireAPIAuth(ws.handleAPIEmailComposePreview))
	mux.HandleFunc("/api/email/compose/send", ws.requireAPIAuth(ws.handleAPIEmailComposeSend))

	// Serve React SPA for all other routes
	mux.HandleFunc("/", ws.handleSPA)

	return ws.withMiddleware(mux)
}

func (ws *WebServer) getAllowedOrigins() []string {
	// Get allowed origins from environment variable
	originsStr := strings.TrimSpace(os.Getenv("LICENSE_SERVER_ALLOWED_ORIGINS"))
	if originsStr == "" {
		// Default to common development origins
		return []string{
			"http://localhost:5173", // Vite default port
			"http://localhost:3000", // Common React port
			"http://localhost:8080", // Common development port
		}
	}

	// Parse comma-separated origins
	origins := strings.Split(originsStr, ",")
	for i, origin := range origins {
		origins[i] = strings.TrimSpace(origin)
	}
	return origins
}

func (ws *WebServer) isOriginAllowed(origin string) bool {
	if origin == "" {
		return true
	}

	allowedOrigins := ws.getAllowedOrigins()
	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == origin {
			return true
		}
	}
	return false
}

func (ws *WebServer) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle CORS with proper origin handling for credentialed requests
		origin := r.Header.Get("Origin")

		// If no origin, use default for development
		if origin == "" {
			origin = "http://localhost:5173"
		} else if !ws.isOriginAllowed(origin) {
			// If origin is not allowed, don't set CORS headers
			next.ServeHTTP(w, r)
			return
		}

		// CORS headers
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Device-Fingerprint, X-License-Key, X-License-Secure, Cookie")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		w.Header().Set("Access-Control-Max-Age", "86400") // 24 hours

		// Handle OPTIONS requests for CORS preflight
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net",
			"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://fonts.googleapis.com",
			"img-src 'self' data:",
			"font-src 'self' data: https://fonts.gstatic.com",
			"connect-src 'self'",
		}, "; "))

		next.ServeHTTP(w, r)
	})
}

func (ws *WebServer) handleSPA(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}

	if ws.distDir == "" {
		http.Error(w, "frontend bundle unavailable", http.StatusServiceUnavailable)
		return
	}

	relPath := strings.TrimPrefix(r.URL.Path, "/")
	if relPath == "" {
		relPath = "index.html"
	}
	cleanPath := filepath.Clean(relPath)
	if strings.HasPrefix(cleanPath, "..") {
		http.NotFound(w, r)
		return
	}
	fullPath := filepath.Join(ws.distDir, cleanPath)
	if !strings.HasPrefix(fullPath, ws.distDir) {
		http.NotFound(w, r)
		return
	}
	if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
		http.ServeFile(w, r, fullPath)
		return
	}
	indexPath := filepath.Join(ws.distDir, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		http.Error(w, "frontend index not found", http.StatusServiceUnavailable)
		return
	}
	http.ServeFile(w, r, indexPath)
}

func (ws *WebServer) getSessionFromContext(r *http.Request) *Session {
	session, _ := r.Context().Value("session").(*Session)
	return session
}

// ==================== JSON API Handlers for React Frontend ====================

// respondJSON writes a JSON response
func (ws *WebServer) respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("Failed to write JSON response: %v", err)
	}
}

// respondAPIError writes a JSON error response with detailed information
func (ws *WebServer) respondAPIError(w http.ResponseWriter, status int, message string, details ...map[string]interface{}) {
	// Create structured error response
	errorResponse := map[string]interface{}{
		"success": false,
		"error": map[string]interface{}{
			"message": message,
			"status":  status,
			"code":    getErrorCodeFromStatus(status),
		},
	}

	// Add additional details if provided
	if len(details) > 0 && details[0] != nil {
		errorResponse["error"].(map[string]interface{})["details"] = details[0]
	}

	ws.respondJSON(w, status, errorResponse)
}

// respondAPIErrorWithRequest provides enhanced error responses with request context
func (ws *WebServer) respondAPIErrorWithRequest(w http.ResponseWriter, r *http.Request, status int, message string, details ...map[string]interface{}) {
	// Create structured error response with request context
	errorResponse := map[string]interface{}{
		"success": false,
		"error": map[string]interface{}{
			"message": message,
			"status":  status,
			"code":    getErrorCodeFromStatus(status),
		},
	}

	// Add additional details if provided
	if len(details) > 0 && details[0] != nil {
		errorResponse["error"].(map[string]interface{})["details"] = details[0]
	}

	// Add request context for debugging
	if r != nil {
		errorResponse["request"] = map[string]interface{}{
			"method":    r.Method,
			"path":      r.URL.Path,
			"timestamp": time.Now().Format(time.RFC3339),
		}
	}

	ws.respondJSON(w, status, errorResponse)
}

// respondAPIErrorSimple maintains backward compatibility
func (ws *WebServer) respondAPIErrorSimple(w http.ResponseWriter, status int, message string) {
	ws.respondJSON(w, status, map[string]string{"error": message})
}

// getErrorCodeFromStatus maps HTTP status codes to error codes
func getErrorCodeFromStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "invalid_request"
	case http.StatusUnauthorized:
		return "unauthorized"
	case http.StatusForbidden:
		return "forbidden"
	case http.StatusNotFound:
		return "not_found"
	case http.StatusMethodNotAllowed:
		return "method_not_allowed"
	case http.StatusConflict:
		return "conflict"
	case http.StatusTooManyRequests:
		return "rate_limited"
	case http.StatusInternalServerError:
		return "internal_error"
	default:
		return "api_error"
	}
}

// requireAPIAuth is middleware for JSON API endpoints requiring authentication
func (ws *WebServer) requireAPIAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			ws.respondAPIError(w, http.StatusUnauthorized, "Authentication required")
			return
		}

		session := ws.GetSession(cookie.Value)
		if session == nil {
			http.SetCookie(w, &http.Cookie{
				Name:     "session_id",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				SameSite: http.SameSiteStrictMode,
			})
			ws.respondAPIError(w, http.StatusUnauthorized, "Session expired")
			return
		}

		ctx := context.WithValue(r.Context(), "session", session)
		next(w, r.WithContext(ctx))
	}
}

// handleAPILogin handles JSON login requests
func (ws *WebServer) handleAPILogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	if !ws.hasAdminUser(r.Context()) {
		ws.respondAPIError(w, http.StatusBadRequest, "Require Setup before login")
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
			"expected": "JSON object with username and password fields",
			"example": map[string]string{
				"username": "admin",
				"password": "password123",
			},
			"error_type":       "json_decode_failed",
			"parse_error":      err.Error(),
			"suggested_action": "Ensure the request body is valid JSON with username and password fields",
		})
		return
	}

	if req.Username == "" || req.Password == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "Username and password are required")
		return
	}

	user, err := ws.lm.AuthenticateAdmin(r.Context(), req.Username, req.Password)
	if err != nil {
		ws.respondAPIError(w, http.StatusUnauthorized, "Invalid username or password")
		return
	}

	session := ws.CreateSession(user.ID, user.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		MaxAge:   int(ws.sessionMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode, // Use Lax for cross-origin requests from frontend
		Secure:   r.TLS != nil,
	})

	ws.respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
	})
}

// handleAPILogout handles JSON logout requests
func (ws *WebServer) handleAPILogout(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	cookie, err := r.Cookie("session_id")
	if err == nil && cookie.Value != "" {
		ws.DeleteSession(cookie.Value)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	ws.respondJSON(w, http.StatusOK, map[string]string{"message": "Logged out successfully"})
}

// handleAPISession returns the current session info
func (ws *WebServer) handleAPISession(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	cookie, err := r.Cookie("session_id")
	if err != nil || cookie.Value == "" {
		ws.respondAPIError(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	session := ws.GetSession(cookie.Value)
	if session == nil {
		ws.respondAPIError(w, http.StatusUnauthorized, "Session expired")
		return
	}

	ws.respondJSON(w, http.StatusOK, map[string]interface{}{
		"id":       session.UserID,
		"username": session.Username,
	})
}

// handleAPISetupRequired checks if initial setup is required
func (ws *WebServer) handleAPISetupRequired(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	required := !ws.hasAdminUser(r.Context())
	ws.respondJSON(w, http.StatusOK, map[string]bool{"required": required})
}

// handleAPISetup handles initial admin setup via JSON
func (ws *WebServer) handleAPISetup(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodPost {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()
	if ws.hasAdminUser(ctx) {
		ws.respondAPIError(w, http.StatusBadRequest, "Setup already completed")
		return
	}

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

	if req.Username == "" || req.Password == "" {
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

	// Create API key for the user
	_, _, err = ws.lm.GenerateAPIKey(ctx, user.ID)
	if err != nil {
		log.Printf("Warning: failed to create API key during setup: %v", err)
	}

	session := ws.CreateSession(user.ID, user.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		MaxAge:   int(ws.sessionMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   r.TLS != nil,
	})

	ws.respondJSON(w, http.StatusCreated, map[string]interface{}{
		"id":       user.ID,
		"username": user.Username,
	})
}

// handleAPIDashboardStats returns dashboard statistics as JSON
func (ws *WebServer) handleAPIDashboardStats(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != http.MethodGet {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}

	ctx := r.Context()

	licenses, _ := ws.lm.ListLicenses(ctx)
	clients, _ := ws.lm.ListClients(ctx)
	products, _ := ws.lm.Storage().ListProducts(ctx)
	users, _ := ws.lm.ListAdminUsers(ctx)

	activeLicenses := 0
	revokedLicenses := 0
	expiredLicenses := 0
	now := time.Now()

	for _, lic := range licenses {
		if lic.IsRevoked {
			revokedLicenses++
		} else if lic.ExpiresAt.Before(now) {
			expiredLicenses++
		} else {
			activeLicenses++
		}
	}

	activeClients := 0
	bannedClients := 0
	for _, client := range clients {
		if client.Status == licensing.ClientStatusBanned {
			bannedClients++
		} else {
			activeClients++
		}
	}

	recentLicenses := licenses
	if len(recentLicenses) > 5 {
		recentLicenses = recentLicenses[:5]
	}

	ws.respondJSON(w, http.StatusOK, map[string]interface{}{
		"total_licenses":   len(licenses),
		"active_licenses":  activeLicenses,
		"revoked_licenses": revokedLicenses,
		"expired_licenses": expiredLicenses,
		"total_clients":    len(clients),
		"active_clients":   activeClients,
		"banned_clients":   bannedClients,
		"total_products":   len(products),
		"total_admins":     len(users),
		"recent_licenses":  recentLicenses,
	})
}
