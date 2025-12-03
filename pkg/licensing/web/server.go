package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/oarkflow/licensing/pkg/licensing"
)

//go:embed templates/*.html templates/partials/*.html
var templatesFS embed.FS

//go:embed templates/*
var staticFS embed.FS

// Session represents an authenticated admin session
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
	templates     map[string]*template.Template
	sessions      map[string]*Session // In-memory cache for fast lookups
	sessionsMu    sync.RWMutex
	sessionMaxAge time.Duration
	csrfSecrets   map[string]time.Time
	csrfMu        sync.RWMutex
	sessionStore  SessionStore // Persistent session storage
}

// NewWebServer creates a new web server instance
func NewWebServer(lm *licensing.LicenseManager) (*WebServer, error) {
	ws := &WebServer{
		lm:            lm,
		sessions:      make(map[string]*Session),
		sessionMaxAge: 24 * time.Hour,
		csrfSecrets:   make(map[string]time.Time),
	}

	// Try to get session store from LicenseManager's storage
	if store, ok := lm.Storage().(SessionStore); ok {
		ws.sessionStore = store
		// Load existing sessions from storage
		ws.loadSessionsFromStorage()
	}

	if err := ws.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Start session cleanup goroutine
	go ws.cleanupSessions()

	return ws, nil
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

func (ws *WebServer) loadTemplates() error {
	funcMap := template.FuncMap{
		"formatTime": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("Jan 02, 2006 15:04")
		},
		"formatDate": func(t time.Time) string {
			if t.IsZero() {
				return "-"
			}
			return t.Format("Jan 02, 2006")
		},
		"truncate": func(s string, length int) string {
			if len(s) <= length {
				return s
			}
			return s[:length] + "..."
		},
		"isExpired": func(t time.Time) bool {
			return !t.IsZero() && t.Before(time.Now())
		},
		"daysUntil": func(t time.Time) int {
			if t.IsZero() {
				return 0
			}
			return int(time.Until(t).Hours() / 24)
		},
		"formatCurrency": func(cents int64, currency string) string {
			if currency == "" {
				currency = "USD"
			}
			return fmt.Sprintf("$%.2f %s", float64(cents)/100, currency)
		},
		"statusBadge": func(status string) template.HTML {
			colors := map[string]string{
				"active":   "bg-green-100 text-green-800",
				"banned":   "bg-red-100 text-red-800",
				"revoked":  "bg-red-100 text-red-800",
				"expired":  "bg-yellow-100 text-yellow-800",
				"inactive": "bg-gray-100 text-gray-800",
			}
			color := colors[strings.ToLower(status)]
			if color == "" {
				color = "bg-gray-100 text-gray-800"
			}
			return template.HTML(fmt.Sprintf(`<span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium %s">%s</span>`, color, status))
		},
		"add": func(a, b int) int {
			return a + b
		},
		"sub": func(a, b int) int {
			return a - b
		},
		"json": func(v interface{}) template.JS {
			b, _ := json.Marshal(v)
			return template.JS(b)
		},
		"safeHTML": func(s string) template.HTML {
			return template.HTML(s)
		},
		"upper": func(s string) string {
			return strings.ToUpper(s)
		},
		"lower": func(s string) string {
			return strings.ToLower(s)
		},
		"slice": func(s string, start, end int) string {
			if start < 0 {
				start = 0
			}
			if end > len(s) {
				end = len(s)
			}
			if start >= end {
				return ""
			}
			return s[start:end]
		},
		"hasPrefix": func(s, prefix string) bool {
			return strings.HasPrefix(s, prefix)
		},
		"contains": func(s, substr string) bool {
			return strings.Contains(s, substr)
		},
	}

	base := template.New("base").Funcs(funcMap)
	layoutFiles := []string{"templates/base.html"}
	partialFiles, err := fs.Glob(templatesFS, "templates/partials/*.html")
	if err != nil {
		return err
	}
	if len(partialFiles) > 0 {
		layoutFiles = append(layoutFiles, partialFiles...)
	}
	if _, err := base.ParseFS(templatesFS, layoutFiles...); err != nil {
		return err
	}

	pageFiles, err := fs.Glob(templatesFS, "templates/*.html")
	if err != nil {
		return err
	}

	ws.templates = make(map[string]*template.Template, len(pageFiles))
	for _, file := range pageFiles {
		name := filepath.Base(file)
		if name == "base.html" {
			continue
		}

		clone, err := base.Clone()
		if err != nil {
			return err
		}

		if _, err := clone.ParseFS(templatesFS, file); err != nil {
			return fmt.Errorf("failed to parse template %s: %w", name, err)
		}

		ws.templates[name] = clone
	}

	return nil
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

		ws.csrfMu.Lock()
		for token, expires := range ws.csrfSecrets {
			if expires.Before(now) {
				delete(ws.csrfSecrets, token)
			}
		}
		ws.csrfMu.Unlock()
	}
}

// GenerateCSRFToken creates a new CSRF token
func (ws *WebServer) GenerateCSRFToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	token := base64.URLEncoding.EncodeToString(bytes)

	ws.csrfMu.Lock()
	ws.csrfSecrets[token] = time.Now().Add(2 * time.Hour)
	ws.csrfMu.Unlock()

	return token
}

// ValidateCSRFToken validates a CSRF token
func (ws *WebServer) ValidateCSRFToken(token string) bool {
	ws.csrfMu.RLock()
	expires, ok := ws.csrfSecrets[token]
	ws.csrfMu.RUnlock()

	if !ok || expires.Before(time.Now()) {
		return false
	}
	return true
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

// TemplateData holds common data for templates
type TemplateData struct {
	Title       string
	CurrentPath string
	User        *Session
	CSRFToken   string
	Flash       *FlashMessage
	Data        interface{}
	Error       string
}

// FlashMessage represents a flash message
type FlashMessage struct {
	Type    string // success, error, warning, info
	Message string
}

// Handler returns the HTTP handler for the web server
func (ws *WebServer) Handler() http.Handler {
	mux := http.NewServeMux()

	// Static files
	staticSub, _ := fs.Sub(staticFS, "static")
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

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

	// Initial setup (before any admin exists)
	mux.HandleFunc("/setup", ws.handleSetup)

	// Auth routes
	mux.HandleFunc("/login", ws.handleLogin)
	mux.HandleFunc("/logout", ws.handleLogout)

	// Dashboard
	mux.HandleFunc("/", ws.requireAuth(ws.handleDashboard))

	// Licenses
	mux.HandleFunc("/licenses", ws.requireAuth(ws.handleLicenses))
	mux.HandleFunc("/licenses/new", ws.requireAuth(ws.handleNewLicense))
	mux.HandleFunc("/licenses/", ws.requireAuth(ws.handleLicenseDetail))

	// Clients
	mux.HandleFunc("/clients", ws.requireAuth(ws.handleClients))
	mux.HandleFunc("/clients/new", ws.requireAuth(ws.handleNewClient))
	mux.HandleFunc("/clients/", ws.requireAuth(ws.handleClientDetail))

	// Products
	mux.HandleFunc("/products", ws.requireAuth(ws.handleProducts))
	mux.HandleFunc("/products/new", ws.requireAuth(ws.handleNewProduct))
	mux.HandleFunc("/products/", ws.requireAuth(ws.handleProductDetail))

	// Plans
	mux.HandleFunc("/plans/", ws.requireAuth(ws.handlePlanDetail))

	// Features
	mux.HandleFunc("/features/", ws.requireAuth(ws.handleFeatureDetail))

	// Messaging
	mux.HandleFunc("/messaging/providers", ws.requireAuth(ws.handleEmailProviders))
	mux.HandleFunc("/messaging/providers/new", ws.requireAuth(ws.handleNewEmailProvider))
	mux.HandleFunc("/messaging/providers/", ws.requireAuth(ws.handleEmailProviderDetail))
	mux.HandleFunc("/messaging/templates", ws.requireAuth(ws.handleEmailTemplates))
	mux.HandleFunc("/messaging/templates/new", ws.requireAuth(ws.handleNewEmailTemplate))
	mux.HandleFunc("/messaging/templates/", ws.requireAuth(ws.handleEmailTemplateDetail))
	mux.HandleFunc("/messaging/compose", ws.requireAuth(ws.handleEmailCompose))

	// Admin Users
	mux.HandleFunc("/admin/users", ws.requireAuth(ws.handleUsers))
	mux.HandleFunc("/admin/users/new", ws.requireAuth(ws.handleNewUser))
	mux.HandleFunc("/admin/users/", ws.requireAuth(ws.handleUserDetail))

	// API Keys
	mux.HandleFunc("/admin/api-keys", ws.requireAuth(ws.handleAPIKeys))
	mux.HandleFunc("/admin/api-keys/new", ws.requireAuth(ws.handleNewAPIKey))

	// Profile
	mux.HandleFunc("/profile", ws.requireAuth(ws.handleProfile))

	return ws.withMiddleware(mux)
}

func (ws *WebServer) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Content-Security-Policy", strings.Join([]string{
			"default-src 'self'",
			"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.tailwindcss.com https://cdn.jsdelivr.net",
			"style-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com",
			"img-src 'self' data:",
			"font-src 'self' data:",
			"connect-src 'self'",
		}, "; "))

		next.ServeHTTP(w, r)
	})
}

func (ws *WebServer) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session_id")
		if err != nil || cookie.Value == "" {
			if ws.hasAdminUser(r.Context()) {
				http.Redirect(w, r, "/login", http.StatusSeeOther)
			} else {
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
			}
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
			destination := "/login"
			if !ws.hasAdminUser(r.Context()) {
				destination = "/setup"
			}
			http.Redirect(w, r, destination, http.StatusSeeOther)
			return
		}

		// Store session in context
		ctx := context.WithValue(r.Context(), "session", session)
		next(w, r.WithContext(ctx))
	}
}

func (ws *WebServer) getSessionFromContext(r *http.Request) *Session {
	session, _ := r.Context().Value("session").(*Session)
	return session
}

func (ws *WebServer) render(w http.ResponseWriter, templateName string, data TemplateData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if data.CSRFToken == "" {
		data.CSRFToken = ws.GenerateCSRFToken()
	}

	tmpl, ok := ws.templates[templateName]
	if !ok {
		log.Printf("Template not found: %s", templateName)
		http.Error(w, "Template not found", http.StatusInternalServerError)
		return
	}

	err := tmpl.ExecuteTemplate(w, templateName, data)
	if err != nil {
		log.Printf("Template error: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (ws *WebServer) renderError(w http.ResponseWriter, status int, message string) {
	w.WriteHeader(status)
	ws.render(w, "error.html", TemplateData{
		Title: "Error",
		Error: message,
	})
}

// validateCSRF checks CSRF token for POST requests
func (ws *WebServer) validateCSRF(r *http.Request) bool {
	if r.Method != http.MethodPost {
		return true
	}
	token := r.FormValue("csrf_token")
	return ws.ValidateCSRFToken(token)
}

// Auth handlers
func (ws *WebServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if !ws.hasAdminUser(r.Context()) {
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		ws.render(w, "login.html", TemplateData{
			Title:     "Login",
			CSRFToken: ws.GenerateCSRFToken(),
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !ws.validateCSRF(r) {
		ws.render(w, "login.html", TemplateData{
			Title:     "Login",
			CSRFToken: ws.GenerateCSRFToken(),
			Error:     "Invalid CSRF token. Please try again.",
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))

	if username == "" || password == "" {
		ws.render(w, "login.html", TemplateData{
			Title:     "Login",
			CSRFToken: ws.GenerateCSRFToken(),
			Error:     "Username and password are required",
		})
		return
	}

	// Authenticate user
	user, err := ws.lm.AuthenticateAdmin(r.Context(), username, password)
	if err != nil {
		ws.render(w, "login.html", TemplateData{
			Title:     "Login",
			CSRFToken: ws.GenerateCSRFToken(),
			Error:     "Invalid username or password",
		})
		return
	}

	// Create session
	session := ws.CreateSession(user.ID, user.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		MaxAge:   int(ws.sessionMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (ws *WebServer) handleLogout(w http.ResponseWriter, r *http.Request) {
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
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (ws *WebServer) handleSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if ws.hasAdminUser(ctx) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	if r.Method == http.MethodGet {
		ws.render(w, "setup.html", TemplateData{
			Title:       "Initial Setup",
			CurrentPath: "/setup",
		})
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if !ws.validateCSRF(r) {
		ws.render(w, "setup.html", TemplateData{
			Title: "Initial Setup",
			Error: "Invalid CSRF token. Please try again.",
		})
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := strings.TrimSpace(r.FormValue("password"))
	confirm := strings.TrimSpace(r.FormValue("confirm_password"))

	if username == "" || password == "" {
		ws.render(w, "setup.html", TemplateData{
			Title: "Initial Setup",
			Error: "Username and password are required",
		})
		return
	}
	if password != confirm {
		ws.render(w, "setup.html", TemplateData{
			Title: "Initial Setup",
			Error: "Passwords do not match",
		})
		return
	}

	user, err := ws.lm.CreateAdminUser(ctx, username, password)
	if err != nil {
		ws.render(w, "setup.html", TemplateData{
			Title: "Initial Setup",
			Error: err.Error(),
		})
		return
	}

	token, _, err := ws.lm.GenerateAPIKey(ctx, user.ID)
	if err != nil {
		ws.render(w, "setup.html", TemplateData{
			Title: "Initial Setup",
			Error: fmt.Sprintf("failed to create API key: %v", err),
		})
		return
	}

	log.Printf("🆕 Initial admin created: %s", user.Username)
	log.Printf("   Password: %s", password)
	log.Printf("   API Key: %s", token)

	session := ws.CreateSession(user.ID, user.Username)
	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    session.ID,
		Path:     "/",
		MaxAge:   int(ws.sessionMaxAge.Seconds()),
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// Dashboard handler
func (ws *WebServer) handleDashboard(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	ctx := r.Context()

	// Gather statistics
	licenses, _ := ws.lm.ListLicenses(ctx)
	clients, _ := ws.lm.ListClients(ctx)
	products, _ := ws.lm.Storage().ListProducts(ctx)
	users, _ := ws.lm.ListAdminUsers(ctx)

	// Calculate stats
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

	// Recent licenses
	recentLicenses := licenses
	if len(recentLicenses) > 5 {
		recentLicenses = recentLicenses[:5]
	}

	data := map[string]interface{}{
		"TotalLicenses":   len(licenses),
		"ActiveLicenses":  activeLicenses,
		"RevokedLicenses": revokedLicenses,
		"ExpiredLicenses": expiredLicenses,
		"TotalClients":    len(clients),
		"ActiveClients":   activeClients,
		"BannedClients":   bannedClients,
		"TotalProducts":   len(products),
		"TotalAdmins":     len(users),
		"RecentLicenses":  recentLicenses,
	}

	ws.render(w, "dashboard.html", TemplateData{
		Title:       "Dashboard",
		CurrentPath: "/",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

// constantTimeCompare compares two strings in constant time
func constantTimeCompare(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
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

// respondAPIError writes a JSON error response
func (ws *WebServer) respondAPIError(w http.ResponseWriter, status int, message string) {
	ws.respondJSON(w, status, map[string]string{"error": message})
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
		// Redirect to setup page instead of showing error
		http.Redirect(w, r, "/setup", http.StatusSeeOther)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
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
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
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
