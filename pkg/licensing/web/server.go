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

// WebServer handles the admin UI
type WebServer struct {
	lm            *licensing.LicenseManager
	templates     map[string]*template.Template
	sessions      map[string]*Session
	sessionsMu    sync.RWMutex
	sessionMaxAge time.Duration
	csrfSecrets   map[string]time.Time
	csrfMu        sync.RWMutex
}

// NewWebServer creates a new web server instance
func NewWebServer(lm *licensing.LicenseManager) (*WebServer, error) {
	ws := &WebServer{
		lm:            lm,
		sessions:      make(map[string]*Session),
		sessionMaxAge: 24 * time.Hour,
		csrfSecrets:   make(map[string]time.Time),
	}

	if err := ws.loadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load templates: %w", err)
	}

	// Start session cleanup goroutine
	go ws.cleanupSessions()

	return ws, nil
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

	return session
}

// GetSession retrieves a session by ID
func (ws *WebServer) GetSession(sessionID string) *Session {
	ws.sessionsMu.RLock()
	session, ok := ws.sessions[sessionID]
	ws.sessionsMu.RUnlock()

	if !ok || session.ExpiresAt.Before(time.Now()) {
		return nil
	}
	return session
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
