package licensing

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/smtp"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/licensing/pkg/audit"
	email "github.com/oarkflow/licensing/pkg/email"
	"github.com/oarkflow/licensing/pkg/utils"
	_ "modernc.org/sqlite"
)

type Server struct {
	lm                  *LicenseManager
	port                string
	rateLimiter         *RateLimiter
	legacyAPIKeyHashes  [][]byte
	tlsCertPath         string
	tlsKeyPath          string
	clientCAPath        string
	allowInsecureHTTP   bool
	webHandler          http.Handler     // Optional web UI handler
	sessionValidator    SessionValidator // Optional session validator for cookie-based auth
	emailTemplateLoader *EmailTemplateLoader
	// In-memory client sessions (for client authentication). Persist via storage in future.
	clientSessions   map[string]*ClientSession
	clientSessionsMu sync.RWMutex
	metrics          *serverMetrics
	auditLogger      *audit.AuditLogger
	auditIncludePing bool
	auditDB          *sql.DB
}

type serverMetrics struct {
	startedAt     time.Time
	requestsTotal atomic.Uint64
	requestsLive  atomic.Uint64
	requests2xx   atomic.Uint64
	requests4xx   atomic.Uint64
	requests5xx   atomic.Uint64
	latencyNanos  atomic.Uint64
	responseBytes atomic.Uint64
}

// SessionValidator validates session cookies for authentication
type SessionValidator interface {
	ValidateSession(sessionID string) (userID string, username string, ok bool)
}

type adminUserResponse struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type apiKeyMetadata struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	ClientID  string    `json:"client_id,omitempty"`
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used_at,omitempty"`
}

type apiKeyIssueResponse struct {
	Token    string         `json:"token"`
	Metadata apiKeyMetadata `json:"metadata"`
}

type emailDispatchResult struct {
	Queued    bool   `json:"queued"`
	Sent      bool   `json:"sent,omitempty"`
	MessageID string `json:"message_id,omitempty"`
	Error     string `json:"error,omitempty"`
}

func newAdminUserResponse(user *AdminUser) adminUserResponse {
	if user == nil {
		return adminUserResponse{}
	}
	return adminUserResponse{
		ID:        user.ID,
		Username:  user.Username,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

func newAPIKeyMetadata(record *APIKeyRecord) apiKeyMetadata {
	if record == nil {
		return apiKeyMetadata{}
	}
	return apiKeyMetadata{
		ID:        record.ID,
		UserID:    record.UserID,
		ClientID:  record.ClientID,
		Prefix:    record.Prefix,
		CreatedAt: record.CreatedAt,
		LastUsed:  record.LastUsed,
	}
}

func NewServer(lm *LicenseManager, port string, apiKeys []string, limiter *RateLimiter, tlsCertPath, tlsKeyPath, clientCAPath string, allowInsecure bool) (*Server, error) {
	var hashes [][]byte
	var err error
	if len(apiKeys) > 0 {
		hashes, err = utils.HashAPIKeys(apiKeys)
		if err != nil {
			return nil, err
		}
	}
	if limiter == nil {
		limiter = NewRateLimiter(60, time.Minute)
	}
	if !allowInsecure && (strings.TrimSpace(tlsCertPath) == "" || strings.TrimSpace(tlsKeyPath) == "") {
		return nil, fmt.Errorf("tls cert/key required unless allowInsecure HTTP is enabled")
	}
	// Initialize email template loader with embedded templates
	// This allows the server to run as a standalone binary
	emailTemplateLoader := NewEmailTemplateLoader(TemplatesFS)
	if err := emailTemplateLoader.LoadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load email templates: %w", err)
	}

	server := &Server{
		lm:                  lm,
		port:                port,
		rateLimiter:         limiter,
		legacyAPIKeyHashes:  hashes,
		tlsCertPath:         tlsCertPath,
		tlsKeyPath:          tlsKeyPath,
		clientCAPath:        clientCAPath,
		allowInsecureHTTP:   allowInsecure,
		emailTemplateLoader: emailTemplateLoader,
		clientSessions:      map[string]*ClientSession{},
		metrics:             &serverMetrics{startedAt: time.Now()},
	}
	if err := server.initAuditLogger(); err != nil {
		return nil, err
	}
	return server, nil
}

// SetWebHandler sets an optional web UI handler for the server
// The web handler will handle all non-API routes (everything not starting with /api/ or /health)
func (s *Server) SetWebHandler(h http.Handler) {
	s.webHandler = h
}

// SetSessionValidator sets an optional session validator for cookie-based authentication
func (s *Server) SetSessionValidator(v SessionValidator) {
	s.sessionValidator = v
}

func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func isSecureRequest(r *http.Request) bool {
	if r != nil && r.TLS != nil {
		return true
	}
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	return proto == "https"
}

func (s *Server) enforceRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if s.rateLimiter == nil {
		return true
	}
	ip := clientIP(r)

	// Check if this is an authenticated admin session - use higher limits
	if s.sessionValidator != nil {
		cookie, err := r.Cookie("session_id")
		if err == nil && cookie.Value != "" {
			if _, _, ok := s.sessionValidator.ValidateSession(cookie.Value); ok {
				// Admin session gets higher rate limits
				if !s.rateLimiter.AllowAdmin(ip) {
					s.respondError(w, http.StatusTooManyRequests, "Too many requests")
					return false
				}
				return true
			}
		}
	}

	// Also check API key for higher limits
	providedKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if providedKey != "" {
		if _, err := s.lm.ValidateAPIKey(r.Context(), providedKey); err == nil {
			if !s.rateLimiter.AllowAdmin(ip) {
				s.respondError(w, http.StatusTooManyRequests, "Too many requests")
				return false
			}
			return true
		}
	}

	// Regular rate limit for unauthenticated requests
	if !s.rateLimiter.Allow(ip) {
		s.respondError(w, http.StatusTooManyRequests, "Too many requests")
		return false
	}
	return true
}

func (s *Server) enforceClientRateLimit(w http.ResponseWriter, r *http.Request) bool {
	if s.rateLimiter == nil {
		return true
	}
	ip := clientIP(r)
	if !s.rateLimiter.Allow(ip) {
		s.respondClientError(w, http.StatusTooManyRequests, "Too many requests", nil)
		return false
	}
	return true
}

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	// First try API key authentication
	providedKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if providedKey != "" {
		if len(s.legacyAPIKeyHashes) > 0 {
			providedHash := sha256.Sum256([]byte(providedKey))
			for _, allowed := range s.legacyAPIKeyHashes {
				if subtle.ConstantTimeCompare(providedHash[:], allowed) == 1 {
					return true
				}
			}
		}
		if _, err := s.lm.ValidateAPIKey(r.Context(), providedKey); err == nil {
			return true
		}
	}

	// If Authorization header is present, allow bearer admin API keys as well
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token := strings.TrimSpace(parts[1])
			if token != "" {
				if _, err := s.lm.ValidateAPIKey(r.Context(), token); err == nil {
					return true
				}
			}
		}
	}

	// Then try session-based authentication (if validator is available)
	if s.sessionValidator != nil {
		cookie, err := r.Cookie("session_id")
		if err == nil && cookie.Value != "" {
			if _, _, ok := s.sessionValidator.ValidateSession(cookie.Value); ok {
				return true
			}
		}
	}

	s.respondError(w, http.StatusUnauthorized, "Unauthorized")
	return false
}

func (s *Server) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, limit int64) bool {
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	decoder := json.NewDecoder(body)
	if err := decoder.Decode(dst); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body", map[string]interface{}{
			"expected":         "Valid JSON object",
			"error_type":       "json_decode_failed",
			"parse_error":      err.Error(),
			"suggested_action": "Ensure the request body contains valid JSON",
		})
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		s.respondError(w, http.StatusBadRequest, "Request body must contain a single JSON object")
		return false
	}
	return true
}

func (s *Server) respondJSON(w http.ResponseWriter, status int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

func (s *Server) respondError(w http.ResponseWriter, status int, message string, details ...map[string]interface{}) {
	if len(details) > 0 && details[0] != nil {
		s.respondJSON(w, status, map[string]interface{}{
			"error":   message,
			"details": details[0],
		})
	} else {
		s.respondJSON(w, status, map[string]string{"error": message})
	}
}

func (s *Server) respondClientJSON(w http.ResponseWriter, status int, payload interface{}, transportKey []byte) {
	w.Header().Set("Content-Type", "application/json")
	if len(transportKey) == 32 {
		data, err := json.Marshal(payload)
		if err != nil {
			log.Printf("failed to marshal secure payload: %v", err)
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		envelope, err := utils.EncryptEnvelope(transportKey, data)
		if err != nil {
			log.Printf("failed to encrypt payload: %v", err)
			s.respondError(w, http.StatusInternalServerError, "internal server error")
			return
		}
		w.Header().Set("X-License-Secure", "1")
		w.WriteHeader(status)
		if err := json.NewEncoder(w).Encode(envelope); err != nil {
			log.Printf("failed to write secure response: %v", err)
		}
		return
	}
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		log.Printf("failed to write JSON response: %v", err)
	}
}

func (s *Server) respondClientError(w http.ResponseWriter, status int, message string, transportKey []byte, details ...map[string]interface{}) {
	var payload interface{}
	if len(details) > 0 && details[0] != nil {
		payload = map[string]interface{}{
			"error":   message,
			"details": details[0],
		}
	} else {
		payload = map[string]string{"error": message}
	}

	if len(transportKey) == 32 {
		s.respondClientJSON(w, status, payload, transportKey)
		return
	}
	s.respondJSON(w, status, payload)
}

func (s *Server) enqueueEmailWithAttachments(ctx context.Context, to, subject, htmlBody, textBody string, metadata map[string]string, attachments []*email.EmailAttachment) (*emailDispatchResult, error) {
	to = strings.TrimSpace(to)
	if to == "" {
		return nil, fmt.Errorf("recipient email is required")
	}
	storage := s.lm.Storage()
	if storage == nil {
		return nil, fmt.Errorf("email storage backend unavailable")
	}
	msg := &email.EmailMessage{
		ID:           uuid.New().String(),
		To:           to,
		Subject:      subject,
		RenderedHTML: htmlBody,
		RenderedText: textBody,
		Status:       email.MessageStatusQueued,
		MaxRetries:   3,
		Metadata:     metadata,
		Attachments:  attachments,
	}
	if err := storage.EnqueueEmail(ctx, msg); err != nil {
		return nil, err
	}
	return &emailDispatchResult{Queued: true, MessageID: msg.ID}, nil
}

// SendEmailNow sends an email immediately using the first active SMTP provider
func (s *Server) SendEmailNow(ctx context.Context, to, subject, htmlBody, textBody string, attachments []*email.EmailAttachment) (*emailDispatchResult, error) {
	return s.sendEmailNow(ctx, to, subject, htmlBody, textBody, attachments)
}

// EmailTemplateLoader returns the email template loader
func (s *Server) EmailTemplateLoader() *EmailTemplateLoader {
	return s.emailTemplateLoader
}

// sendEmailNow sends an email immediately using the first active SMTP provider
func (s *Server) sendEmailNow(ctx context.Context, to, subject, htmlBody, textBody string, attachments []*email.EmailAttachment) (*emailDispatchResult, error) {
	to = strings.TrimSpace(to)
	if to == "" {
		return nil, fmt.Errorf("recipient email is required")
	}

	storage := s.lm.Storage()
	if storage == nil {
		return nil, fmt.Errorf("storage backend unavailable")
	}

	// Get an active email provider (only enabled ones)
	providers, err := storage.ListEmailProviders(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to list email providers: %w", err)
	}
	log.Printf("📧 Found %d enabled email providers", len(providers))
	if len(providers) == 0 {
		// Check if any providers exist but are disabled
		allProviders, checkErr := storage.ListEmailProviders(ctx, true)
		if checkErr == nil && len(allProviders) > 0 {
			return nil, fmt.Errorf("email provider(s) exist but none are enabled - please enable an SMTP provider in /messaging/providers")
		}
		return nil, fmt.Errorf("no email providers configured - please configure an SMTP provider in /messaging/providers")
	}

	// Use the first active SMTP provider (prefer default if available)
	var provider *email.EmailProvider
	for _, p := range providers {
		log.Printf("📧 Checking provider: %s (type=%s, enabled=%t, default=%t)", p.Name, p.Type, p.Enabled, p.IsDefault)
		if p.Type == email.ProviderTypeSMTP && p.Enabled {
			if p.IsDefault {
				provider = p
				break
			}
			if provider == nil {
				provider = p
			}
		}
	}
	if provider == nil {
		return nil, fmt.Errorf("no active SMTP provider found - please enable an SMTP provider in /messaging/providers")
	}
	log.Printf("📧 Using email provider: %s (%s)", provider.Name, provider.Slug)

	// Extract SMTP config
	config := provider.Config
	host := getConfigString(config, "host")
	port := getConfigInt(config, "port", 587)
	username := getConfigString(config, "username")
	password := getConfigString(config, "password")
	fromEmail := getConfigString(config, "from_email")
	fromName := getConfigString(config, "from_name")
	useTLS := getConfigBool(config, "use_tls")
	startTLS := getConfigBool(config, "start_tls")
	skipVerify := getConfigBool(config, "skip_tls_verify")
	timeout := time.Duration(getConfigInt(config, "timeout_seconds", 30)) * time.Second

	if host == "" {
		return nil, fmt.Errorf("SMTP host not configured")
	}
	if fromEmail == "" {
		return nil, fmt.Errorf("from_email not configured")
	}

	// Build the email message
	msgID := uuid.New().String()
	boundary := fmt.Sprintf("===%s===", msgID)

	var msgBuilder strings.Builder

	// Headers
	if fromName != "" {
		msgBuilder.WriteString(fmt.Sprintf("From: %s <%s>\r\n", fromName, fromEmail))
	} else {
		msgBuilder.WriteString(fmt.Sprintf("From: %s\r\n", fromEmail))
	}
	msgBuilder.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msgBuilder.WriteString(fmt.Sprintf("Subject: %s\r\n", subject))
	msgBuilder.WriteString(fmt.Sprintf("Message-ID: <%s@%s>\r\n", msgID, host))
	msgBuilder.WriteString("MIME-Version: 1.0\r\n")

	hasAttachments := len(attachments) > 0

	if hasAttachments {
		msgBuilder.WriteString(fmt.Sprintf("Content-Type: multipart/mixed; boundary=\"%s\"\r\n", boundary))
		msgBuilder.WriteString("\r\n")

		// Text part
		if textBody != "" {
			msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msgBuilder.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
			msgBuilder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
			msgBuilder.WriteString(textBody)
			msgBuilder.WriteString("\r\n")
		}

		// HTML part
		if htmlBody != "" {
			msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msgBuilder.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
			msgBuilder.WriteString("Content-Transfer-Encoding: quoted-printable\r\n\r\n")
			msgBuilder.WriteString(htmlBody)
			msgBuilder.WriteString("\r\n")
		}

		// Attachments
		for _, att := range attachments {
			msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", boundary))
			msgBuilder.WriteString(fmt.Sprintf("Content-Type: %s; name=\"%s\"\r\n", att.ContentType, att.Filename))
			msgBuilder.WriteString("Content-Transfer-Encoding: base64\r\n")
			msgBuilder.WriteString(fmt.Sprintf("Content-Disposition: attachment; filename=\"%s\"\r\n\r\n", att.Filename))
			msgBuilder.WriteString(base64.StdEncoding.EncodeToString(att.Data))
			msgBuilder.WriteString("\r\n")
		}

		msgBuilder.WriteString(fmt.Sprintf("--%s--\r\n", boundary))
	} else {
		// Simple multipart/alternative for text+html
		altBoundary := fmt.Sprintf("===alt%s===", msgID)
		msgBuilder.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n", altBoundary))
		msgBuilder.WriteString("\r\n")

		if textBody != "" {
			msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			msgBuilder.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n\r\n")
			msgBuilder.WriteString(textBody)
			msgBuilder.WriteString("\r\n")
		}

		if htmlBody != "" {
			msgBuilder.WriteString(fmt.Sprintf("--%s\r\n", altBoundary))
			msgBuilder.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n\r\n")
			msgBuilder.WriteString(htmlBody)
			msgBuilder.WriteString("\r\n")
		}

		msgBuilder.WriteString(fmt.Sprintf("--%s--\r\n", altBoundary))
	}

	// Connect to SMTP server
	addr := fmt.Sprintf("%s:%d", host, port)
	dialer := &net.Dialer{Timeout: timeout}

	var conn net.Conn
	if useTLS {
		tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("SMTP dial failed: %w", err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return nil, fmt.Errorf("SMTP client init failed: %w", err)
	}
	defer client.Close()

	// STARTTLS if needed
	if !useTLS && startTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: skipVerify}
			if err := client.StartTLS(tlsCfg); err != nil {
				log.Printf("Warning: STARTTLS failed: %v", err)
			}
		}
	}

	// Auth if credentials provided
	if username != "" {
		auth := smtp.PlainAuth("", username, password, host)
		if err := client.Auth(auth); err != nil {
			return nil, fmt.Errorf("SMTP auth failed: %w", err)
		}
	}

	// Send the email
	if err := client.Mail(fromEmail); err != nil {
		return nil, fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err := client.Rcpt(to); err != nil {
		return nil, fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}

	wc, err := client.Data()
	if err != nil {
		return nil, fmt.Errorf("SMTP DATA failed: %w", err)
	}

	if _, err := io.WriteString(wc, msgBuilder.String()); err != nil {
		wc.Close()
		return nil, fmt.Errorf("SMTP write failed: %w", err)
	}
	if err := wc.Close(); err != nil {
		return nil, fmt.Errorf("SMTP close data failed: %w", err)
	}

	// Try to quit gracefully, but don't fail if quit fails
	// Some SMTP servers may not support QUIT or may have already closed the connection
	if err := client.Quit(); err != nil {
		// Log at debug level since this is often expected behavior
		log.Printf("Debug: SMTP quit failed (but email sent successfully): %v", err)
	}

	return &emailDispatchResult{Queued: false, Sent: true, MessageID: msgID}, nil
}

// Helper functions for config parsing
func getConfigString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	val, ok := m[key]
	if !ok || val == nil {
		return ""
	}
	if s, ok := val.(string); ok {
		return strings.TrimSpace(s)
	}
	return fmt.Sprintf("%v", val)
}

func getConfigInt(m map[string]any, key string, defaultVal int) int {
	if m == nil {
		return defaultVal
	}
	val, ok := m[key]
	if !ok || val == nil {
		return defaultVal
	}
	switch v := val.(type) {
	case int:
		return v
	case float64:
		return int(v)
	case string:
		var i int
		fmt.Sscanf(v, "%d", &i)
		return i
	}
	return defaultVal
}

func getConfigBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	val, ok := m[key]
	if !ok || val == nil {
		return false
	}
	if b, ok := val.(bool); ok {
		return b
	}
	return false
}

// sendLicenseEmailToClient sends a license email to the client asynchronously
func (s *Server) sendLicenseEmailToClient(ctx context.Context, clientID string, license *License) {
	log.Printf("📧 Starting license email process for client %s", clientID)

	// Get client information
	client, err := s.lm.GetClient(ctx, clientID)
	if err != nil {
		log.Printf("❌ failed to get client %s for license email: %v", clientID, err)
		return
	}
	log.Printf("📧 Got client info: %s (%s)", client.Name, client.Email)

	// Get product information
	product, err := s.lm.Storage().GetProduct(ctx, license.ProductID)
	if err != nil {
		log.Printf("❌ failed to get product %s for license email: %v", license.ProductID, err)
		return
	}
	log.Printf("📧 Got product info: %s", product.Name)

	// Prepare minimal license data for email (only essential fields)
	minimalLicenseData := map[string]string{
		"email":       client.Email,
		"license_key": license.LicenseKey,
		"client_id":   license.ClientID,
	}
	licenseJSON, err := json.MarshalIndent(minimalLicenseData, "", "  ")
	if err != nil {
		log.Printf("failed to marshal license JSON for email: %v", err)
		return
	}

	// Prepare email template data
	clientLabel := client.Name
	if clientLabel == "" {
		clientLabel = client.Email
	}

	productLabel := product.Name
	if productLabel == "" {
		productLabel = product.Slug
	}

	licenseSubject := fmt.Sprintf("%s license credentials", productLabel)
	jsonBody := string(licenseJSON)

	// Render license email using template
	licenseTemplateData := EmailTemplateData{
		ClientName:  clientLabel,
		ProductName: productLabel,
		Email:       client.Email,
		LicenseJSON: jsonBody,
		SupportURL:  "https://support.example.com",
		DocsURL:     "https://docs.example.com",
	}

	licenseHTML, err := s.emailTemplateLoader.RenderTemplate("license_email", licenseTemplateData)
	if err != nil {
		log.Printf("failed to render license email template: %v", err)
		// Fallback to simple HTML if template rendering fails
		licenseHTML = fmt.Sprintf("<p>Hi %s,</p><p>Here are the license credentials for %s. We have also attached the <code>license.json</code> file to this email for your convenience.</p><pre style=\"padding:12px;background:#0f172a;color:#e2e8f0;border-radius:8px;white-space:pre-wrap;\">%s</pre><p>Keep this file private and secure.</p><p>Thanks,<br/>The Licensing Team</p>", html.EscapeString(clientLabel), html.EscapeString(productLabel), html.EscapeString(jsonBody))
	}

	licenseText := fmt.Sprintf("Hi %s,\n\nHere are the license credentials for %s. We have also attached the license.json file to this email for your convenience.\n\nKeep this file private and secure.\n\nThanks,\nThe Licensing Team", clientLabel, productLabel)

	// Create the JSON file attachment
	licenseAttachment := &email.EmailAttachment{
		Filename:    "license.json",
		ContentType: "application/json",
		Data:        licenseJSON,
		Size:        int64(len(licenseJSON)),
	}

	if res, err := s.sendEmailNow(ctx, client.Email, licenseSubject, licenseHTML, licenseText, []*email.EmailAttachment{licenseAttachment}); err != nil {
		log.Printf("❌ failed to send license email for %s: %v", client.Email, err)
	} else {
		log.Printf("✅ license email sent successfully to %s (message ID: %s)", client.Email, res.MessageID)
	}
}

func (s *Server) decodeClientJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, limit int64) ([]byte, bool) {
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	payload, err := io.ReadAll(body)
	if err != nil {
		s.respondClientError(w, http.StatusBadRequest, "Failed to read request body", nil)
		return nil, false
	}
	fingerprint := strings.TrimSpace(r.Header.Get("X-Device-Fingerprint"))
	licenseKey := strings.TrimSpace(r.Header.Get("X-License-Key"))
	secure := strings.EqualFold(strings.TrimSpace(r.Header.Get("X-License-Secure")), "1")
	var transportKey []byte
	if secure {
		if fingerprint == "" || licenseKey == "" {
			s.respondClientError(w, http.StatusBadRequest, "Secure payload missing fingerprint or license key", nil)
			return nil, false
		}
		key, err := s.lm.getDeviceTransportKey(r.Context(), licenseKey, fingerprint)
		if err != nil {
			s.respondClientError(w, http.StatusUnauthorized, "Device not authorized for secure transport", nil)
			return nil, false
		}
		transportKey = key
		var envelope utils.SecureEnvelope
		if err := json.Unmarshal(payload, &envelope); err != nil {
			s.respondClientError(w, http.StatusBadRequest, "Invalid secure envelope", nil)
			return nil, false
		}
		payload, err = utils.DecryptEnvelope(transportKey, &envelope)
		if err != nil {
			s.respondClientError(w, http.StatusBadRequest, "Failed to decrypt payload", nil)
			return nil, false
		}
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		s.respondClientError(w, http.StatusBadRequest, "Invalid request body", transportKey, map[string]interface{}{
			"expected":         "Valid JSON object",
			"error_type":       "json_decode_failed",
			"parse_error":      err.Error(),
			"suggested_action": "Ensure the request body contains valid JSON",
		})
		return nil, false
	}
	return transportKey, true
}

func (s *Server) withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		w.Header().Set("X-Request-ID", uuid.New().String())
		next.ServeHTTP(w, r)
	})
}

func envBoolDefault(key string, defaultVal bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return defaultVal
	}
	switch strings.ToLower(raw) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func (s *Server) initAuditLogger() error {
	if !envBoolDefault("LICENSE_SERVER_AUDIT_ENABLED", true) {
		return nil
	}
	auditPath := strings.TrimSpace(os.Getenv("LICENSE_SERVER_AUDIT_DB_PATH"))
	if auditPath == "" {
		if sqlitePath := strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_SQLITE_PATH")); sqlitePath != "" {
			auditPath = sqlitePath
		} else if homeDir, err := os.UserHomeDir(); err == nil {
			auditPath = filepath.Join(homeDir, ".licensing", "data", "audit.db")
		} else {
			auditPath = "./data/audit.db"
		}
	}
	if err := os.MkdirAll(filepath.Dir(auditPath), 0o700); err != nil {
		return fmt.Errorf("create audit directory: %w", err)
	}
	db, err := sql.Open("sqlite", auditPath)
	if err != nil {
		return fmt.Errorf("open audit sqlite db: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	storage, err := audit.NewSQLiteStorage(db)
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("initialize audit storage: %w", err)
	}
	bufferSize := 2000
	if raw := strings.TrimSpace(os.Getenv("LICENSE_SERVER_AUDIT_BUFFER_SIZE")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 {
			bufferSize = parsed
		}
	}
	logger, err := audit.NewAuditLogger(&audit.AuditLoggerConfig{
		Storage:        storage,
		Async:          envBoolDefault("LICENSE_SERVER_AUDIT_ASYNC", true),
		BufferSize:     bufferSize,
		EnableChaining: envBoolDefault("LICENSE_SERVER_AUDIT_CHAINING", true),
	})
	if err != nil {
		_ = db.Close()
		return fmt.Errorf("initialize audit logger: %w", err)
	}
	s.auditLogger = logger
	s.auditDB = db
	s.auditIncludePing = envBoolDefault("LICENSE_SERVER_AUDIT_INCLUDE_HEALTH", false)
	log.Printf("🧾 Audit logging enabled (sqlite: %s)", auditPath)
	return nil
}

func (s *Server) auditLog(ctx context.Context, event *audit.Event) {
	if s.auditLogger == nil || event == nil {
		return
	}
	if err := s.auditLogger.Log(ctx, event); err != nil {
		log.Printf("failed to write audit event: %v", err)
	}
}

func (s *Server) resolveAuditActor(r *http.Request) (string, string) {
	if r == nil {
		return "anonymous", "unknown"
	}
	providedKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if providedKey != "" {
		if rec, err := s.lm.ValidateAPIKey(r.Context(), providedKey); err == nil {
			return rec.ID, "admin_api_key"
		}
	}
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth != "" {
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			token := strings.TrimSpace(parts[1])
			if token != "" {
				if rec, err := s.lm.ValidateAPIKey(r.Context(), token); err == nil {
					return rec.ID, "admin_api_key"
				}
			}
		}
	}
	if s.sessionValidator != nil {
		if cookie, err := r.Cookie("session_id"); err == nil && cookie.Value != "" {
			if userID, _, ok := s.sessionValidator.ValidateSession(cookie.Value); ok {
				return userID, "admin_session"
			}
		}
	}
	return "anonymous", "unknown"
}

func (s *Server) withAudit(next http.Handler) http.Handler {
	if s.auditLogger == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.auditIncludePing && (r.URL.Path == "/health" || r.URL.Path == "/metrics") {
			next.ServeHTTP(w, r)
			return
		}
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		actorID, actorType := s.resolveAuditActor(r)
		result := "success"
		severity := audit.SeverityInfo
		if status >= 400 {
			result = "failure"
			severity = audit.SeverityWarning
		}
		if status >= 500 {
			severity = audit.SeverityError
		}
		event := audit.NewEvent(audit.EventAPIRequest, severity, "http_request", fmt.Sprintf("%s %s", r.Method, r.URL.Path)).
			WithActor(actorID, actorType, clientIP(r)).
			WithResult(result).
			WithRequest(uuid.New().String(), "", r.UserAgent()).
			WithMetadata("method", r.Method).
			WithMetadata("path", r.URL.Path).
			WithMetadata("status_code", status).
			WithMetadata("duration_ms", time.Since(start).Milliseconds()).
			WithMetadata("response_bytes", rec.bytes)
		s.auditLog(r.Context(), event)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (sr *statusRecorder) Write(p []byte) (int, error) {
	if sr.status == 0 {
		sr.status = http.StatusOK
	}
	n, err := sr.ResponseWriter.Write(p)
	sr.bytes += n
	return n, err
}

func (s *Server) withMetrics(next http.Handler) http.Handler {
	if s.metrics == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		s.metrics.requestsTotal.Add(1)
		s.metrics.requestsLive.Add(1)
		defer s.metrics.requestsLive.Add(^uint64(0))

		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)

		status := rec.status
		if status == 0 {
			status = http.StatusOK
		}
		switch {
		case status >= 500:
			s.metrics.requests5xx.Add(1)
		case status >= 400:
			s.metrics.requests4xx.Add(1)
		default:
			s.metrics.requests2xx.Add(1)
		}
		s.metrics.responseBytes.Add(uint64(rec.bytes))
		s.metrics.latencyNanos.Add(uint64(time.Since(start).Nanoseconds()))
	})
}

func metricsEnabled() bool {
	raw := strings.TrimSpace(os.Getenv("LICENSE_SERVER_METRICS_ENABLED"))
	if raw != "" {
		switch strings.ToLower(raw) {
		case "1", "true", "yes", "on":
			return true
		default:
			return false
		}
	}
	env := strings.ToLower(strings.TrimSpace(os.Getenv("APP_ENV")))
	if env == "prod" || env == "production" {
		return false
	}
	return true
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	if s.metrics == nil {
		http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
		return
	}
	total := s.metrics.requestsTotal.Load()
	latencyNanos := s.metrics.latencyNanos.Load()
	avgLatency := 0.0
	if total > 0 {
		avgLatency = (float64(latencyNanos) / float64(total)) / float64(time.Second)
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP licensing_http_requests_total Total HTTP requests handled.\n")
	fmt.Fprintf(w, "# TYPE licensing_http_requests_total counter\n")
	fmt.Fprintf(w, "licensing_http_requests_total %d\n", total)
	fmt.Fprintf(w, "# HELP licensing_http_requests_in_flight Current in-flight HTTP requests.\n")
	fmt.Fprintf(w, "# TYPE licensing_http_requests_in_flight gauge\n")
	fmt.Fprintf(w, "licensing_http_requests_in_flight %d\n", s.metrics.requestsLive.Load())
	fmt.Fprintf(w, "# HELP licensing_http_requests_2xx_total Total successful HTTP requests.\n")
	fmt.Fprintf(w, "# TYPE licensing_http_requests_2xx_total counter\n")
	fmt.Fprintf(w, "licensing_http_requests_2xx_total %d\n", s.metrics.requests2xx.Load())
	fmt.Fprintf(w, "# HELP licensing_http_requests_4xx_total Total client error HTTP requests.\n")
	fmt.Fprintf(w, "# TYPE licensing_http_requests_4xx_total counter\n")
	fmt.Fprintf(w, "licensing_http_requests_4xx_total %d\n", s.metrics.requests4xx.Load())
	fmt.Fprintf(w, "# HELP licensing_http_requests_5xx_total Total server error HTTP requests.\n")
	fmt.Fprintf(w, "# TYPE licensing_http_requests_5xx_total counter\n")
	fmt.Fprintf(w, "licensing_http_requests_5xx_total %d\n", s.metrics.requests5xx.Load())
	fmt.Fprintf(w, "# HELP licensing_http_response_bytes_total Total bytes written in HTTP responses.\n")
	fmt.Fprintf(w, "# TYPE licensing_http_response_bytes_total counter\n")
	fmt.Fprintf(w, "licensing_http_response_bytes_total %d\n", s.metrics.responseBytes.Load())
	fmt.Fprintf(w, "# HELP licensing_http_request_duration_seconds_avg Average request duration in seconds.\n")
	fmt.Fprintf(w, "# TYPE licensing_http_request_duration_seconds_avg gauge\n")
	fmt.Fprintf(w, "licensing_http_request_duration_seconds_avg %f\n", avgLatency)
	fmt.Fprintf(w, "# HELP licensing_process_uptime_seconds Process uptime in seconds.\n")
	fmt.Fprintf(w, "# TYPE licensing_process_uptime_seconds gauge\n")
	fmt.Fprintf(w, "licensing_process_uptime_seconds %d\n", int64(time.Since(s.metrics.startedAt).Seconds()))
	fmt.Fprintf(w, "# HELP licensing_process_goroutines Number of goroutines.\n")
	fmt.Fprintf(w, "# TYPE licensing_process_goroutines gauge\n")
	fmt.Fprintf(w, "licensing_process_goroutines %d\n", runtime.NumGoroutine())
}

func (s *Server) getAllowedOrigins() []string {
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

func (s *Server) isOriginAllowed(origin string) bool {
	if origin == "" {
		return true
	}

	allowedOrigins := s.getAllowedOrigins()
	for _, allowedOrigin := range allowedOrigins {
		if allowedOrigin == origin {
			return true
		}
	}
	return false
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Handle CORS with proper origin handling for credentialed requests
		origin := r.Header.Get("Origin")

		// If no origin, allow any (for non-browser clients)
		if origin == "" {
			origin = "*"
		} else if !s.isOriginAllowed(origin) {
			// If origin is not allowed, don't set CORS headers
			next.ServeHTTP(w, r)
			return
		}

		// Set CORS headers
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

		next.ServeHTTP(w, r)
	})
}

func setSecurityHeaders(w http.ResponseWriter) {
	headers := w.Header()
	headers.Set("X-Content-Type-Options", "nosniff")
	headers.Set("X-Frame-Options", "DENY")
	headers.Set("Referrer-Policy", "no-referrer")
	headers.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'")
	headers.Set("Permissions-Policy", "geolocation=()")
	headers.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
	headers.Set("Cache-Control", "no-store")
}

func (s *Server) hasTLSConfig() bool {
	return s.tlsCertPath != "" && s.tlsKeyPath != ""
}

func (s *Server) buildTLSConfig() (*tls.Config, error) {
	config := &tls.Config{MinVersion: tls.VersionTLS12}
	if s.clientCAPath != "" {
		caBytes, err := os.ReadFile(s.clientCAPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("failed to parse client CA certificate")
		}
		config.ClientCAs = pool
		config.ClientAuth = tls.RequireAndVerifyClientCert
	}
	return config, nil
}

func (s *Server) handleActivate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondClientError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}

	var req ActivationRequest
	transportKey, ok := s.decodeClientJSONBody(w, r, &req, maxActivationPayloadBytes)
	if !ok {
		return
	}
	if err := validateActivationRequest(&req); err != nil {
		s.respondClientError(w, http.StatusBadRequest, err.Error(), transportKey)
		return
	}
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	req.IPAddress = clientIP(r)
	req.UserAgent = r.UserAgent()

	resp, err := s.lm.ActivateLicense(r.Context(), &req)
	if err != nil {
		s.respondClientError(w, http.StatusInternalServerError, err.Error(), transportKey)
		return
	}
	s.respondClientJSON(w, http.StatusOK, resp, transportKey)
}

// --- Client session helpers ---
func (s *Server) createClientSession(_ context.Context, clientID, ip, ua string) (*ClientSession, error) {
	s.clientSessionsMu.Lock()
	defer s.clientSessionsMu.Unlock()
	sid := uuid.New().String()
	// Generate refresh token
	rtb := make([]byte, 32)
	if _, err := rand.Read(rtb); err != nil {
		return nil, err
	}
	refresh := base64.RawURLEncoding.EncodeToString(rtb)
	now := time.Now()
	sess := &ClientSession{
		ID:           sid,
		ClientID:     clientID,
		RefreshToken: refresh,
		CreatedAt:    now,
		ExpiresAt:    now.Add(7 * 24 * time.Hour),
		IPAddress:    ip,
		UserAgent:    ua,
	}
	if s.clientSessions == nil {
		s.clientSessions = map[string]*ClientSession{}
	}
	s.clientSessions[sid] = sess
	return sess, nil
}

func (s *Server) getClientSessionByID(sessionID string) (*ClientSession, bool) {
	s.clientSessionsMu.RLock()
	defer s.clientSessionsMu.RUnlock()
	if s.clientSessions == nil {
		return nil, false
	}
	sess, ok := s.clientSessions[sessionID]
	if !ok || sess == nil {
		return nil, false
	}
	if sess.Revoked || time.Now().After(sess.ExpiresAt) {
		return nil, false
	}
	return sess, true
}

func (s *Server) findClientSessionByRefreshToken(refresh string) (*ClientSession, bool) {
	s.clientSessionsMu.RLock()
	defer s.clientSessionsMu.RUnlock()
	for _, sess := range s.clientSessions {
		if sess != nil && sess.RefreshToken == refresh && !sess.Revoked && time.Now().Before(sess.ExpiresAt) {
			return sess, true
		}
	}
	return nil, false
}

func (s *Server) revokeClientSession(sessionID string) {
	s.clientSessionsMu.Lock()
	defer s.clientSessionsMu.Unlock()
	if s.clientSessions == nil {
		return
	}
	if s.clientSessions[sessionID] != nil {
		s.clientSessions[sessionID].Revoked = true
	}
}

// getClientFromRequest authenticates a client via Authorization:Bareer <session id>
func (s *Server) getClientFromRequest(r *http.Request) (*Client, *ClientSession, error) {
	// Prefer explicit client API key header
	providedKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if providedKey != "" {
		if client, _, err := s.lm.ValidateClientAPIKey(r.Context(), providedKey); err == nil {
			return client, nil, nil
		}
	}

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if auth == "" {
		// try cookie
		cookie, err := r.Cookie("client_session")
		if err != nil || cookie.Value == "" {
			return nil, nil, fmt.Errorf("missing auth")
		}
		auth = cookie.Value
	} else {
		// Expect: Bearer <token>
		parts := strings.SplitN(auth, " ", 2)
		if len(parts) == 2 && strings.EqualFold(parts[0], "Bearer") {
			auth = parts[1]
		}
	}
	if auth == "" {
		return nil, nil, fmt.Errorf("missing auth token")
	}
	// Try to interpret the auth token as a client session ID first; if that fails, try it as a client API key.
	sess, ok := s.getClientSessionByID(auth)
	if ok {
		client, err := s.lm.GetClient(r.Context(), sess.ClientID)
		if err != nil {
			return nil, nil, err
		}
		return client, sess, nil
	}
	// Try API key as fallback
	if client, _, err := s.lm.ValidateClientAPIKey(r.Context(), auth); err == nil {
		return client, nil, nil
	}
	return nil, nil, fmt.Errorf("invalid or expired session")
}

// --- Client auth handlers ---
func (s *Server) handleClientRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	var req struct {
		Email    string `json:"email"`
		Username string `json:"username,omitempty"`
		Password string `json:"password"`
		Name     string `json:"name,omitempty"`
		Company  string `json:"company_name,omitempty"`
	}
	if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
		return
	}
	if req.Email == "" || req.Password == "" {
		s.respondError(w, http.StatusBadRequest, "email and password are required")
		return
	}
	// Create client with password
	client, err := s.lm.CreateClientWithPassword(r.Context(), strings.TrimSpace(req.Email), req.Password, strings.TrimSpace(req.Username), req.Name, req.Company)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Create session for the newly registered client
	cp := clientIP(r)
	sess, err := s.createClientSession(r.Context(), client.ID, cp, r.UserAgent())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	// Set cookie
	http.SetCookie(w, &http.Cookie{Name: "client_session", Value: sess.ID, Path: "/", HttpOnly: true, Secure: isSecureRequest(r), Expires: sess.ExpiresAt})
	// Return client with session info
	s.respondJSON(w, http.StatusCreated, map[string]interface{}{"client": client, "session": sess})
}

func (s *Server) handleClientLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	var req struct {
		Email    string `json:"email,omitempty"`
		Username string `json:"username,omitempty"`
		Password string `json:"password"`
	}
	if !s.decodeJSONBody(w, r, &req, maxActivationPayloadBytes) {
		return
	}
	client, err := func() (*Client, error) {
		if strings.TrimSpace(req.Username) != "" {
			return s.lm.VerifyClientPasswordByUsername(r.Context(), strings.TrimSpace(req.Username), req.Password)
		}
		return s.lm.VerifyClientPassword(r.Context(), strings.TrimSpace(req.Email), req.Password)
	}()
	if err != nil {
		s.respondError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	cp := clientIP(r)
	sess, err := s.createClientSession(r.Context(), client.ID, cp, r.UserAgent())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to create session")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "client_session", Value: sess.ID, Path: "/", HttpOnly: true, Secure: isSecureRequest(r), Expires: sess.ExpiresAt})
	// Response includes a refresh token that can be used by the client (if desired)
	s.respondJSON(w, http.StatusOK, map[string]interface{}{"client": client, "session": sess})
}

func (s *Server) handleClientLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	client, sess, err := s.getClientFromRequest(r)
	if err != nil {
		s.respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.revokeClientSession(sess.ID)
	// Clear cookie
	http.SetCookie(w, &http.Cookie{Name: "client_session", Value: "", Path: "/", HttpOnly: true, Secure: isSecureRequest(r), Expires: time.Now().Add(-1 * time.Hour)})
	s.respondJSON(w, http.StatusOK, map[string]interface{}{"message": "logged out", "client": client.ID})
}

func (s *Server) handleClientKeys(w http.ResponseWriter, r *http.Request) {
	// Authenticate client
	client, _, err := s.getClientFromRequest(r)
	if err != nil {
		s.respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	// Accept both /api/client/keys and /api/client/keys/{keyID}
	tail := strings.TrimPrefix(r.URL.Path, "/api/client/keys")
	tail = strings.Trim(tail, "/")

	switch r.Method {
	case http.MethodGet:
		// list keys for this client
		keys, err := s.lm.ListAPIKeysByClient(r.Context(), client.ID)
		if err != nil {
			s.respondClientError(w, http.StatusInternalServerError, err.Error(), nil)
			return
		}
		resp := make([]apiKeyMetadata, 0, len(keys))
		for _, k := range keys {
			resp = append(resp, newAPIKeyMetadata(k))
		}
		if resp == nil {
			resp = []apiKeyMetadata{}
		}
		s.respondClientJSON(w, http.StatusOK, resp, nil)
		return
	case http.MethodPost:
		// create a new key for this client
		token, record, err := s.lm.GenerateClientAPIKey(r.Context(), client.ID)
		if err != nil {
			s.respondClientError(w, http.StatusBadRequest, err.Error(), nil)
			return
		}
		s.respondClientJSON(w, http.StatusCreated, map[string]interface{}{"token": token, "metadata": newAPIKeyMetadata(record)}, nil)
		return
	case http.MethodDelete:
		if tail == "" {
			s.respondClientError(w, http.StatusBadRequest, "api key id required", nil)
			return
		}
		keyID := tail
		// Ensure the key belongs to this client
		// First fetch key by checking ListAPIKeysByClient
		keys, err := s.lm.ListAPIKeysByClient(r.Context(), client.ID)
		if err != nil {
			s.respondClientError(w, http.StatusInternalServerError, err.Error(), nil)
			return
		}
		found := false
		for _, k := range keys {
			if k.ID == keyID {
				found = true
				break
			}
		}
		if !found {
			s.respondClientError(w, http.StatusNotFound, "api key not found", nil)
			return
		}
		if err := s.lm.DeleteAPIKey(r.Context(), keyID); err != nil {
			s.respondClientError(w, http.StatusInternalServerError, err.Error(), nil)
			return
		}
		s.respondClientJSON(w, http.StatusOK, map[string]string{"message": "api key deleted"}, nil)
		return
	default:
		s.respondClientError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
}

func (s *Server) handleClientProfile(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	client, _, err := s.getClientFromRequest(r)
	if err != nil {
		s.respondError(w, http.StatusUnauthorized, "unauthorized")
		return
	}
	s.respondJSON(w, http.StatusOK, client)
}

func (s *Server) handleClientRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if !s.decodeJSONBody(w, r, &req, maxActivationPayloadBytes) {
		return
	}
	if strings.TrimSpace(req.RefreshToken) == "" {
		s.respondError(w, http.StatusBadRequest, "refresh_token is required")
		return
	}
	oldSess, ok := s.findClientSessionByRefreshToken(req.RefreshToken)
	if !ok || oldSess == nil {
		s.respondError(w, http.StatusUnauthorized, "invalid refresh token")
		return
	}
	// Create a new session (rotate)
	newSess, err := s.createClientSession(r.Context(), oldSess.ClientID, clientIP(r), r.UserAgent())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "failed to refresh session")
		return
	}
	// Revoke old session
	s.revokeClientSession(oldSess.ID)
	// Return new session details
	http.SetCookie(w, &http.Cookie{Name: "client_session", Value: newSess.ID, Path: "/", HttpOnly: true, Secure: isSecureRequest(r), Expires: newSess.ExpiresAt})
	client, _ := s.lm.GetClient(r.Context(), newSess.ClientID)
	s.respondJSON(w, http.StatusOK, map[string]interface{}{"client": client, "session": newSess})
}

// Offline token generation - admin-only for now
func (s *Server) handleGenerateOfflineToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	var req struct {
		LicenseKey        string `json:"license_key"`
		DeviceFingerprint string `json:"device_fingerprint"`
		MaxUses           int    `json:"max_uses"`
		ValidityDays      int    `json:"validity_days"`
	}
	if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
		return
	}
	if req.ValidityDays <= 0 {
		req.ValidityDays = 30
	}
	if req.MaxUses <= 0 {
		req.MaxUses = 30
	}
	token, signedBundle, err := s.lm.GenerateOfflineValidationToken(r.Context(), req.LicenseKey, req.DeviceFingerprint, req.MaxUses, req.ValidityDays)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	// Return the offline token object at the top-level. If a signed bundle was
	// generated, include it as `signed_bundle` alongside the token fields so
	// callers that unmarshal directly into OfflineValidationToken continue to
	// work and callers that want the signed bundle can read it too.
	if signedBundle == "" {
		s.respondJSON(w, http.StatusCreated, token)
		return
	}

	// Merge token fields and the signed bundle into a single top-level object
	var tokenMap map[string]interface{}
	tb, _ := json.Marshal(token)
	_ = json.Unmarshal(tb, &tokenMap)
	tokenMap["signed_bundle"] = json.RawMessage(signedBundle)
	s.respondJSON(w, http.StatusCreated, tokenMap)
}

// Public endpoint exposing the active offline signing public key
func (s *Server) handleGetActiveSigningPublicKey(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	// Prefer the configured offline signer provider for the public key; fall back to storage
	var keyID string
	var pub []byte
	if s.lm != nil && s.lm.offlineSigner != nil {
		if id, err := s.lm.offlineSigner.ActiveKeyID(); err == nil {
			keyID = id
			if b, err2 := s.lm.offlineSigner.PublicKey(id); err2 == nil {
				pub = b
			}
		}
	}
	if keyID == "" || len(pub) == 0 {
		storage := s.lm.Storage()
		if storage == nil {
			s.respondError(w, http.StatusInternalServerError, "storage backend unavailable")
			return
		}
		key, err := storage.GetActiveSigningKey(r.Context())
		if err != nil {
			s.respondError(w, http.StatusNotFound, err.Error())
			return
		}
		keyID = key.ID
		pub = key.PublicKey
	}
	resp := map[string]string{"key_id": keyID, "public_key": base64.StdEncoding.EncodeToString(pub)}
	s.respondJSON(w, http.StatusOK, resp)
}

// GET /api/keys/offline-signing-public/{id}
// Returns the public key for a specific signing key id.
func (s *Server) handleGetSigningPublicKeyByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/keys/offline-signing-public/")
	id = strings.TrimSpace(id)
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "signing key id required")
		return
	}

	storage := s.lm.Storage()
	if storage == nil {
		s.respondError(w, http.StatusInternalServerError, "storage backend unavailable")
		return
	}

	key, err := storage.GetSigningKey(r.Context(), id)
	if err != nil {
		s.respondError(w, http.StatusNotFound, err.Error())
		return
	}
	if len(key.PublicKey) == 0 {
		s.respondError(w, http.StatusNotFound, "public key not available for requested id")
		return
	}

	resp := map[string]string{"key_id": key.ID, "public_key": base64.StdEncoding.EncodeToString(key.PublicKey)}
	s.respondJSON(w, http.StatusOK, resp)
}

// handleGetRevocationManifest returns a signed revocation manifest clients can use
// Manifest includes revoked offline tokens and revoked license keys, optionally filtered by 'since' ISO timestamp
func (s *Server) handleGetRevocationManifest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}

	since := strings.TrimSpace(r.URL.Query().Get("since"))
	var sinceTime time.Time
	var err error
	if since != "" {
		sinceTime, err = time.Parse(time.RFC3339, since)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, "invalid since timestamp")
			return
		}
	}

	storage := s.lm.Storage()
	if storage == nil {
		s.respondError(w, http.StatusInternalServerError, "storage backend unavailable")
		return
	}

	// collect revoked offline tokens
	tokens, err := storage.ListOfflineValidationTokens(r.Context())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	revokedTokens := make([]map[string]interface{}, 0)
	for _, t := range tokens {
		if t.IsRevoked {
			if !sinceTime.IsZero() && t.RevokedAt.IsZero() {
				continue
			}
			if !sinceTime.IsZero() && t.RevokedAt.Before(sinceTime) {
				continue
			}
			revokedTokens = append(revokedTokens, map[string]interface{}{
				"token":       t.Token,
				"license_key": t.LicenseKey,
				"revoked_at":  t.RevokedAt,
			})
		}
	}

	// collect revoked licenses
	licenses, err := s.lm.ListLicenses(r.Context())
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	revokedLicenses := make([]map[string]interface{}, 0)
	for _, lic := range licenses {
		if lic.IsRevoked {
			if !sinceTime.IsZero() && lic.RevokedAt.IsZero() {
				continue
			}
			if !sinceTime.IsZero() && lic.RevokedAt.Before(sinceTime) {
				continue
			}
			revokedLicenses = append(revokedLicenses, map[string]interface{}{
				"license_key": lic.LicenseKey,
				"revoked_at":  lic.RevokedAt,
			})
		}
	}

	manifest := map[string]interface{}{
		"version":                "1",
		"generated_at":           time.Now().UTC().Format(time.RFC3339),
		"revoked_offline_tokens": revokedTokens,
		"revoked_licenses":       revokedLicenses,
	}

	// Sign manifest if possible using offline signer
	var signature string
	var keyID string
	if s.lm != nil && s.lm.offlineSigner != nil {
		if id, err := s.lm.offlineSigner.ActiveKeyID(); err == nil {
			keyID = id
			payload, _ := json.Marshal(manifest)
			if sig, err := s.lm.offlineSigner.Sign(id, payload); err == nil {
				signature = base64.StdEncoding.EncodeToString(sig)
			}
		}
	} else {
		// fallback to storage stored keys
		if activeKey, err := s.lm.Storage().GetActiveSigningKey(r.Context()); err == nil && len(activeKey.PrivateKey) > 0 {
			p, _ := json.Marshal(manifest)
			sig := ed25519.Sign(ed25519.PrivateKey(activeKey.PrivateKey), p)
			signature = base64.StdEncoding.EncodeToString(sig)
			keyID = activeKey.ID
		}
	}

	resp := map[string]interface{}{
		"manifest": manifest,
	}
	if signature != "" {
		resp["signature"] = signature
		resp["signing_key_id"] = keyID
	}

	s.respondJSON(w, http.StatusOK, resp)
}

// Admin endpoints to manage signing keys
func (s *Server) handleAdminSigningKeys(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		keys, err := s.lm.Storage().ListSigningKeys(r.Context())
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Respond with public info only
		out := make([]map[string]interface{}, 0, len(keys))
		for _, k := range keys {
			out = append(out, map[string]interface{}{
				"id":         k.ID,
				"name":       k.Name,
				"public_key": base64.StdEncoding.EncodeToString(k.PublicKey),
				"is_active":  k.IsActive,
				"created_at": k.CreatedAt,
			})
		}
		s.respondJSON(w, http.StatusOK, out)
	case http.MethodPost:
		var req struct {
			Name     string `json:"name,omitempty"`
			Activate bool   `json:"activate,omitempty"`
		}
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		// Generate an ed25519 key pair
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		key := &SigningKey{
			ID:         uuid.New().String(),
			Name:       strings.TrimSpace(req.Name),
			PublicKey:  pub,
			PrivateKey: priv,
			IsActive:   req.Activate,
			CreatedAt:  time.Now().UTC(),
		}
		if err := s.lm.Storage().SaveSigningKey(r.Context(), key); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if req.Activate {
			if err := s.lm.Storage().SetActiveSigningKey(r.Context(), key.ID); err != nil {
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
		}
		s.respondJSON(w, http.StatusCreated, map[string]interface{}{
			"id":         key.ID,
			"name":       key.Name,
			"public_key": base64.StdEncoding.EncodeToString(key.PublicKey),
			"is_active":  key.IsActive,
			"created_at": key.CreatedAt,
		})
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminSigningKeyActions(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/admin/signing-keys/")
	id := strings.TrimSpace(path)
	if id == "" {
		s.respondError(w, http.StatusBadRequest, "signing key id is required")
		return
	}

	switch r.Method {
	case http.MethodPost:
		// only action supported today: activate
		q := strings.TrimSpace(r.URL.Query().Get("action"))
		if q == "activate" {
			if err := s.lm.Storage().SetActiveSigningKey(r.Context(), id); err != nil {
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.respondJSON(w, http.StatusOK, map[string]string{"message": "activated"})
			return
		}
		s.respondError(w, http.StatusBadRequest, "action is required (e.g. action=activate)")
	case http.MethodDelete:
		// delete (remove key)
		// Note: For now we only allow removing (deleting) a key by id if found
		if err := s.lm.Storage().SetActiveSigningKey(r.Context(), ""); err != nil {
			// ignore
		}
		// No direct delete storage method implemented — fall back to SetActiveSigningKey empty
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "delete not implemented; set inactive via POST?action=activate on another key"})
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

// Offline token validation - open endpoint that validates a provided token
func (s *Server) handleValidateOfflineToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	var req struct {
		OfflineToken      string `json:"offline_token"`
		DeviceFingerprint string `json:"device_fingerprint"`
	}
	if !s.decodeJSONBody(w, r, &req, maxActivationPayloadBytes) {
		return
	}
	license, token, err := s.lm.ValidateOfflineToken(r.Context(), strings.TrimSpace(req.OfflineToken), strings.TrimSpace(req.DeviceFingerprint))
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	resp := map[string]interface{}{
		"license": license,
		"token":   token,
		"success": true,
	}
	s.respondJSON(w, http.StatusOK, resp)
}

// List offline tokens - admin-only. Optional query params: license_key or client_id
func (s *Server) handleListOfflineTokens(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	licenseKey := strings.TrimSpace(q.Get("license_key"))
	clientID := strings.TrimSpace(q.Get("client_id"))
	var tokens []*OfflineValidationToken
	var err error
	if licenseKey != "" {
		tokens, err = s.lm.ListOfflineValidationTokens(r.Context(), licenseKey)
	} else if clientID != "" {
		tokens, err = s.lm.ListOfflineValidationTokensByClient(r.Context(), clientID)
	} else {
		tokens, err = s.lm.Storage().ListOfflineValidationTokens(r.Context())
	}
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if tokens == nil {
		tokens = []*OfflineValidationToken{}
	}
	s.respondJSON(w, http.StatusOK, tokens)
}

// List offline validation logs - admin-only. Optional params: token, license_key, client_id
func (s *Server) handleListOfflineLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	q := r.URL.Query()
	token := strings.TrimSpace(q.Get("token"))
	licenseKey := strings.TrimSpace(q.Get("license_key"))
	clientID := strings.TrimSpace(q.Get("client_id"))
	var logs []*OfflineValidationLog
	var err error
	if token != "" {
		logs, err = s.lm.GetOfflineValidationLogs(r.Context(), token)
	} else if licenseKey != "" {
		logs, err = s.lm.GetOfflineValidationLogsByLicense(r.Context(), licenseKey)
	} else if clientID != "" {
		logs, err = s.lm.GetOfflineValidationLogsByClient(r.Context(), clientID)
	} else {
		s.respondError(w, http.StatusBadRequest, "token, license_key, or client_id is required")
		return
	}
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if logs == nil {
		logs = []*OfflineValidationLog{}
	}
	s.respondJSON(w, http.StatusOK, logs)
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondClientError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}
	var req ActivationRequest
	transportKey, ok := s.decodeClientJSONBody(w, r, &req, maxActivationPayloadBytes)
	if !ok {
		return
	}
	if err := validateActivationRequest(&req); err != nil {
		s.respondClientError(w, http.StatusBadRequest, err.Error(), transportKey)
		return
	}
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	req.IPAddress = clientIP(r)
	req.UserAgent = r.UserAgent()
	resp, err := s.lm.VerifyLicense(r.Context(), &req)
	if err != nil {
		s.respondClientError(w, http.StatusInternalServerError, err.Error(), transportKey)
		return
	}
	s.respondClientJSON(w, http.StatusOK, resp, transportKey)
}

func (s *Server) handleTrial(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondClientError(w, http.StatusMethodNotAllowed, "Method not allowed", nil)
		return
	}
	if !s.enforceClientRateLimit(w, r) {
		return
	}

	var req trialLicenseAPIRequest
	if !s.decodeJSONBody(w, r, &req, maxActivationPayloadBytes) {
		return
	}

	trialReq := &TrialLicenseRequest{
		Email:             req.Email,
		DeviceFingerprint: req.DeviceFingerprint,
		ProductID:         req.ProductID,
		TrialDurationDays: req.TrialDurationDays,
		SubscriptionURL:   req.SubscriptionURL,
	}

	resp, err := s.lm.GenerateTrialLicense(r.Context(), trialReq)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	if !resp.Success {
		status := http.StatusOK
		if resp.AlreadyUsed {
			status = http.StatusConflict
		}
		s.respondJSON(w, status, resp)
		return
	}

	s.respondJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleTrialCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}

	var fingerprint string
	if r.Method == http.MethodGet {
		fingerprint = strings.TrimSpace(r.URL.Query().Get("device_fingerprint"))
	} else {
		var req struct {
			DeviceFingerprint string `json:"device_fingerprint"`
		}
		if !s.decodeJSONBody(w, r, &req, maxActivationPayloadBytes) {
			return
		}
		fingerprint = strings.TrimSpace(req.DeviceFingerprint)
	}

	if fingerprint == "" {
		s.respondError(w, http.StatusBadRequest, "device_fingerprint is required")
		return
	}

	hasUsed, err := s.lm.HasDeviceUsedTrial(r.Context(), fingerprint)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	resp := map[string]interface{}{
		"device_fingerprint": fingerprint,
		"trial_used":         hasUsed,
		"eligible_for_trial": !hasUsed,
	}

	if hasUsed {
		trial, err := s.lm.GetDeviceTrial(r.Context(), fingerprint)
		if err == nil {
			resp["trial_started_at"] = trial.TrialStartedAt
			resp["trial_expires_at"] = trial.TrialExpiresAt
			resp["trial_expired"] = time.Now().After(trial.TrialExpiresAt)
		}
	}

	s.respondJSON(w, http.StatusOK, resp)
}

// SubscribeRequest represents a subscription creation request.
type SubscribeRequest struct {
	Email        string            `json:"email"`
	ProductID    string            `json:"product_id"`
	PlanID       string            `json:"plan_id"`
	StartDate    string            `json:"start_date,omitempty"`    // ISO 8601 format, defaults to now
	DurationDays int               `json:"duration_days,omitempty"` // Overrides billing cycle if set
	MaxDevices   int               `json:"max_devices,omitempty"`   // Defaults to 1
	SendEmail    bool              `json:"send_email,omitempty"`    // Send welcome email to customer
	IsTrial      bool              `json:"is_trial,omitempty"`      // Force trial mode regardless of plan
	Metadata     map[string]string `json:"metadata,omitempty"`      // Additional metadata
}

func (s *Server) handleSubscribe(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	var req SubscribeRequest
	if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
		return
	}

	email := strings.TrimSpace(req.Email)
	productID := strings.TrimSpace(req.ProductID)
	planID := strings.TrimSpace(req.PlanID)

	if email == "" || productID == "" || planID == "" {
		s.respondError(w, http.StatusBadRequest, "email, product_id, and plan_id are required")
		return
	}

	ctx := r.Context()

	// Verify product exists
	product, err := s.lm.Storage().GetProduct(ctx, productID)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, "product not found")
		return
	}

	// Verify plan exists and belongs to product
	plan, err := s.lm.Storage().GetPlan(ctx, planID)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, "plan not found")
		return
	}
	if plan.ProductID != productID {
		s.respondError(w, http.StatusBadRequest, "plan does not belong to the specified product")
		return
	}

	// Get or create client
	client, err := s.lm.GetClientByEmail(ctx, email)
	if err != nil {
		// Create new client
		client, err = s.lm.CreateClient(ctx, email)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to create client: %v", err))
			return
		}
	}

	// Parse start date
	startDate := time.Now()
	if req.StartDate != "" {
		parsed, err := time.Parse(time.RFC3339, req.StartDate)
		if err != nil {
			parsed, err = time.Parse("2006-01-02", req.StartDate)
			if err != nil {
				s.respondError(w, http.StatusBadRequest, "invalid start_date format, use ISO 8601 (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)")
				return
			}
		}
		startDate = parsed
	}

	// Calculate end date based on billing cycle or custom duration
	var endDate time.Time
	var nextBillingDate time.Time
	billingCycle := plan.BillingCycle
	if req.DurationDays > 0 {
		endDate = startDate.AddDate(0, 0, req.DurationDays)
	} else {
		switch billingCycle {
		case "monthly":
			endDate = startDate.AddDate(0, 1, 0)
			nextBillingDate = endDate
		case "yearly":
			endDate = startDate.AddDate(1, 0, 0)
			nextBillingDate = endDate
		case "lifetime":
			endDate = startDate.AddDate(100, 0, 0) // 100 years
		default:
			endDate = startDate.AddDate(1, 0, 0) // Default to yearly
			nextBillingDate = endDate
		}
	}

	maxDevices := req.MaxDevices
	if maxDevices <= 0 {
		maxDevices = 1
	}

	// Create subscription record
	now := time.Now()
	subscription := &Subscription{
		ID:              uuid.New().String(),
		ClientID:        client.ID,
		ProductID:       productID,
		PlanID:          planID,
		Status:          SubscriptionStatusActive,
		StartDate:       startDate,
		EndDate:         endDate,
		BillingCycle:    billingCycle,
		NextBillingDate: nextBillingDate,
		CreatedAt:       now,
		UpdatedAt:       now,
	}

	// Generate license for the subscription
	duration := endDate.Sub(startDate)
	mode, interval := s.lm.DefaultCheckPolicy()
	opts := &GenerateLicenseOptions{
		ProductID: productID,
		PlanID:    planID,
	}

	license, err := s.lm.GenerateLicenseWithOptions(ctx, client.ID, duration, maxDevices, plan.Slug, mode, interval, opts)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to generate license: %v", err))
		return
	}

	subscription.LicenseID = license.ID

	// Save subscription
	if err := s.lm.Storage().SaveSubscription(ctx, subscription); err != nil {
		s.respondError(w, http.StatusInternalServerError, fmt.Sprintf("failed to save subscription: %v", err))
		return
	}

	// Build response
	resp := map[string]interface{}{
		"success":      true,
		"message":      "Subscription created successfully",
		"subscription": subscription,
		"license": map[string]interface{}{
			"id":          license.ID,
			"license_key": license.LicenseKey,
			"plan_slug":   license.PlanSlug,
			"expires_at":  license.ExpiresAt,
			"max_devices": license.MaxDevices,
		},
		"client": map[string]interface{}{
			"id":    client.ID,
			"email": client.Email,
		},
		"product": map[string]interface{}{
			"id":   product.ID,
			"name": product.Name,
			"slug": product.Slug,
		},
		"plan": map[string]interface{}{
			"id":            plan.ID,
			"name":          plan.Name,
			"slug":          plan.Slug,
			"billing_cycle": plan.BillingCycle,
		},
	}

	// TODO: Send welcome email if requested
	if req.SendEmail {
		resp["email_sent"] = false
		resp["email_message"] = "Email sending not yet implemented"
	}

	s.respondJSON(w, http.StatusCreated, resp)
}

func (s *Server) handleSubscriptions(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	ctx := r.Context()

	switch r.Method {
	case http.MethodGet:
		clientID := strings.TrimSpace(r.URL.Query().Get("client_id"))
		var subs []*Subscription
		var err error
		if clientID != "" {
			subs, err = s.lm.Storage().ListSubscriptionsByClient(ctx, clientID)
		} else {
			subs, err = s.lm.Storage().ListSubscriptions(ctx)
		}
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if subs == nil {
			subs = []*Subscription{}
		}
		s.respondJSON(w, http.StatusOK, subs)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleProvisionLicense(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	var req provisionLicenseRequest
	if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
		return
	}
	ctx := r.Context()
	emailAddr := strings.TrimSpace(req.Email)
	if !emailRegex.MatchString(emailAddr) {
		s.respondError(w, http.StatusBadRequest, "invalid email address")
		return
	}

	planID := strings.TrimSpace(req.PlanID)
	productID := strings.TrimSpace(req.ProductID)

	// Validate that both product_id and plan_id are provided
	if planID == "" {
		s.respondError(w, http.StatusBadRequest, "plan_id is required")
		return
	}
	if productID == "" {
		s.respondError(w, http.StatusBadRequest, "product_id is required")
		return
	}

	// Get the plan
	plan, planErr := s.lm.Storage().GetPlan(ctx, planID)
	if planErr != nil {
		s.respondError(w, http.StatusBadRequest, "plan not found")
		return
	}
	if !plan.IsActive {
		s.respondError(w, http.StatusBadRequest, "plan is not active")
		return
	}

	// Get the product
	product, productErr := s.lm.Storage().GetProduct(ctx, productID)
	if productErr != nil || product == nil {
		s.respondError(w, http.StatusBadRequest, "product not found")
		return
	}
	if plan.ProductID != "" && plan.ProductID != product.ID {
		s.respondError(w, http.StatusBadRequest, "plan does not belong to specified product")
		return
	}

	// Derive max_devices from plan
	maxDevices := plan.MaxDevices
	if maxDevices <= 0 {
		// Fallback to min_devices if max_devices is not set
		if plan.MinDevices > 0 {
			maxDevices = plan.MinDevices
		} else {
			maxDevices = 1
		}
	}

	// Derive duration from plan
	var duration time.Duration
	if plan.DurationDays > 0 {
		duration = time.Duration(plan.DurationDays) * 24 * time.Hour
	} else {
		// Calculate duration based on billing cycle if duration_days not set
		switch plan.BillingCycle {
		case "monthly":
			duration = 30 * 24 * time.Hour
		case "yearly":
			duration = 365 * 24 * time.Hour
		case "lifetime":
			duration = 100 * 365 * 24 * time.Hour // 100 years for lifetime
		default:
			duration = 365 * 24 * time.Hour // Default to yearly
		}
	}

	// Use default check policy
	mode, interval := s.lm.DefaultCheckPolicy()

	planSlug := plan.Slug

	client, err := s.lm.GetClientByEmail(ctx, emailAddr)
	clientCreated := false
	if err != nil {
		if errors.Is(err, errClientMissing) {
			client, err = s.lm.CreateClientWithProfile(ctx, emailAddr, "", req.Name, req.CompanyName)
			if err != nil {
				s.respondError(w, http.StatusBadRequest, err.Error())
				return
			}
			clientCreated = true
		} else {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
	} else {
		if _, err := s.lm.UpdateClientProfile(ctx, client, req.Name, req.CompanyName); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
	}

	ops := &GenerateLicenseOptions{ProductID: productID, PlanID: planID}
	license, err := s.lm.GenerateLicenseWithOptions(ctx, client.ID, duration, maxDevices, planSlug, mode, interval, ops)
	if err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}

	clientLabel := client.Name
	if clientLabel == "" {
		clientLabel = client.Email
	}
	planLabel := plan.Name
	if planLabel == "" {
		planLabel = plan.Slug
	}
	productLabel := "your account"
	if product.Name != "" {
		productLabel = product.Name
	}

	emails := make(map[string]emailDispatchResult)
	welcomeSubject := fmt.Sprintf("Welcome to %s", productLabel)

	// Render welcome email using template
	welcomeTemplateData := EmailTemplateData{
		ClientName:  clientLabel,
		PlanName:    planLabel,
		ProductName: productLabel,
		Email:       client.Email,
		SupportURL:  "https://support.example.com",
		DocsURL:     "https://docs.example.com",
	}
	welcomeHTML, err := s.emailTemplateLoader.RenderTemplate("welcome_email", welcomeTemplateData)
	if err != nil {
		log.Printf("failed to render welcome email template: %v", err)
		// Fallback to simple text if template rendering fails
		welcomeHTML = fmt.Sprintf("<p>Hi %s,</p><p>You're now set up on the <strong>%s</strong> plan for %s.</p><p>We'll send your license JSON in a separate email momentarily. Save it securely before activating devices.</p><p>Thanks,<br/>The Licensing Team</p>", html.EscapeString(clientLabel), html.EscapeString(planLabel), html.EscapeString(productLabel))
	}

	welcomeText := fmt.Sprintf("Hi %s,\n\nYou're now set up on the %s plan (%s). We'll send your license JSON in a separate email right away. Keep an eye on your inbox and store the JSON securely before activating devices.\n\nThanks,\nThe Licensing Team", clientLabel, planLabel, productLabel)
	if res, err := s.sendEmailNow(ctx, client.Email, welcomeSubject, welcomeHTML, welcomeText, nil); err != nil {
		emails["welcome"] = emailDispatchResult{Sent: false, Error: err.Error()}
		log.Printf("failed to send welcome email for %s: %v", client.Email, err)
	} else {
		emails["welcome"] = *res
	}

	licensePayload := map[string]any{
		"email":       client.Email,
		"client_id":   client.ID,
		"license_key": license.LicenseKey,
		"plan_slug":   license.PlanSlug,
		"plan_id":     license.PlanID,
		"product_id":  license.ProductID,
		"expires_at":  license.ExpiresAt,
		"max_devices": license.MaxDevices,
	}
	if planLabel != "" {
		licensePayload["plan_name"] = planLabel
	}
	licenseJSON, err := json.MarshalIndent(licensePayload, "", "  ")
	if err != nil {
		log.Printf("failed to marshal license payload for email: %v", err)
	}
	licenseSubject := fmt.Sprintf("%s license credentials", productLabel)
	jsonBody := string(licenseJSON)

	// Render license email using template
	licenseTemplateData := EmailTemplateData{
		ClientName:  clientLabel,
		ProductName: productLabel,
		Email:       client.Email,
		LicenseJSON: jsonBody,
		SupportURL:  "https://support.example.com",
		DocsURL:     "https://docs.example.com",
	}
	licenseHTML, err := s.emailTemplateLoader.RenderTemplate("license_email", licenseTemplateData)
	if err != nil {
		log.Printf("failed to render license email template: %v", err)
		// Fallback to simple HTML if template rendering fails
		licenseHTML = fmt.Sprintf("<p>Hi %s,</p><p>Here are the license credentials. We have also attached the <code>license.json</code> file to this email for your convenience.</p><pre style=\"padding:12px;background:#0f172a;color:#e2e8f0;border-radius:8px;white-space:pre-wrap;\">%s</pre><p>Keep this file private and secure.</p><p>Thanks,<br/>The Licensing Team</p>", html.EscapeString(clientLabel), html.EscapeString(jsonBody))
	}

	licenseText := fmt.Sprintf("Hi %s,\n\nHere are the license credentials. We have also attached the license.json file to this email for your convenience.\n\nKeep this file private and secure.\n\nThanks,\nThe Licensing Team", clientLabel)

	// Create the JSON file attachment
	licenseAttachment := &email.EmailAttachment{
		Filename:    "license.json",
		ContentType: "application/json",
		Data:        licenseJSON,
		Size:        int64(len(licenseJSON)),
	}

	if res, err := s.sendEmailNow(ctx, client.Email, licenseSubject, licenseHTML, licenseText, []*email.EmailAttachment{licenseAttachment}); err != nil {
		emails["license"] = emailDispatchResult{Sent: false, Error: err.Error()}
		log.Printf("failed to send license email for %s: %v", client.Email, err)
	} else {
		emails["license"] = *res
	}

	response := map[string]any{
		"client":         client,
		"license":        license,
		"client_created": clientCreated,
		"plan":           plan,
		"product":        product,
		"emails":         emails,
	}
	s.respondJSON(w, http.StatusCreated, response)
}

func (s *Server) handleLicenses(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		licenses, err := s.lm.ListLicenses(r.Context())
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if licenses == nil {
			licenses = []*License{}
		}
		s.respondJSON(w, http.StatusOK, licenses)
	case http.MethodPost:
		var req createLicenseRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		plan := strings.TrimSpace(req.PlanSlug)
		if req.ClientID == "" || req.DurationDays <= 0 || req.MaxDevices <= 0 || plan == "" {
			s.respondError(w, http.StatusBadRequest, "client_id, duration_days, max_devices, plan_slug must be provided")
			return
		}
		duration := time.Duration(req.DurationDays) * 24 * time.Hour
		interval := time.Duration(req.CheckIntervalSeconds) * time.Second
		if interval < 0 {
			interval = 0
		}
		modeInput := strings.TrimSpace(req.CheckMode)
		mode := ParseLicenseCheckMode(modeInput)
		if modeInput == "" {
			mode, interval = s.lm.DefaultCheckPolicy()
		} else if mode == LicenseCheckModeCustom && interval <= 0 {
			_, defaultInterval := s.lm.DefaultCheckPolicy()
			interval = defaultInterval
		}

		// Build options with product and plan IDs if provided
		var opts *GenerateLicenseOptions
		productID := strings.TrimSpace(req.ProductID)
		planID := strings.TrimSpace(req.PlanID)
		if len(req.FeatureScopes) > 0 && (productID == "" || planID == "") {
			s.respondError(w, http.StatusBadRequest, "feature scopes require product_id and plan_id")
			return
		}
		if productID != "" || planID != "" || len(req.FeatureScopes) > 0 {
			opts = &GenerateLicenseOptions{
				ProductID:     productID,
				PlanID:        planID,
				FeatureScopes: req.FeatureScopes,
			}
		}

		license, err := s.lm.GenerateLicenseWithOptions(r.Context(), req.ClientID, duration, req.MaxDevices, plan, mode, interval, opts)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}

		// Send license email to client asynchronously
		go s.sendLicenseEmailToClient(context.Background(), req.ClientID, license)

		s.respondJSON(w, http.StatusCreated, license)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		users, err := s.lm.ListAdminUsers(r.Context())
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		resp := make([]adminUserResponse, 0, len(users))
		for _, user := range users {
			resp = append(resp, newAdminUserResponse(user))
		}
		if resp == nil {
			resp = []adminUserResponse{}
		}
		s.respondJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req createAdminUserRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		user, err := s.lm.CreateAdminUser(r.Context(), req.Username, req.Password)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondJSON(w, http.StatusCreated, newAdminUserResponse(user))
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminAPIKeys(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
		if userID == "" {
			s.respondError(w, http.StatusBadRequest, "user_id is required")
			return
		}
		keys, err := s.lm.ListAPIKeysByUser(r.Context(), userID)
		if err != nil {
			if errors.Is(err, errUserMissing) {
				s.respondError(w, http.StatusNotFound, "admin user not found")
			} else {
				s.respondError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		resp := make([]apiKeyMetadata, 0, len(keys))
		for _, key := range keys {
			resp = append(resp, newAPIKeyMetadata(key))
		}
		if resp == nil {
			resp = []apiKeyMetadata{}
		}
		s.respondJSON(w, http.StatusOK, resp)
	case http.MethodPost:
		var req createAPIKeyRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		req.UserID = strings.TrimSpace(req.UserID)
		if req.UserID == "" {
			s.respondError(w, http.StatusBadRequest, "user_id is required")
			return
		}
		token, record, err := s.lm.GenerateAPIKey(r.Context(), req.UserID)
		if err != nil {
			if errors.Is(err, errUserMissing) {
				s.respondError(w, http.StatusNotFound, "admin user not found")
			} else {
				s.respondError(w, http.StatusBadRequest, err.Error())
			}
			return
		}
		resp := apiKeyIssueResponse{
			Token:    token,
			Metadata: newAPIKeyMetadata(record),
		}
		s.respondJSON(w, http.StatusCreated, resp)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleAdminAPIKeyActions(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	// Extract the API key ID from the path: /api/admin/api-keys/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/admin/api-keys/")
	keyID := strings.TrimSpace(path)
	if keyID == "" {
		s.respondError(w, http.StatusBadRequest, "API key ID is required")
		return
	}

	switch r.Method {
	case http.MethodDelete:
		err := s.lm.DeleteAPIKey(r.Context(), keyID)
		if err != nil {
			if errors.Is(err, errAPIKeyMissing) {
				s.respondError(w, http.StatusNotFound, "API key not found")
			} else {
				s.respondError(w, http.StatusInternalServerError, err.Error())
			}
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "API key deleted"})
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	s.respondJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) handleAuditLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	if s.auditLogger == nil {
		s.respondError(w, http.StatusServiceUnavailable, "audit logger is not enabled")
		return
	}
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 5000 {
			limit = parsed
		}
	}
	offset := 0
	if raw := strings.TrimSpace(r.URL.Query().Get("offset")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 0 {
			offset = parsed
		}
	}
	filter := &audit.AuditFilter{
		ActorID: actorIDParam(r.URL.Query().Get("actor_id")),
		Result:  strings.TrimSpace(r.URL.Query().Get("result")),
		Limit:   limit,
		Offset:  offset,
	}
	if et := strings.TrimSpace(r.URL.Query().Get("event_type")); et != "" {
		filter.EventTypes = []audit.EventType{audit.EventType(et)}
	}
	if sv := strings.TrimSpace(r.URL.Query().Get("severity")); sv != "" {
		filter.Severities = []audit.Severity{audit.Severity(sv)}
	}
	events, err := s.auditLogger.Query(r.Context(), filter)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []*audit.Event{}
	}
	s.respondJSON(w, http.StatusOK, events)
}

func actorIDParam(v string) string {
	return strings.TrimSpace(v)
}

func (s *Server) handleAuditComplianceReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	if s.auditLogger == nil {
		s.respondError(w, http.StatusServiceUnavailable, "audit logger is not enabled")
		return
	}
	framework := strings.TrimSpace(r.URL.Query().Get("framework"))
	if framework == "" {
		framework = "SOC2"
	}
	days := 30
	if raw := strings.TrimSpace(r.URL.Query().Get("days")); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil && parsed > 0 && parsed <= 3650 {
			days = parsed
		}
	}
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -days)
	report, err := s.auditLogger.GenerateComplianceReport(r.Context(), framework, start, end)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.respondJSON(w, http.StatusOK, report)
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		clients, err := s.lm.ListClients(r.Context())
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if clients == nil {
			clients = []*Client{}
		}
		s.respondJSON(w, http.StatusOK, clients)

	case http.MethodPost:
		var req createClientRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		var client *Client
		var err error
		if strings.TrimSpace(req.Password) != "" {
			client, err = s.lm.CreateClientWithPassword(r.Context(), req.Email, req.Password, req.Username, req.Name, req.CompanyName)
		} else {
			client, err = s.lm.CreateClientWithProfile(r.Context(), req.Email, req.Username, req.Name, req.CompanyName)
		}
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondJSON(w, http.StatusCreated, client)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleClientActions(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/api/clients/") {
		http.NotFound(w, r)
		return
	}
	tail := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/")
	parts := strings.Split(tail, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	clientID := parts[0]

	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	// Handle /api/clients/{id} - get single client
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		client, err := s.lm.GetClient(r.Context(), clientID)
		if err != nil {
			s.respondError(w, http.StatusNotFound, "Client not found")
			return
		}
		s.respondJSON(w, http.StatusOK, client)
		return
	}

	// Handle /api/clients/{id}/{action} or /api/clients/{id}/{action}/{sub}
	action := parts[1]
	// Support sub-actions like keys/{keyID}
	var subID string
	if len(parts) >= 3 {
		subID = parts[2]
	}

	switch action {
	case "licenses":
		if r.Method != http.MethodGet {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		allLicenses, err := s.lm.ListLicenses(r.Context())
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		// Filter licenses by client ID
		var licenses []*License
		for _, lic := range allLicenses {
			if lic.ClientID == clientID {
				licenses = append(licenses, lic)
			}
		}
		if licenses == nil {
			licenses = []*License{}
		}
		s.respondJSON(w, http.StatusOK, licenses)
	case "ban":
		if r.Method != http.MethodPost {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req banClientRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		client, err := s.lm.BanClient(r.Context(), clientID, req.Reason)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("Client %s banned", clientID)
		s.respondJSON(w, http.StatusOK, client)
	case "unban":
		if r.Method != http.MethodPost {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		client, err := s.lm.UnbanClient(r.Context(), clientID)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("Client %s unbanned", clientID)
		s.respondJSON(w, http.StatusOK, client)
	case "keys":
		// Admin operations for client API keys
		if r.Method == http.MethodGet {
			keys, err := s.lm.ListAPIKeysByClient(r.Context(), clientID)
			if err != nil {
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if keys == nil {
				keys = []*APIKeyRecord{}
			}
			s.respondJSON(w, http.StatusOK, keys)
			return
		}
		if r.Method == http.MethodPost {
			// Create a client API key (admin)
			token, record, err := s.lm.GenerateClientAPIKey(r.Context(), clientID)
			if err != nil {
				s.respondError(w, http.StatusBadRequest, err.Error())
				return
			}
			s.respondJSON(w, http.StatusCreated, map[string]interface{}{"token": token, "metadata": newAPIKeyMetadata(record)})
			return
		}
		// Delete handled by /api/clients/{id}/keys/{keyID}
		if r.Method == http.MethodDelete {
			if strings.TrimSpace(subID) == "" {
				s.respondError(w, http.StatusBadRequest, "API key ID is required")
				return
			}
			if err := s.lm.DeleteAPIKey(r.Context(), subID); err != nil {
				if errors.Is(err, errAPIKeyMissing) {
					s.respondError(w, http.StatusNotFound, "API key not found")
				} else {
					s.respondError(w, http.StatusInternalServerError, err.Error())
				}
				return
			}
			s.respondJSON(w, http.StatusOK, map[string]string{"message": "API key deleted"})
			return
		}
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	default:
		http.NotFound(w, r)
	}
}

// Admin-level key deletion for client-scoped keys
// Path: /api/clients/{id}/keys/{id}
// Called by the same handleClientActions since path parsing is above - handle keys/{key} explicitly

func (s *Server) handleLicenseActions(w http.ResponseWriter, r *http.Request) {
	if !strings.HasPrefix(r.URL.Path, "/api/licenses/") {
		http.NotFound(w, r)
		return
	}
	tail := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/licenses/"), "/")
	parts := strings.Split(tail, "/")

	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	licenseID := parts[0]

	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	// Handle /api/licenses/{id} - get single license
	if len(parts) == 1 {
		if r.Method != http.MethodGet {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		license, err := s.lm.storage.GetLicense(r.Context(), licenseID)
		if err != nil {
			s.respondError(w, http.StatusNotFound, "License not found")
			return
		}
		s.respondJSON(w, http.StatusOK, license)
		return
	}

	// Handle /api/licenses/{id}/{action}
	action := parts[1]

	switch action {
	case "revoke":
		if r.Method != http.MethodPost {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req licenseMutationRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		license, err := s.lm.RevokeLicense(r.Context(), licenseID, req.Reason)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("License %s revoked", licenseID)
		s.respondJSON(w, http.StatusOK, license)
	case "reinstate":
		if r.Method != http.MethodPost {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		license, err := s.lm.ReinstateLicense(r.Context(), licenseID)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		log.Printf("License %s reinstated", licenseID)
		s.respondJSON(w, http.StatusOK, license)
	case "activations":
		if r.Method != http.MethodGet {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		activations, err := s.lm.ListActivations(r.Context(), licenseID)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if activations == nil {
			activations = []*ActivationRecord{}
		}
		s.respondJSON(w, http.StatusOK, activations)
	case "delete-device":
		if r.Method != http.MethodPost {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req struct {
			Fingerprint string `json:"fingerprint"`
		}
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		if strings.TrimSpace(req.Fingerprint) == "" {
			s.respondError(w, http.StatusBadRequest, "fingerprint is required")
			return
		}
		if err := s.lm.DeleteDevice(r.Context(), licenseID, req.Fingerprint); err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "Device deleted"})
	case "entitlements":
		if r.Method != http.MethodPut && r.Method != http.MethodPost {
			s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
			return
		}
		var req struct {
			FeatureScopes []FeatureScopeSelection `json:"feature_scopes"`
		}
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		license, err := s.lm.UpdateLicenseEntitlements(r.Context(), licenseID, req.FeatureScopes)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, license)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) Start() error {
	mux := http.NewServeMux()

	// API routes
	mux.HandleFunc("/api/activate", s.handleActivate)
	mux.HandleFunc("/api/licenses", s.handleLicenses)
	mux.HandleFunc("/api/verify", s.handleVerify)
	mux.HandleFunc("/api/trial", s.handleTrial)
	mux.HandleFunc("/api/trial/check", s.handleTrialCheck)
	mux.HandleFunc("/api/subscribe", s.handleSubscribe)
	mux.HandleFunc("/api/subscriptions", s.handleSubscriptions)
	mux.HandleFunc("/api/licenses/", s.handleLicenseActions)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/clients/", s.handleClientActions)
	mux.HandleFunc("/api/admin/users", s.handleAdminUsers)
	mux.HandleFunc("/api/admin/api-keys", s.handleAdminAPIKeys)
	mux.HandleFunc("/api/admin/api-keys/", s.handleAdminAPIKeyActions)
	mux.HandleFunc("/api/admin/audit", s.handleAuditLogs)
	mux.HandleFunc("/api/admin/audit/compliance", s.handleAuditComplianceReport)
	mux.HandleFunc("/api/admin/signing-keys", s.handleAdminSigningKeys)
	mux.HandleFunc("/api/admin/signing-keys/", s.handleAdminSigningKeyActions)
	mux.HandleFunc("/api/admin/licenses/provision", s.handleProvisionLicense)
	mux.HandleFunc("/api/products", s.handleProducts)
	mux.HandleFunc("/api/products/", s.handleProductActions)
	mux.HandleFunc("/api/entitlements", s.handleEntitlements)
	mux.HandleFunc("/health", s.handleHealth)
	if metricsEnabled() {
		mux.HandleFunc("/metrics", s.handleMetrics)
	}

	// Offline validation endpoints
	mux.HandleFunc("/api/licenses/offline-token", s.handleGenerateOfflineToken)
	mux.HandleFunc("/api/licenses/offline-validate", s.handleValidateOfflineToken)
	mux.HandleFunc("/api/licenses/offline-tokens", s.handleListOfflineTokens)
	// Revocation manifest for offline clients to fetch
	mux.HandleFunc("/api/licenses/offline-revocations", s.handleGetRevocationManifest)
	// Expose active signing public key for clients to verify offline bundles
	mux.HandleFunc("/api/keys/offline-signing-public", s.handleGetActiveSigningPublicKey)
	// allow fetching a specific public key by id
	mux.HandleFunc("/api/keys/offline-signing-public/", s.handleGetSigningPublicKeyByID)
	mux.HandleFunc("/api/licenses/offline-logs", s.handleListOfflineLogs)
	// Client auth endpoints
	mux.HandleFunc("/api/client/auth/register", s.handleClientRegister)
	mux.HandleFunc("/api/client/auth/login", s.handleClientLogin)
	mux.HandleFunc("/api/client/auth/logout", s.handleClientLogout)
	mux.HandleFunc("/api/client/auth/refresh", s.handleClientRefresh)
	mux.HandleFunc("/api/client/profile", s.handleClientProfile)
	// Client keys for managing API keys bound to their client account
	mux.HandleFunc("/api/client/keys", s.handleClientKeys)
	mux.HandleFunc("/api/client/keys/", s.handleClientKeys)

	// If web UI handler is set, use it for all other routes
	if s.webHandler != nil {
		mux.Handle("/", s.webHandler)
	} else {
		// If no web handler is set, try to serve static files from web/dist
		distPath := "web/dist"
		if _, err := os.Stat(distPath); err == nil {
			// web/dist directory exists, serve static files
			mux.Handle("/", http.FileServer(http.Dir(distPath)))
			log.Printf("🖥️  Serving static web UI from %s", distPath)
		}
	}

	server := &http.Server{
		Addr:              s.port,
		Handler:           s.withMetrics(s.withAudit(s.withCORS(s.withSecurityHeaders(mux)))),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	addr := server.Addr
	if addr == "" {
		addr = ":http"
	}
	displayAddr := addr
	if strings.HasPrefix(addr, ":") {
		displayAddr = "0.0.0.0" + addr
	}
	useTLS := s.hasTLSConfig()
	scheme := "http"
	if useTLS {
		scheme = "https"
	} else if !s.allowInsecureHTTP {
		return fmt.Errorf("tls required: set LICENSE_SERVER_TLS_CERT/KEY or start with --allow-insecure-http for development")
	}
	log.Printf("🌐 Listening on %s://%s", scheme, displayAddr)
	if useTLS {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			return err
		}
		server.TLSConfig = tlsConfig
		return server.ListenAndServeTLS(s.tlsCertPath, s.tlsKeyPath)
	}
	log.Printf("WARNING: starting licensing server without TLS; traffic will be unencrypted")
	return server.ListenAndServe()
}
