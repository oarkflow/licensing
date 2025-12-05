package licensing

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
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
	"strings"
	"time"

	"github.com/google/uuid"
	email "github.com/oarkflow/licensing/pkg/email"
	"github.com/oarkflow/licensing/pkg/utils"
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
	// Initialize email template loader
	emailTemplateLoader := NewEmailTemplateLoader()
	if err := emailTemplateLoader.LoadTemplates(); err != nil {
		return nil, fmt.Errorf("failed to load email templates: %w", err)
	}

	return &Server{
		lm:                  lm,
		port:                port,
		rateLimiter:         limiter,
		legacyAPIKeyHashes:  hashes,
		tlsCertPath:         tlsCertPath,
		tlsKeyPath:          tlsKeyPath,
		clientCAPath:        clientCAPath,
		allowInsecureHTTP:   allowInsecure,
		emailTemplateLoader: emailTemplateLoader,
	}, nil
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

func (s *Server) enqueueEmail(ctx context.Context, to, subject, htmlBody, textBody string, metadata map[string]string) (*emailDispatchResult, error) {
	return s.enqueueEmailWithAttachments(ctx, to, subject, htmlBody, textBody, metadata, nil)
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

	// Get an active email provider
	providers, err := storage.ListEmailProviders(ctx, false)
	if err != nil {
		return nil, fmt.Errorf("failed to list email providers: %w", err)
	}
	log.Printf("📧 Found %d email providers", len(providers))
	if len(providers) == 0 {
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

	// Prepare license data for email
	licenseJSON, err := json.MarshalIndent(license, "", "  ")
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
			client, err = s.lm.CreateClientWithProfile(ctx, emailAddr, req.Name, req.CompanyName)
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
	if product != nil && product.Name != "" {
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
		if productID != "" || planID != "" {
			opts = &GenerateLicenseOptions{
				ProductID: productID,
				PlanID:    planID,
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
		client, err := s.lm.CreateClientWithProfile(r.Context(), req.Email, req.Name, req.CompanyName)
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

	// Handle /api/clients/{id}/{action}
	action := parts[1]

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
	default:
		http.NotFound(w, r)
	}
}

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
	mux.HandleFunc("/api/admin/licenses/provision", s.handleProvisionLicense)
	mux.HandleFunc("/api/products", s.handleProducts)
	mux.HandleFunc("/api/products/", s.handleProductActions)
	mux.HandleFunc("/api/entitlements", s.handleEntitlements)
	mux.HandleFunc("/health", s.handleHealth)

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
		Handler:           s.withCORS(s.withSecurityHeaders(mux)),
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
