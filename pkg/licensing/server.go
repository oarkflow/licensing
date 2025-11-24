package licensing

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oarflow/licensing/pkg/utils"
)

type Server struct {
	lm                 *LicenseManager
	port               string
	rateLimiter        *RateLimiter
	legacyAPIKeyHashes [][]byte
	tlsCertPath        string
	tlsKeyPath         string
	clientCAPath       string
	allowInsecureHTTP  bool
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
	return &Server{
		lm:                 lm,
		port:               port,
		rateLimiter:        limiter,
		legacyAPIKeyHashes: hashes,
		tlsCertPath:        tlsCertPath,
		tlsKeyPath:         tlsKeyPath,
		clientCAPath:       clientCAPath,
		allowInsecureHTTP:  allowInsecure,
	}, nil
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
	providedKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if providedKey == "" {
		s.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return false
	}
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
	s.respondError(w, http.StatusUnauthorized, "Unauthorized")
	return false
}

func (s *Server) decodeJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, limit int64) bool {
	body := http.MaxBytesReader(w, r.Body, limit)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		s.respondError(w, http.StatusBadRequest, "Invalid request body")
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

func (s *Server) respondError(w http.ResponseWriter, status int, message string) {
	s.respondJSON(w, status, map[string]string{"error": message})
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

func (s *Server) respondClientError(w http.ResponseWriter, status int, message string, transportKey []byte) {
	if len(transportKey) == 32 {
		s.respondClientJSON(w, status, map[string]string{"error": message}, transportKey)
		return
	}
	s.respondError(w, status, message)
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
		s.respondClientError(w, http.StatusBadRequest, "Invalid request body", transportKey)
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
		if req.ClientID == "" || req.DurationDays <= 0 || req.MaxDevices <= 0 {
			s.respondError(w, http.StatusBadRequest, "client_id, duration_days, max_devices must be provided")
			return
		}
		duration := time.Duration(req.DurationDays) * 24 * time.Hour
		license, err := s.lm.GenerateLicense(r.Context(), req.ClientID, duration, req.MaxDevices)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
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
		client, err := s.lm.CreateClient(r.Context(), req.Email)
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
	if len(parts) < 2 || len(parts) > 2 {
		http.NotFound(w, r)
		return
	}
	clientID := parts[0]
	action := parts[1]
	if clientID == "" {
		http.NotFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	switch action {
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
	if len(parts) < 2 || len(parts) > 2 {
		http.NotFound(w, r)
		return
	}
	licenseID := parts[0]
	action := parts[1]
	if licenseID == "" {
		http.NotFound(w, r)
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

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
	mux.HandleFunc("/api/activate", s.handleActivate)
	mux.HandleFunc("/api/licenses", s.handleLicenses)
	mux.HandleFunc("/api/verify", s.handleVerify)
	mux.HandleFunc("/api/licenses/", s.handleLicenseActions)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/clients/", s.handleClientActions)
	mux.HandleFunc("/api/admin/users", s.handleAdminUsers)
	mux.HandleFunc("/api/admin/api-keys", s.handleAdminAPIKeys)
	mux.HandleFunc("/health", s.handleHealth)

	server := &http.Server{
		Addr:              s.port,
		Handler:           s.withSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	useTLS := s.hasTLSConfig()
	if useTLS {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			return err
		}
		server.TLSConfig = tlsConfig
		return server.ListenAndServeTLS(s.tlsCertPath, s.tlsKeyPath)
	}
	if !s.allowInsecureHTTP {
		return fmt.Errorf("tls required: set LICENSE_SERVER_TLS_CERT/KEY or start with --allow-insecure-http for development")
	}
	log.Printf("WARNING: starting licensing server without TLS; traffic will be unencrypted")
	return server.ListenAndServe()
}
