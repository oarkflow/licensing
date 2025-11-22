package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Server struct {
	lm           *LicenseManager
	port         string
	rateLimiter  *RateLimiter
	apiKeyHashes [][]byte
	tlsCertPath  string
	tlsKeyPath   string
	clientCAPath string
}

func hashAPIKeys(keys []string) ([][]byte, error) {
	hashes := make([][]byte, 0, len(keys))
	for _, key := range keys {
		trimmed := strings.TrimSpace(key)
		if trimmed == "" {
			continue
		}
		hash := sha256.Sum256([]byte(trimmed))
		copyHash := make([]byte, len(hash))
		copy(copyHash, hash[:])
		hashes = append(hashes, copyHash)
	}
	if len(hashes) == 0 {
		return nil, fmt.Errorf("no valid API keys provided")
	}
	return hashes, nil
}

func parseAPIKeys(raw string) []string {
	parts := strings.Split(raw, ",")
	keys := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		keys = append(keys, trimmed)
	}
	return keys
}

func NewServer(lm *LicenseManager, port string, apiKeys []string, limiter *RateLimiter, tlsCertPath, tlsKeyPath, clientCAPath string) (*Server, error) {
	if len(apiKeys) == 0 {
		return nil, fmt.Errorf("at least one API key is required")
	}
	if limiter == nil {
		limiter = NewRateLimiter(60, time.Minute)
	}
	hashes, err := hashAPIKeys(apiKeys)
	if err != nil {
		return nil, err
	}
	return &Server{
		lm:           lm,
		port:         port,
		rateLimiter:  limiter,
		apiKeyHashes: hashes,
		tlsCertPath:  tlsCertPath,
		tlsKeyPath:   tlsKeyPath,
		clientCAPath: clientCAPath,
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

func (s *Server) authorizeAdmin(w http.ResponseWriter, r *http.Request) bool {
	providedKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
	if providedKey == "" {
		s.respondError(w, http.StatusUnauthorized, "Unauthorized")
		return false
	}
	providedHash := sha256.Sum256([]byte(providedKey))
	for _, allowed := range s.apiKeyHashes {
		if subtle.ConstantTimeCompare(providedHash[:], allowed) == 1 {
			return true
		}
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
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	if !s.enforceRateLimit(w, r) {
		return
	}

	var req ActivationRequest
	if !s.decodeJSONBody(w, r, &req, maxActivationPayloadBytes) {
		return
	}
	if err := validateActivationRequest(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, err.Error())
		return
	}
	req.LicenseKey = normalizeLicenseKey(req.LicenseKey)
	req.IPAddress = clientIP(r)
	req.UserAgent = r.UserAgent()

	resp, err := s.lm.ActivateLicense(r.Context(), &req)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	s.respondJSON(w, http.StatusOK, resp)
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
		if req.ClientID == "" || req.DurationDays <= 0 || req.MaxActivations <= 0 {
			s.respondError(w, http.StatusBadRequest, "client_id, duration_days, and max_activations must be provided")
			return
		}
		duration := time.Duration(req.DurationDays) * 24 * time.Hour
		license, err := s.lm.GenerateLicense(r.Context(), req.ClientID, duration, req.MaxActivations)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondJSON(w, http.StatusCreated, license)
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
		client, err := s.lm.CreateClient(r.Context(), req.Email, req.Username)
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
	mux.HandleFunc("/api/licenses/", s.handleLicenseActions)
	mux.HandleFunc("/api/clients", s.handleClients)
	mux.HandleFunc("/api/clients/", s.handleClientActions)
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
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	log.Printf("🚀 License Manager Server starting on port %s", s.port)
	log.Printf("📝 Endpoints:")
	log.Printf("   POST   %s://localhost%s/api/activate", scheme, s.port)
	log.Printf("   GET    %s://localhost%s/api/licenses", scheme, s.port)
	log.Printf("   POST   %s://localhost%s/api/licenses", scheme, s.port)
	log.Printf("   POST   %s://localhost%s/api/licenses/{id}/revoke", scheme, s.port)
	log.Printf("   POST   %s://localhost%s/api/clients", scheme, s.port)
	log.Printf("   POST   %s://localhost%s/api/clients/{id}/ban", scheme, s.port)
	log.Printf("   GET    %s://localhost%s/health", scheme, s.port)

	if useTLS {
		tlsConfig, err := s.buildTLSConfig()
		if err != nil {
			return err
		}
		server.TLSConfig = tlsConfig
		log.Printf("🔐 TLS enabled (mTLS=%t)", s.clientCAPath != "")
		return server.ListenAndServeTLS(s.tlsCertPath, s.tlsKeyPath)
	}

	return server.ListenAndServe()
}
