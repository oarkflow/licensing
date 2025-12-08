package network

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"
	"time"
)

// TLSConfig represents TLS configuration for secure communication
type TLSConfig struct {
	MinVersion               uint16
	MaxVersion               uint16
	CipherSuites             []uint16
	PreferServerCipherSuites bool
	CertFile                 string
	KeyFile                  string
	ClientCAFile             string
	RequireClientCert        bool
}

// DefaultTLSConfig returns secure TLS configuration
func DefaultTLSConfig() *TLSConfig {
	return &TLSConfig{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
		},
		PreferServerCipherSuites: true,
		RequireClientCert:        false,
	}
}

// BuildTLSConfig creates a tls.Config from TLSConfig
func (tc *TLSConfig) BuildTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion:               tc.MinVersion,
		MaxVersion:               tc.MaxVersion,
		CipherSuites:             tc.CipherSuites,
		PreferServerCipherSuites: tc.PreferServerCipherSuites,
	}

	// Load server certificate if provided
	if tc.CertFile != "" && tc.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(tc.CertFile, tc.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load certificate: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	// Load client CA for mTLS if provided
	if tc.ClientCAFile != "" {
		caCert, err := ioutil.ReadFile(tc.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read client CA: %w", err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse client CA")
		}

		tlsConfig.ClientCAs = caCertPool
		if tc.RequireClientCert {
			tlsConfig.ClientAuth = tls.RequireAndVerifyClientCert
		} else {
			tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		}
	}

	return tlsConfig, nil
}

// CertificatePinner implements certificate pinning
type CertificatePinner struct {
	pinnedCerts map[string][]byte // hostname -> certificate hash
}

// NewCertificatePinner creates a new certificate pinner
func NewCertificatePinner() *CertificatePinner {
	return &CertificatePinner{
		pinnedCerts: make(map[string][]byte),
	}
}

// PinCertificate pins a certificate for a hostname
func (cp *CertificatePinner) PinCertificate(hostname string, certHash []byte) {
	cp.pinnedCerts[hostname] = certHash
}

// VerifyPeerCertificate verifies the peer certificate against pinned certificates
func (cp *CertificatePinner) VerifyPeerCertificate(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	if len(verifiedChains) == 0 || len(verifiedChains[0]) == 0 {
		return fmt.Errorf("no verified certificate chains")
	}

	cert := verifiedChains[0][0]
	hostname := cert.Subject.CommonName

	pinnedHash, exists := cp.pinnedCerts[hostname]
	if !exists {
		// No pin for this host, allow connection
		return nil
	}

	// Verify certificate hash matches pinned hash
	// In production, use proper certificate fingerprinting
	certHash := cert.Raw
	if len(certHash) != len(pinnedHash) {
		return fmt.Errorf("certificate hash mismatch for %s", hostname)
	}

	for i := range certHash {
		if certHash[i] != pinnedHash[i] {
			return fmt.Errorf("certificate hash mismatch for %s", hostname)
		}
	}

	return nil
}

// SecureHTTPClient creates an HTTP client with secure defaults
func SecureHTTPClient(tlsConfig *tls.Config) *http.Client {
	if tlsConfig == nil {
		tlsConfig = &tls.Config{
			MinVersion: tls.VersionTLS13,
		}
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
		DisableKeepAlives:   false,
		ForceAttemptHTTP2:   true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

// RequestSigner signs HTTP requests for authentication
type RequestSigner struct {
	apiKey    string
	apiSecret string
}

// NewRequestSigner creates a new request signer
func NewRequestSigner(apiKey, apiSecret string) *RequestSigner {
	return &RequestSigner{
		apiKey:    apiKey,
		apiSecret: apiSecret,
	}
}

// SignRequest signs an HTTP request
func (rs *RequestSigner) SignRequest(req *http.Request) error {
	// Add timestamp
	timestamp := time.Now().Unix()
	req.Header.Set("X-Request-Timestamp", fmt.Sprintf("%d", timestamp))

	// Add API key
	req.Header.Set("X-API-Key", rs.apiKey)

	// In production, implement proper request signing (HMAC)
	// signature := hmac.SHA256(apiSecret, method + path + timestamp + body)
	// req.Header.Set("X-Signature", signature)

	return nil
}

// SecurityHeaders adds recommended security headers to HTTP responses
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Prevent clickjacking
		w.Header().Set("X-Frame-Options", "DENY")

		// Prevent MIME type sniffing
		w.Header().Set("X-Content-Type-Options", "nosniff")

		// Enable XSS protection
		w.Header().Set("X-XSS-Protection", "1; mode=block")

		// Enforce HTTPS
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")

		// Content Security Policy
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// Referrer Policy
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")

		// Permissions Policy
		w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}
