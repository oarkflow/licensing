package middleware

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/oarkflow/licensing/pkg/audit"
	"github.com/oarkflow/licensing/pkg/auth"
)

// SecurityContext key for storing security information in request context
type SecurityContextKey string

const (
	UserIDKey    SecurityContextKey = "user_id"
	UserRoleKey  SecurityContextKey = "user_role"
	RequestIDKey SecurityContextKey = "request_id"
	ClientIPKey  SecurityContextKey = "client_ip"
)

// SecurityMiddleware holds all security middleware components
type SecurityMiddleware struct {
	accessControl  *auth.AccessControl
	rateLimiter    *auth.RateLimiter
	passwordHasher *auth.PasswordHasher
	auditLogger    *audit.AuditLogger
}

// NewSecurityMiddleware creates a new security middleware
func NewSecurityMiddleware(
	accessControl *auth.AccessControl,
	rateLimiter *auth.RateLimiter,
	passwordHasher *auth.PasswordHasher,
	auditLogger *audit.AuditLogger,
) *SecurityMiddleware {
	return &SecurityMiddleware{
		accessControl:  accessControl,
		rateLimiter:    rateLimiter,
		passwordHasher: passwordHasher,
		auditLogger:    auditLogger,
	}
}

// Authentication middleware validates API keys or tokens
func (sm *SecurityMiddleware) Authentication(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract API key from header
		apiKey := r.Header.Get("X-API-Key")
		if apiKey == "" {
			// Try Authorization header
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				apiKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if apiKey == "" {
			sm.logUnauthorized(r, "missing API key")
			http.Error(w, "Unauthorized: missing API key", http.StatusUnauthorized)
			return
		}

		// Validate API key (implement your validation logic)
		userID, role, err := sm.validateAPIKey(apiKey)
		if err != nil {
			sm.logUnauthorized(r, fmt.Sprintf("invalid API key: %v", err))
			http.Error(w, "Unauthorized: invalid API key", http.StatusUnauthorized)
			return
		}

		// Add user info to context
		ctx := r.Context()
		ctx = context.WithValue(ctx, UserIDKey, userID)
		ctx = context.WithValue(ctx, UserRoleKey, role)
		ctx = context.WithValue(ctx, ClientIPKey, getClientIP(r))

		// Log successful authentication
		event := audit.NewEvent(
			audit.EventAuthLogin,
			audit.SeverityInfo,
			"api_authentication",
			"Successful API authentication",
		).WithActor(userID, "user", getClientIP(r)).WithResult("success")

		sm.auditLogger.Log(ctx, event)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequirePermission creates middleware that checks for a specific permission
func (sm *SecurityMiddleware) RequirePermission(permission auth.Permission) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userID := r.Context().Value(UserIDKey)
			if userID == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			userIDStr, ok := userID.(string)
			if !ok {
				http.Error(w, "Invalid user context", http.StatusInternalServerError)
				return
			}

			// Check permission
			if err := sm.accessControl.CheckPermission(userIDStr, permission); err != nil {
				event := audit.NewEvent(
					audit.EventSecurityUnauthorized,
					audit.SeverityWarning,
					r.URL.Path,
					"Permission denied",
				).WithActor(userIDStr, "user", getClientIP(r)).
					WithResult("failure").
					WithMetadata("required_permission", string(permission))

				sm.auditLogger.Log(r.Context(), event)

				http.Error(w, "Forbidden: insufficient permissions", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RateLimit middleware enforces rate limiting
func (sm *SecurityMiddleware) RateLimit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		identifier := getClientIP(r)

		// Use user ID if authenticated
		if userID := r.Context().Value(UserIDKey); userID != nil {
			if userIDStr, ok := userID.(string); ok {
				identifier = userIDStr
			}
		}

		if !sm.rateLimiter.Allow(identifier) {
			event := audit.NewEvent(
				audit.EventAPIRateLimited,
				audit.SeverityWarning,
				r.URL.Path,
				"Rate limit exceeded",
			).WithActor(identifier, "client", getClientIP(r)).WithResult("failure")

			sm.auditLogger.Log(r.Context(), event)

			w.Header().Set("Retry-After", "60")
			http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// AuditLog middleware logs all requests
func (sm *SecurityMiddleware) AuditLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Wrap response writer to capture status code
		wrapped := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		// Process request
		next.ServeHTTP(wrapped, r)

		// Log request
		duration := time.Since(startTime)

		userID := "anonymous"
		if uid := r.Context().Value(UserIDKey); uid != nil {
			if userIDStr, ok := uid.(string); ok {
				userID = userIDStr
			}
		}

		result := "success"
		severity := audit.SeverityInfo
		if wrapped.statusCode >= 400 {
			result = "failure"
			severity = audit.SeverityWarning
		}
		if wrapped.statusCode >= 500 {
			severity = audit.SeverityError
		}

		event := audit.NewEvent(
			audit.EventAPIRequest,
			severity,
			r.URL.Path,
			fmt.Sprintf("%s %s", r.Method, r.URL.Path),
		).WithActor(userID, "user", getClientIP(r)).
			WithResult(result).
			WithMetadata("method", r.Method).
			WithMetadata("status_code", wrapped.statusCode).
			WithMetadata("duration_ms", duration.Milliseconds()).
			WithMetadata("user_agent", r.UserAgent())

		sm.auditLogger.Log(r.Context(), event)
	})
}

// RequireRole creates middleware that checks for a specific role
func (sm *SecurityMiddleware) RequireRole(role auth.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole := r.Context().Value(UserRoleKey)
			if userRole == nil {
				http.Error(w, "Unauthorized", http.StatusUnauthorized)
				return
			}

			userRoleStr, ok := userRole.(auth.Role)
			if !ok {
				http.Error(w, "Invalid role context", http.StatusInternalServerError)
				return
			}

			// Check role hierarchy
			if !sm.hasRequiredRole(userRoleStr, role) {
				userID := r.Context().Value(UserIDKey)
				event := audit.NewEvent(
					audit.EventSecurityUnauthorized,
					audit.SeverityWarning,
					r.URL.Path,
					"Insufficient role",
				).WithActor(fmt.Sprint(userID), "user", getClientIP(r)).
					WithResult("failure").
					WithMetadata("required_role", string(role)).
					WithMetadata("user_role", string(userRoleStr))

				sm.auditLogger.Log(r.Context(), event)

				http.Error(w, "Forbidden: insufficient role", http.StatusForbidden)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// hasRequiredRole checks if user role meets requirement based on hierarchy
func (sm *SecurityMiddleware) hasRequiredRole(userRole, requiredRole auth.Role) bool {
	roleHierarchy := map[auth.Role]int{
		auth.RoleReadOnly:  1,
		auth.RoleSupport:   2,
		auth.RoleAPIClient: 2,
		auth.RoleManager:   3,
		auth.RoleAdmin:     4,
	}

	userLevel, userExists := roleHierarchy[userRole]
	requiredLevel, reqExists := roleHierarchy[requiredRole]

	if !userExists || !reqExists {
		return false
	}

	return userLevel >= requiredLevel
}

// validateAPIKey validates an API key and returns user info
func (sm *SecurityMiddleware) validateAPIKey(apiKey string) (string, auth.Role, error) {
	if strings.TrimSpace(apiKey) == "" {
		return "", "", fmt.Errorf("empty API key")
	}
	// Fail closed until a concrete validator is wired to a persistent auth store.
	return "", "", fmt.Errorf("API key validation backend not configured")
}

// logUnauthorized logs unauthorized access attempts
func (sm *SecurityMiddleware) logUnauthorized(r *http.Request, reason string) {
	event := audit.NewEvent(
		audit.EventSecurityUnauthorized,
		audit.SeverityWarning,
		r.URL.Path,
		fmt.Sprintf("Unauthorized access: %s", reason),
	).WithActor("anonymous", "client", getClientIP(r)).
		WithResult("failure").
		WithMetadata("method", r.Method).
		WithMetadata("user_agent", r.UserAgent())

	sm.auditLogger.Log(r.Context(), event)
}

// getClientIP extracts client IP from request
func getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(statusCode int) {
	rw.statusCode = statusCode
	rw.ResponseWriter.WriteHeader(statusCode)
}

// CORS middleware with secure defaults
func SecureCORS(allowedOrigins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")

			// Check if origin is allowed
			allowed := false
			for _, allowedOrigin := range allowedOrigins {
				if origin == allowedOrigin {
					allowed = true
					break
				}
			}

			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key")
				w.Header().Set("Access-Control-Max-Age", "86400")
				w.Header().Set("Access-Control-Allow-Credentials", "true")
			}

			// Handle preflight
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// RequestID middleware adds unique request ID
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			requestID = fmt.Sprintf("req-%d", time.Now().UnixNano())
		}

		ctx := context.WithValue(r.Context(), RequestIDKey, requestID)
		w.Header().Set("X-Request-ID", requestID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// Recovery middleware recovers from panics
func Recovery(auditLogger *audit.AuditLogger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if err := recover(); err != nil {
					event := audit.NewEvent(
						audit.EventSystemError,
						audit.SeverityCritical,
						r.URL.Path,
						fmt.Sprintf("Panic recovered: %v", err),
					).WithActor("system", "system", getClientIP(r)).
						WithResult("failure").
						WithMetadata("panic", fmt.Sprint(err))

					auditLogger.Log(r.Context(), event)

					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// ErrorResponse represents an API error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
	Code    int    `json:"code"`
}

// WriteJSONError writes a JSON error response
func WriteJSONError(w http.ResponseWriter, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(ErrorResponse{
		Error:   http.StatusText(code),
		Message: message,
		Code:    code,
	})
}

// WriteJSON writes a JSON response
func WriteJSON(w http.ResponseWriter, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}
