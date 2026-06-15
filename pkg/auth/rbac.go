package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/argon2"
)

// Role represents a user role
type Role string

const (
	RoleAdmin     Role = "admin"
	RoleManager   Role = "manager"
	RoleSupport   Role = "support"
	RoleReadOnly  Role = "readonly"
	RoleAPIClient Role = "api_client"
)

// Permission represents a specific permission
type Permission string

const (
	// License Permissions
	PermissionLicenseCreate Permission = "license:create"
	PermissionLicenseRead   Permission = "license:read"
	PermissionLicenseUpdate Permission = "license:update"
	PermissionLicenseRevoke Permission = "license:revoke"
	PermissionLicenseDelete Permission = "license:delete"

	// Product Permissions
	PermissionProductCreate Permission = "product:create"
	PermissionProductRead   Permission = "product:read"
	PermissionProductUpdate Permission = "product:update"
	PermissionProductDelete Permission = "product:delete"

	// Plan Permissions
	PermissionPlanCreate Permission = "plan:create"
	PermissionPlanRead   Permission = "plan:read"
	PermissionPlanUpdate Permission = "plan:update"
	PermissionPlanDelete Permission = "plan:delete"

	// Billing Permissions
	PermissionBillingRead       Permission = "billing:read"
	PermissionBillingWrite      Permission = "billing:write"
	PermissionBillingGateway    Permission = "billing:gateway"
	PermissionBillingApproval   Permission = "billing:approval"
	PermissionBillingCollection Permission = "billing:collection"

	// Admin Permissions
	PermissionAdminAccess  Permission = "admin:access"
	PermissionUserManage   Permission = "user:manage"
	PermissionConfigManage Permission = "config:manage"
	PermissionAuditView    Permission = "audit:view"
	PermissionAPIKeyManage Permission = "apikey:manage"

	// Reporting Permissions
	PermissionReportView   Permission = "report:view"
	PermissionReportExport Permission = "report:export"
)

// RolePermissions maps roles to their default permissions
var RolePermissions = map[Role][]Permission{
	RoleAdmin: {
		PermissionLicenseCreate, PermissionLicenseRead, PermissionLicenseUpdate,
		PermissionLicenseRevoke, PermissionLicenseDelete,
		PermissionProductCreate, PermissionProductRead, PermissionProductUpdate, PermissionProductDelete,
		PermissionPlanCreate, PermissionPlanRead, PermissionPlanUpdate, PermissionPlanDelete,
		PermissionBillingRead, PermissionBillingWrite, PermissionBillingGateway, PermissionBillingApproval, PermissionBillingCollection,
		PermissionAdminAccess, PermissionUserManage, PermissionConfigManage,
		PermissionAuditView, PermissionAPIKeyManage,
		PermissionReportView, PermissionReportExport,
	},
	RoleManager: {
		PermissionLicenseCreate, PermissionLicenseRead, PermissionLicenseUpdate, PermissionLicenseRevoke,
		PermissionProductRead, PermissionProductUpdate,
		PermissionPlanRead, PermissionPlanUpdate,
		PermissionBillingRead, PermissionBillingWrite, PermissionBillingApproval, PermissionBillingCollection,
		PermissionReportView,
	},
	RoleSupport: {
		PermissionLicenseRead, PermissionProductRead, PermissionPlanRead,
		PermissionBillingRead,
		PermissionReportView,
	},
	RoleReadOnly: {
		PermissionLicenseRead, PermissionProductRead, PermissionPlanRead, PermissionBillingRead,
	},
	RoleAPIClient: {
		PermissionLicenseRead, PermissionProductRead, PermissionPlanRead,
	},
}

// User represents a system user
type User struct {
	ID           string                 `json:"id"`
	Username     string                 `json:"username"`
	Email        string                 `json:"email"`
	PasswordHash string                 `json:"-"` // Never expose in JSON
	Roles        []Role                 `json:"roles"`
	Permissions  []Permission           `json:"permissions"` // Additional custom permissions
	MFAEnabled   bool                   `json:"mfa_enabled"`
	MFASecret    string                 `json:"-"` // Never expose
	CreatedAt    time.Time              `json:"created_at"`
	UpdatedAt    time.Time              `json:"updated_at"`
	LastLogin    time.Time              `json:"last_login"`
	Disabled     bool                   `json:"disabled"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// HasPermission checks if user has a specific permission
func (u *User) HasPermission(permission Permission) bool {
	// Check custom permissions first
	for _, p := range u.Permissions {
		if p == permission {
			return true
		}
	}

	// Check role-based permissions
	for _, role := range u.Roles {
		rolePerms, exists := RolePermissions[role]
		if !exists {
			continue
		}
		for _, p := range rolePerms {
			if p == permission {
				return true
			}
		}
	}

	return false
}

// HasRole checks if user has a specific role
func (u *User) HasRole(role Role) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// GetAllPermissions returns all permissions (role-based + custom)
func (u *User) GetAllPermissions() []Permission {
	permMap := make(map[Permission]bool)

	// Add custom permissions
	for _, p := range u.Permissions {
		permMap[p] = true
	}

	// Add role-based permissions
	for _, role := range u.Roles {
		rolePerms, exists := RolePermissions[role]
		if !exists {
			continue
		}
		for _, p := range rolePerms {
			permMap[p] = true
		}
	}

	// Convert map to slice
	permissions := make([]Permission, 0, len(permMap))
	for p := range permMap {
		permissions = append(permissions, p)
	}

	return permissions
}

// PasswordHasher handles password hashing and verification
type PasswordHasher struct {
	time    uint32
	memory  uint32
	threads uint8
	keyLen  uint32
}

// NewPasswordHasher creates a new password hasher with secure defaults
func NewPasswordHasher() *PasswordHasher {
	return &PasswordHasher{
		time:    1,         // 1 iteration
		memory:  64 * 1024, // 64 MB
		threads: 4,         // 4 threads
		keyLen:  32,        // 32 bytes
	}
}

// Hash hashes a password using Argon2id
func (h *PasswordHasher) Hash(password string) (string, error) {
	// Generate random salt
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Hash password
	hash := argon2.IDKey([]byte(password), salt, h.time, h.memory, h.threads, h.keyLen)

	// Encode as base64 with salt prepended
	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		h.memory,
		h.time,
		h.threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return encoded, nil
}

// Verify verifies a password against a hash
func (h *PasswordHasher) Verify(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	var version int
	var memory, time uint32
	var threads uint8
	var salt, hash string

	_, err := fmt.Sscanf(encodedHash, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		&version, &memory, &time, &threads, &salt, &hash)
	if err != nil {
		return false, fmt.Errorf("failed to parse hash: %w", err)
	}

	// Decode salt and hash
	saltBytes, err := base64.RawStdEncoding.DecodeString(salt)
	if err != nil {
		return false, fmt.Errorf("failed to decode salt: %w", err)
	}

	hashBytes, err := base64.RawStdEncoding.DecodeString(hash)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// Hash the password with the same parameters
	computedHash := argon2.IDKey([]byte(password), saltBytes, time, memory, threads, uint32(len(hashBytes)))

	// Constant-time comparison
	return subtle.ConstantTimeCompare(hashBytes, computedHash) == 1, nil
}

// Session represents a user session
type Session struct {
	ID           string                 `json:"id"`
	UserID       string                 `json:"user_id"`
	CreatedAt    time.Time              `json:"created_at"`
	ExpiresAt    time.Time              `json:"expires_at"`
	IP           string                 `json:"ip"`
	UserAgent    string                 `json:"user_agent"`
	RefreshToken string                 `json:"-"` // Never expose
	MFAVerified  bool                   `json:"mfa_verified"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
}

// IsValid checks if session is valid
func (s *Session) IsValid() bool {
	return time.Now().Before(s.ExpiresAt)
}

// Requires returns whether session requires MFA
func (s *Session) RequiresMFA() bool {
	return !s.MFAVerified
}

// APIKey represents an API key for programmatic access
type APIKey struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Key         string       `json:"key"` // Only shown once during creation
	KeyHash     string       `json:"-"`   // Stored in database
	UserID      string       `json:"user_id"`
	Scopes      []Permission `json:"scopes"`
	CreatedAt   time.Time    `json:"created_at"`
	ExpiresAt   *time.Time   `json:"expires_at,omitempty"`
	LastUsedAt  *time.Time   `json:"last_used_at,omitempty"`
	Disabled    bool         `json:"disabled"`
	Description string       `json:"description,omitempty"`
	RateLimit   int          `json:"rate_limit"` // Requests per minute
}

// IsValid checks if API key is valid
func (k *APIKey) IsValid() bool {
	if k.Disabled {
		return false
	}

	if k.ExpiresAt != nil && time.Now().After(*k.ExpiresAt) {
		return false
	}

	return true
}

// HasScope checks if API key has a specific scope
func (k *APIKey) HasScope(scope Permission) bool {
	for _, s := range k.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AccessControl manages access control
type AccessControl struct {
	users   map[string]*User
	apiKeys map[string]*APIKey
}

// NewAccessControl creates a new access control manager
func NewAccessControl() *AccessControl {
	return &AccessControl{
		users:   make(map[string]*User),
		apiKeys: make(map[string]*APIKey),
	}
}

// CheckPermission checks if user has permission
func (ac *AccessControl) CheckPermission(userID string, permission Permission) error {
	user, exists := ac.users[userID]
	if !exists {
		return errors.New("user not found")
	}

	if user.Disabled {
		return errors.New("user is disabled")
	}

	if !user.HasPermission(permission) {
		return fmt.Errorf("user does not have permission: %s", permission)
	}

	return nil
}

// CheckAPIKeyPermission checks if API key has permission
func (ac *AccessControl) CheckAPIKeyPermission(keyID string, scope Permission) error {
	apiKey, exists := ac.apiKeys[keyID]
	if !exists {
		return errors.New("API key not found")
	}

	if !apiKey.IsValid() {
		return errors.New("API key is invalid or expired")
	}

	if !apiKey.HasScope(scope) {
		return fmt.Errorf("API key does not have scope: %s", scope)
	}

	return nil
}

// AuditContext contains context for audit logging
type AuditContext struct {
	UserID    string
	SessionID string
	IP        string
	UserAgent string
	Action    string
}

// AuthenticationResult represents the result of authentication
type AuthenticationResult struct {
	Success      bool
	User         *User
	Session      *Session
	RequiresMFA  bool
	Error        string
	FailedReason string
}

// RateLimiter manages rate limiting
type RateLimiter struct {
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

// NewRateLimiter creates a new rate limiter
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
}

// Allow checks if request is allowed
func (r *RateLimiter) Allow(key string) bool {
	now := time.Now()

	// Get requests for this key
	requests := r.requests[key]

	// Remove old requests outside the window
	cutoff := now.Add(-r.window)
	validRequests := []time.Time{}
	for _, t := range requests {
		if t.After(cutoff) {
			validRequests = append(validRequests, t)
		}
	}

	// Check if under limit
	if len(validRequests) >= r.limit {
		return false
	}

	// Add current request
	validRequests = append(validRequests, now)
	r.requests[key] = validRequests

	return true
}

// Reset resets rate limit for a key
func (r *RateLimiter) Reset(key string) {
	delete(r.requests, key)
}
