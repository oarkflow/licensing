package licensing

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ==================== License Manager ====================

type Client struct {
	ID          string       `json:"id"`
	Username    string       `json:"username,omitempty"`
	Email       string       `json:"email"`
	Name        string       `json:"name,omitempty"`
	CompanyName string       `json:"company_name,omitempty"`
	Status      ClientStatus `json:"status"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
	BannedAt    time.Time    `json:"banned_at,omitempty"`
	BanReason   string       `json:"ban_reason,omitempty"`
	// Authentication fields (optional; persisted after migration)
	PasswordHash       []byte    `json:"-"`
	LastLogin          time.Time `json:"last_login,omitempty"`
	LoginAttempts      int       `json:"login_attempts,omitempty"`
	AccountLockedUntil time.Time `json:"account_locked_until,omitempty"`
}

// ClientSession represents a client session (non-admin)
type ClientSession struct {
	ID           string    `json:"id"`
	ClientID     string    `json:"client_id"`
	RefreshToken string    `json:"refresh_token"`
	CreatedAt    time.Time `json:"created_at"`
	ExpiresAt    time.Time `json:"expires_at"`
	IPAddress    string    `json:"ip_address,omitempty"`
	UserAgent    string    `json:"user_agent,omitempty"`
	Revoked      bool      `json:"revoked"`
}

type License struct {
	ID                     string                      `json:"id"`
	ClientID               string                      `json:"client_id"`
	Email                  string                      `json:"email"`
	ProductID              string                      `json:"product_id,omitempty"`
	PlanSlug               string                      `json:"plan_slug"`
	PlanID                 string                      `json:"plan_id,omitempty"`
	LicenseKey             string                      `json:"license_key"`
	IsRevoked              bool                        `json:"is_revoked"`
	RevokedAt              time.Time                   `json:"revoked_at,omitempty"`
	RevokeReason           string                      `json:"revoke_reason,omitempty"`
	IsActivated            bool                        `json:"is_activated"`
	IssuedAt               time.Time                   `json:"issued_at"`
	LastActivatedAt        time.Time                   `json:"last_activated_at,omitempty"`
	ExpiresAt              time.Time                   `json:"expires_at"`
	CurrentActivations     int                         `json:"current_activations"`
	MaxDevices             int                         `json:"max_devices"`
	DeviceCount            int                         `json:"device_count"`
	Devices                map[string]*LicenseDevice   `json:"devices"`
	AuthorizedUsers        map[string]*LicenseIdentity `json:"authorized_users,omitempty"`
	CheckMode              LicenseCheckMode            `json:"check_mode,omitempty"`
	CheckIntervalSecs      int64                       `json:"check_interval_seconds,omitempty"`
	NextCheckAt            time.Time                   `json:"next_check_at,omitempty"`
	LastCheckAt            time.Time                   `json:"last_check_at,omitempty"`
	Entitlements           *LicenseEntitlements        `json:"entitlements,omitempty"`
	IsTrial                bool                        `json:"is_trial"`
	TrialStartedAt         time.Time                   `json:"trial_started_at,omitempty"`
	TrialDeviceFingerprint string                      `json:"trial_device_fingerprint,omitempty"`
}

type LicenseCheckMode string

const (
	LicenseCheckModeNone    LicenseCheckMode = "none"
	LicenseCheckModeEachRun LicenseCheckMode = "each_execution"
	LicenseCheckModeMonthly LicenseCheckMode = "monthly"
	LicenseCheckModeYearly  LicenseCheckMode = "yearly"
	LicenseCheckModeCustom  LicenseCheckMode = "custom"
)

func ParseLicenseCheckMode(input string) LicenseCheckMode {
	switch strings.ToLower(strings.TrimSpace(input)) {
	case string(LicenseCheckModeNone):
		return LicenseCheckModeNone
	case string(LicenseCheckModeMonthly):
		return LicenseCheckModeMonthly
	case string(LicenseCheckModeYearly):
		return LicenseCheckModeYearly
	case string(LicenseCheckModeCustom):
		return LicenseCheckModeCustom
	default:
		return LicenseCheckModeYearly
	}
}

func (m LicenseCheckMode) String() string {
	if m == "" {
		return string(LicenseCheckModeYearly)
	}
	return string(m)
}

func (m LicenseCheckMode) RequiresSchedule() bool {
	switch m {
	case LicenseCheckModeNone:
		return false
	default:
		return true
	}
}

type LicenseIdentity struct {
	Email            string    `json:"email"`
	ClientID         string    `json:"client_id,omitempty"`
	ProviderClientID string    `json:"provider_client_id,omitempty"`
	GrantedAt        time.Time `json:"granted_at"`
}

type ActivationRequest struct {
	Email             string       `json:"email"`
	ClientID          string       `json:"client_id,omitempty"`
	LicenseKey        string       `json:"license_key"`
	DeviceFingerprint string       `json:"device_fingerprint"`
	ProductID         string       `json:"product_id,omitempty"` // Product ID or slug to validate license against
	ReplacementToken  string       `json:"replacement_token,omitempty"`
	DeviceProof       *DeviceProof `json:"device_proof,omitempty"`
	IPAddress         string       `json:"-"`
	UserAgent         string       `json:"-"`
	AppVersion        string       `json:"-"`
}

type ActivationResponse struct {
	Success          bool      `json:"success"`
	Message          string    `json:"message"`
	EncryptedLicense string    `json:"encrypted_license,omitempty"`
	Nonce            string    `json:"nonce,omitempty"`
	Signature        string    `json:"signature,omitempty"`
	PublicKey        string    `json:"public_key,omitempty"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
}

type ClientStatus string

const (
	ClientStatusActive ClientStatus = "active"
	ClientStatusBanned ClientStatus = "banned"
)

type LicenseDevice struct {
	Fingerprint           string    `json:"fingerprint"`
	ActivatedAt           time.Time `json:"activated_at"`
	LastSeenAt            time.Time `json:"last_seen_at"`
	TransportKey          []byte    `json:"-"`
	Status                string    `json:"status,omitempty"`
	Label                 string    `json:"label,omitempty"`
	HardwareFingerprint   string    `json:"hardware_fingerprint,omitempty"`
	HardwareConfidence    string    `json:"hardware_confidence,omitempty"`
	LastIP                string    `json:"last_ip,omitempty"`
	LastUserAgent         string    `json:"last_user_agent,omitempty"`
	AppVersion            string    `json:"app_version,omitempty"`
	ProofVersion          int       `json:"proof_version,omitempty"`
	DeviceKeyID           string    `json:"device_key_id,omitempty"`
	DevicePublicKey       []byte    `json:"device_public_key,omitempty"`
	PublicKeyAlgorithm    string    `json:"public_key_algorithm,omitempty"`
	KeyProvider           string    `json:"key_provider,omitempty"`
	AttestationType       string    `json:"attestation_type,omitempty"`
	AttestationStatus     string    `json:"attestation_status,omitempty"`
	LastProofAt           time.Time `json:"last_proof_at,omitempty"`
	RevokedAt             time.Time `json:"revoked_at,omitempty"`
	RevokedReason         string    `json:"revoked_reason,omitempty"`
	ReplacedByFingerprint string    `json:"replaced_by_fingerprint,omitempty"`
	ReplacementTokenID    string    `json:"replacement_token_id,omitempty"`
}

const (
	DeviceStatusTrusted            = "trusted"
	DeviceStatusRevoked            = "revoked"
	DeviceStatusReplacementPending = "replacement_pending"
	DeviceStatusReplaced           = "replaced"
	DeviceStatusSuspicious         = "suspicious"

	DeviceProofVersionV2             = 2
	DeviceProofAlgorithmEd25519      = "ed25519"
	DeviceProofAlgorithmRSAPSSSHA256 = "rsa-pss-sha256"
	DeviceProofPurposeActivate       = "activate"
	DeviceProofPurposeVerify         = "verify"
	DeviceProofPurposeTrial          = "trial"
)

type DeviceProof struct {
	Version            int               `json:"version"`
	Purpose            string            `json:"purpose"`
	ChallengeID        string            `json:"challenge_id"`
	Nonce              string            `json:"nonce"`
	Fingerprint        string            `json:"fingerprint"`
	KeyID              string            `json:"key_id"`
	KeyProvider        string            `json:"key_provider"`
	PublicKeyAlgorithm string            `json:"public_key_alg"`
	PublicKey          string            `json:"public_key"`
	Signature          string            `json:"signature"`
	Attestation        map[string]string `json:"attestation,omitempty"`
}

type DeviceProofPayload struct {
	Purpose     string
	ChallengeID string
	Nonce       string
	LicenseKey  string
	ClientID    string
	Email       string
	ProductID   string
	Fingerprint string
	PublicKey   []byte
}

func DeviceProofPublicKeyID(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	return hex.EncodeToString(sum[:])
}

func DeviceProofFingerprint(algorithm string, publicKey []byte) string {
	algorithm = strings.ToLower(strings.TrimSpace(algorithm))
	if algorithm == "" {
		algorithm = "unknown"
	}
	return "fp:v2:" + algorithm + ":" + DeviceProofPublicKeyID(publicKey)
}

func EncodeDeviceProofBytes(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}

func DecodeDeviceProofBytes(value string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(strings.TrimSpace(value))
}

func CanonicalDeviceProofPayload(payload DeviceProofPayload) []byte {
	publicKeyHash := DeviceProofPublicKeyID(payload.PublicKey)
	parts := []string{
		"v=2",
		"purpose=" + strings.ToLower(strings.TrimSpace(payload.Purpose)),
		"challenge_id=" + strings.TrimSpace(payload.ChallengeID),
		"nonce=" + strings.TrimSpace(payload.Nonce),
		"license_key=" + normalizeLicenseKey(payload.LicenseKey),
		"client_id=" + strings.TrimSpace(payload.ClientID),
		"email=" + normalizeEmail(payload.Email),
		"product_id=" + strings.TrimSpace(payload.ProductID),
		"fingerprint=" + strings.TrimSpace(payload.Fingerprint),
		"public_key_sha256=" + publicKeyHash,
	}
	return []byte(strings.Join(parts, "\n"))
}

func VerifyDeviceProofSignature(proof *DeviceProof, payload DeviceProofPayload) ([]byte, error) {
	if proof == nil {
		return nil, fmt.Errorf("device proof required")
	}
	if proof.Version != DeviceProofVersionV2 {
		return nil, fmt.Errorf("unsupported device proof version")
	}
	algorithm := strings.ToLower(strings.TrimSpace(proof.PublicKeyAlgorithm))
	if algorithm != DeviceProofAlgorithmEd25519 && algorithm != DeviceProofAlgorithmRSAPSSSHA256 {
		return nil, fmt.Errorf("unsupported device proof public key algorithm")
	}
	publicKey, err := DecodeDeviceProofBytes(proof.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("invalid device proof public key: %w", err)
	}
	signature, err := DecodeDeviceProofBytes(proof.Signature)
	if err != nil {
		return nil, fmt.Errorf("invalid device proof signature: %w", err)
	}
	payload.PublicKey = publicKey
	canonicalPayload := CanonicalDeviceProofPayload(payload)
	switch algorithm {
	case DeviceProofAlgorithmEd25519:
		if len(publicKey) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid device proof public key size")
		}
		if len(signature) != ed25519.SignatureSize {
			return nil, fmt.Errorf("invalid device proof signature size")
		}
		if !ed25519.Verify(ed25519.PublicKey(publicKey), canonicalPayload, signature) {
			return nil, fmt.Errorf("device proof signature invalid")
		}
	case DeviceProofAlgorithmRSAPSSSHA256:
		parsed, err := x509.ParsePKIXPublicKey(publicKey)
		if err != nil {
			return nil, fmt.Errorf("invalid rsa device proof public key: %w", err)
		}
		rsaPublicKey, ok := parsed.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("device proof public key is not RSA")
		}
		digest := sha256.Sum256(canonicalPayload)
		if err := rsa.VerifyPSS(rsaPublicKey, crypto.SHA256, digest[:], signature, nil); err != nil {
			return nil, fmt.Errorf("device proof signature invalid")
		}
	}
	expectedKeyID := DeviceProofPublicKeyID(publicKey)
	if strings.TrimSpace(proof.KeyID) != "" && !strings.EqualFold(strings.TrimSpace(proof.KeyID), expectedKeyID) {
		return nil, fmt.Errorf("device proof key id mismatch")
	}
	expectedFingerprint := DeviceProofFingerprint(algorithm, publicKey)
	proofFingerprint := normalizeDeviceFingerprint(proof.Fingerprint)
	if proofFingerprint != "" && proofFingerprint != expectedFingerprint {
		return nil, fmt.Errorf("device proof fingerprint mismatch")
	}
	return publicKey, nil
}

type ActivationRecord struct {
	ID                string    `json:"id"`
	LicenseID         string    `json:"license_id"`
	ClientID          string    `json:"client_id"`
	DeviceFingerprint string    `json:"device_fingerprint"`
	IPAddress         string    `json:"ip_address"`
	UserAgent         string    `json:"user_agent"`
	Success           bool      `json:"success"`
	Message           string    `json:"message"`
	Timestamp         time.Time `json:"timestamp"`
}

func cloneClient(client *Client) *Client {
	if client == nil {
		return nil
	}
	clone := *client
	return &clone
}

func cloneLicense(license *License) *License {
	if license == nil {
		return nil
	}
	clone := *license
	if license.Devices != nil {
		clone.Devices = make(map[string]*LicenseDevice, len(license.Devices))
		for fp, dev := range license.Devices {
			if dev == nil {
				continue
			}
			copyDev := *dev
			if len(dev.TransportKey) > 0 {
				copyDev.TransportKey = append([]byte(nil), dev.TransportKey...)
			}
			if len(dev.DevicePublicKey) > 0 {
				copyDev.DevicePublicKey = append([]byte(nil), dev.DevicePublicKey...)
			}
			clone.Devices[fp] = &copyDev
		}
	}
	if license.AuthorizedUsers != nil {
		clone.AuthorizedUsers = make(map[string]*LicenseIdentity, len(license.AuthorizedUsers))
		for key, ident := range license.AuthorizedUsers {
			if ident == nil {
				continue
			}
			copyIdent := *ident
			clone.AuthorizedUsers[key] = &copyIdent
		}
	}
	refreshLicenseDeviceStats(&clone)
	return &clone
}

func refreshLicenseDeviceStats(license *License) {
	if license == nil {
		return
	}
	deviceCount := 0
	for _, device := range license.Devices {
		if device == nil {
			continue
		}
		device.Status = normalizeDeviceStatus(device.Status)
		if device.Status == DeviceStatusTrusted || device.Status == DeviceStatusReplacementPending {
			deviceCount++
		}
	}
	license.DeviceCount = deviceCount
	license.CurrentActivations = deviceCount
	if license.MaxDevices <= 0 {
		license.MaxDevices = 1
	}
}

func normalizeDeviceStatus(status string) string {
	switch strings.TrimSpace(status) {
	case DeviceStatusTrusted, DeviceStatusRevoked, DeviceStatusReplacementPending, DeviceStatusReplaced, DeviceStatusSuspicious:
		return strings.TrimSpace(status)
	default:
		return DeviceStatusTrusted
	}
}

func cloneActivationRecord(record *ActivationRecord) *ActivationRecord {
	if record == nil {
		return nil
	}
	clone := *record
	return &clone
}

func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

func licenseIdentityKey(email string) string {
	return normalizeEmail(email)
}

var (
	emailRegex               = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	licenseKeyRegex          = regexp.MustCompile(`^[A-Z2-7]{5}(?:-?[A-Z2-7]{5}){7}$`)
	proofFingerprintRegex    = regexp.MustCompile(`^fp:v2:[a-z0-9][a-z0-9-]{1,31}:[a-f0-9]{64}$`)
	hardwareFingerprintRegex = regexp.MustCompile(`^hw:v1:[a-f0-9]{64}$`)
)

const maxActivationPayloadBytes = 1 << 20

func normalizeLicenseKey(key string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(key))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	return cleaned
}

func normalizeDeviceFingerprint(fingerprint string) string {
	parts := strings.Split(strings.TrimSpace(fingerprint), ":")
	if len(parts) != 4 {
		return strings.TrimSpace(fingerprint)
	}
	return strings.ToLower(parts[0]) + ":" + strings.ToLower(parts[1]) + ":" + strings.ToLower(parts[2]) + ":" + strings.ToLower(parts[3])
}

func validateProofDeviceFingerprint(fingerprint string) error {
	fingerprint = normalizeDeviceFingerprint(fingerprint)
	if !proofFingerprintRegex.MatchString(fingerprint) {
		return errors.New("invalid device fingerprint format")
	}
	algorithm := strings.Split(fingerprint, ":")[2]
	switch algorithm {
	case DeviceProofAlgorithmEd25519, DeviceProofAlgorithmRSAPSSSHA256:
		return nil
	default:
		return errors.New("unsupported device fingerprint algorithm")
	}
}

func validateHardwareFingerprint(fingerprint string) error {
	if !hardwareFingerprintRegex.MatchString(strings.ToLower(strings.TrimSpace(fingerprint))) {
		return errors.New("invalid hardware fingerprint format")
	}
	return nil
}

func validateActivationRequest(req *ActivationRequest) error {
	if req == nil {
		return errors.New("request missing")
	}
	email := strings.TrimSpace(req.Email)
	if !emailRegex.MatchString(email) {
		return errors.New("invalid email address")
	}
	clientID := strings.TrimSpace(req.ClientID)
	if clientID == "" {
		return errors.New("client_id is required")
	}
	keyCandidate := strings.ToUpper(strings.TrimSpace(req.LicenseKey))
	keyCandidate = strings.ReplaceAll(keyCandidate, " ", "")
	if !licenseKeyRegex.MatchString(keyCandidate) {
		return errors.New("invalid license key format")
	}
	req.DeviceFingerprint = normalizeDeviceFingerprint(req.DeviceFingerprint)
	if err := validateProofDeviceFingerprint(req.DeviceFingerprint); err != nil {
		return err
	}
	return nil
}

// ==================== HTTP Server ====================

const maxAdminPayloadBytes = 256 << 10

type createClientRequest struct {
	Email       string            `json:"email"`
	Name        string            `json:"name,omitempty"`
	CompanyName string            `json:"company_name,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	Username    string            `json:"username,omitempty"`
	Password    string            `json:"password,omitempty"`
}

type banClientRequest struct {
	Reason string `json:"reason"`
}

// FeatureScopeSelection represents the desired feature/scopes state for a license.
type FeatureScopeSelection struct {
	FeatureID   string           `json:"feature_id,omitempty"`
	FeatureSlug string           `json:"feature_slug"`
	Enabled     bool             `json:"enabled"`
	Scopes      []ScopeSelection `json:"scopes,omitempty"`
}

// ScopeSelection represents the desired permission for a scope.
type ScopeSelection struct {
	ScopeID    string            `json:"scope_id,omitempty"`
	ScopeSlug  string            `json:"scope_slug"`
	Permission ScopePermission   `json:"permission"`
	Limit      int               `json:"limit,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type CouponCode struct {
	ID                      string               `json:"id"`
	Code                    string               `json:"code"`
	Name                    string               `json:"name"`
	Description             string               `json:"description,omitempty"`
	ProductID               string               `json:"product_id,omitempty"`
	AllowedClientIDs        []string             `json:"allowed_client_ids,omitempty"`
	MaxRedemptions          int                  `json:"max_redemptions,omitempty"`
	MaxRedemptionsPerClient int                  `json:"max_redemptions_per_client,omitempty"`
	IsActive                bool                 `json:"is_active"`
	StartsAt                time.Time            `json:"starts_at,omitempty"`
	ExpiresAt               time.Time            `json:"expires_at,omitempty"`
	Metadata                map[string]string    `json:"metadata,omitempty"`
	Features                []CouponFeaturePatch `json:"features,omitempty"`
	CreatedAt               time.Time            `json:"created_at"`
	UpdatedAt               time.Time            `json:"updated_at"`
}

type CouponFeaturePatch struct {
	FeatureID   string             `json:"feature_id,omitempty"`
	FeatureSlug string             `json:"feature_slug,omitempty"`
	Enabled     *bool              `json:"enabled,omitempty"`
	Metadata    map[string]string  `json:"metadata,omitempty"`
	Scopes      []CouponScopePatch `json:"scopes,omitempty"`
}

type CouponScopePatch struct {
	ScopeID    string            `json:"scope_id,omitempty"`
	ScopeSlug  string            `json:"scope_slug,omitempty"`
	Permission ScopePermission   `json:"permission,omitempty"`
	Limit      *int              `json:"limit,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type CouponRedemption struct {
	ID         string            `json:"id"`
	CouponID   string            `json:"coupon_id"`
	CouponCode string            `json:"coupon_code"`
	LicenseID  string            `json:"license_id"`
	ClientID   string            `json:"client_id"`
	RedeemedBy string            `json:"redeemed_by,omitempty"`
	RedeemedAt time.Time         `json:"redeemed_at"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type createLicenseRequest struct {
	ClientID             string                  `json:"client_id"`
	ProductID            string                  `json:"product_id,omitempty"`
	PlanID               string                  `json:"plan_id,omitempty"`
	DurationDays         int                     `json:"duration_days"`
	MaxDevices           int                     `json:"max_devices"`
	CheckMode            string                  `json:"check_mode,omitempty"`
	CheckIntervalSeconds int64                   `json:"check_interval_seconds,omitempty"`
	PlanSlug             string                  `json:"plan_slug"`
	IsTrial              bool                    `json:"is_trial,omitempty"`
	Metadata             map[string]string       `json:"metadata,omitempty"`
	FeatureScopes        []FeatureScopeSelection `json:"feature_scopes,omitempty"`
}

type licenseMutationRequest struct {
	Reason string `json:"reason"`
}

type upgradePlanRequest struct {
	ProductID    string            `json:"product_id"`
	PlanID       string            `json:"plan_id"`
	MaxDevices   int               `json:"max_devices,omitempty"`
	DurationDays int               `json:"duration_days,omitempty"`
	Trial        bool              `json:"trial,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type createAdminUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createAPIKeyRequest struct {
	UserID         string   `json:"user_id"`
	Scopes         []string `json:"scopes,omitempty"`
	AllowedIPs     []string `json:"allowed_ips,omitempty"`
	AllowedOrigins []string `json:"allowed_origins,omitempty"`
	ExpiresAt      string   `json:"expires_at,omitempty"`
	TTLHours       int      `json:"ttl_hours,omitempty"`
}

type trialLicenseAPIRequest struct {
	Email             string            `json:"email"`
	DeviceFingerprint string            `json:"device_fingerprint"`
	ProductID         string            `json:"product_id,omitempty"`
	TrialDurationDays int               `json:"trial_duration_days,omitempty"`
	SubscriptionURL   string            `json:"subscription_url,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	DeviceProof       *DeviceProof      `json:"device_proof,omitempty"`
}

type provisionLicenseRequest struct {
	Email       string            `json:"email"`
	Name        string            `json:"name,omitempty"`
	CompanyName string            `json:"company_name,omitempty"`
	ProductID   string            `json:"product_id"`
	PlanID      string            `json:"plan_id"`
	IsTrial     bool              `json:"is_trial,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
}
