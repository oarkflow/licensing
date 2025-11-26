package licensing

import (
	"errors"
	"regexp"
	"strings"
	"time"
)

// ==================== License Manager ====================

type Client struct {
	ID        string       `json:"id"`
	Email     string       `json:"email"`
	Status    ClientStatus `json:"status"`
	CreatedAt time.Time    `json:"created_at"`
	UpdatedAt time.Time    `json:"updated_at"`
	BannedAt  time.Time    `json:"banned_at,omitempty"`
	BanReason string       `json:"ban_reason,omitempty"`
}

type License struct {
	ID                 string                      `json:"id"`
	ClientID           string                      `json:"client_id"`
	Email              string                      `json:"email"`
	PlanSlug           string                      `json:"plan_slug"`
	LicenseKey         string                      `json:"license_key"`
	IsRevoked          bool                        `json:"is_revoked"`
	RevokedAt          time.Time                   `json:"revoked_at,omitempty"`
	RevokeReason       string                      `json:"revoke_reason,omitempty"`
	IsActivated        bool                        `json:"is_activated"`
	IssuedAt           time.Time                   `json:"issued_at"`
	LastActivatedAt    time.Time                   `json:"last_activated_at,omitempty"`
	ExpiresAt          time.Time                   `json:"expires_at"`
	CurrentActivations int                         `json:"current_activations"`
	MaxDevices         int                         `json:"max_devices"`
	DeviceCount        int                         `json:"device_count"`
	Devices            map[string]*LicenseDevice   `json:"devices"`
	AuthorizedUsers    map[string]*LicenseIdentity `json:"authorized_users,omitempty"`
	CheckMode          LicenseCheckMode            `json:"check_mode,omitempty"`
	CheckIntervalSecs  int64                       `json:"check_interval_seconds,omitempty"`
	NextCheckAt        time.Time                   `json:"next_check_at,omitempty"`
	LastCheckAt        time.Time                   `json:"last_check_at,omitempty"`
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
	Email             string `json:"email"`
	ClientID          string `json:"client_id,omitempty"`
	LicenseKey        string `json:"license_key"`
	DeviceFingerprint string `json:"device_fingerprint"`
	IPAddress         string `json:"-"`
	UserAgent         string `json:"-"`
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
	Fingerprint  string    `json:"fingerprint"`
	ActivatedAt  time.Time `json:"activated_at"`
	LastSeenAt   time.Time `json:"last_seen_at"`
	TransportKey []byte    `json:"-"`
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
	deviceCount := len(license.Devices)
	license.DeviceCount = deviceCount
	license.CurrentActivations = deviceCount
	if license.MaxDevices <= 0 {
		license.MaxDevices = 1
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
	emailRegex       = regexp.MustCompile(`^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`)
	licenseKeyRegex  = regexp.MustCompile(`^[A-Z2-7]{5}(?:-?[A-Z2-7]{5}){7}$`)
	fingerprintRegex = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)
)

const maxActivationPayloadBytes = 1 << 20

func normalizeLicenseKey(key string) string {
	cleaned := strings.ToUpper(strings.TrimSpace(key))
	cleaned = strings.ReplaceAll(cleaned, "-", "")
	cleaned = strings.ReplaceAll(cleaned, " ", "")
	return cleaned
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
	if !fingerprintRegex.MatchString(strings.TrimSpace(req.DeviceFingerprint)) {
		return errors.New("invalid device fingerprint format")
	}
	return nil
}

// ==================== HTTP Server ====================

const maxAdminPayloadBytes = 256 << 10

type createClientRequest struct {
	Email string `json:"email"`
}

type banClientRequest struct {
	Reason string `json:"reason"`
}

type createLicenseRequest struct {
	ClientID             string `json:"client_id"`
	DurationDays         int    `json:"duration_days"`
	MaxDevices           int    `json:"max_devices"`
	CheckMode            string `json:"check_mode,omitempty"`
	CheckIntervalSeconds int64  `json:"check_interval_seconds,omitempty"`
	PlanSlug             string `json:"plan_slug"`
}

type licenseMutationRequest struct {
	Reason string `json:"reason"`
}

type createAdminUserRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type createAPIKeyRequest struct {
	UserID string `json:"user_id"`
}
