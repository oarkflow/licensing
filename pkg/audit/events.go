package audit

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
)

// EventType represents the type of audit event
type EventType string

const (
	// License Events
	EventLicenseCreated     EventType = "license.created"
	EventLicenseUpdated     EventType = "license.updated"
	EventLicenseRevoked     EventType = "license.revoked"
	EventLicenseActivated   EventType = "license.activated"
	EventLicenseDeactivated EventType = "license.deactivated"
	EventLicenseVerified    EventType = "license.verified"
	EventLicenseExpired     EventType = "license.expired"

	// Activation Events
	EventActivationAttempted   EventType = "activation.attempted"
	EventActivationSucceeded   EventType = "activation.succeeded"
	EventActivationFailed      EventType = "activation.failed"
	EventDeactivationAttempted EventType = "deactivation.attempted"
	EventDeactivationSucceeded EventType = "deactivation.succeeded"
	EventDeactivationFailed    EventType = "deactivation.failed"

	// Verification Events
	EventVerificationSucceeded EventType = "verification.succeeded"
	EventVerificationFailed    EventType = "verification.failed"
	EventVerificationExpired   EventType = "verification.expired"
	EventVerificationTampered  EventType = "verification.tampered"

	// Security Events
	EventSecurityIntrusion    EventType = "security.intrusion"
	EventSecurityTampering    EventType = "security.tampering"
	EventSecurityUnauthorized EventType = "security.unauthorized"
	EventSecurityBruteForce   EventType = "security.brute_force"
	EventSecurityAnomaly      EventType = "security.anomaly"

	// Admin Events
	EventAdminLogin    EventType = "admin.login"
	EventAdminLogout   EventType = "admin.logout"
	EventAdminAction   EventType = "admin.action"
	EventConfigChanged EventType = "config.changed"
	EventKeyRotated    EventType = "key.rotated"

	// API Events
	EventAPIAccess      EventType = "api.access"
	EventAPIRateLimited EventType = "api.rate_limited"
	EventAPIError       EventType = "api.error"
	EventAPIRequest     EventType = "api.request"

	// Product Events
	EventProductCreated EventType = "product.created"
	EventProductUpdated EventType = "product.updated"
	EventProductDeleted EventType = "product.deleted"

	// Plan Events
	EventPlanCreated EventType = "plan.created"
	EventPlanUpdated EventType = "plan.updated"
	EventPlanDeleted EventType = "plan.deleted"

	// Billing Events
	EventBillingGatewayChanged      EventType = "billing.gateway.changed"
	EventBillingSubscriptionChanged EventType = "billing.subscription.changed"
	EventBillingInvoiceChanged      EventType = "billing.invoice.changed"
	EventBillingPaymentChanged      EventType = "billing.payment.changed"
	EventBillingApproval            EventType = "billing.approval"
	EventBillingJob                 EventType = "billing.job"
	EventBillingWebhook             EventType = "billing.webhook"

	// Authentication Events
	EventAuthLogin  EventType = "auth.login"
	EventAuthLogout EventType = "auth.logout"
	EventAuthFailed EventType = "auth.failed"

	// System Events
	EventSystemStartup  EventType = "system.startup"
	EventSystemShutdown EventType = "system.shutdown"
	EventSystemError    EventType = "system.error"
)

// Severity represents the severity level of an audit event
type Severity string

const (
	SeverityInfo     Severity = "info"
	SeverityWarning  Severity = "warning"
	SeverityError    Severity = "error"
	SeverityCritical Severity = "critical"
)

// Event represents an audit log event
type Event struct {
	ID           string                 `json:"id"`
	Type         EventType              `json:"type"`
	Severity     Severity               `json:"severity"`
	Timestamp    time.Time              `json:"timestamp"`
	ActorID      string                 `json:"actor_id,omitempty"`   // User/system that triggered the event
	ActorType    string                 `json:"actor_type,omitempty"` // "user", "system", "api"
	ActorIP      string                 `json:"actor_ip,omitempty"`
	ResourceID   string                 `json:"resource_id,omitempty"`   // ID of affected resource
	ResourceType string                 `json:"resource_type,omitempty"` // "license", "product", "plan"
	Action       string                 `json:"action"`                  // Description of action
	Result       string                 `json:"result"`                  // "success", "failure", "partial"
	Message      string                 `json:"message"`
	Metadata     map[string]interface{} `json:"metadata,omitempty"`
	ErrorCode    string                 `json:"error_code,omitempty"`
	ErrorMessage string                 `json:"error_message,omitempty"`
	SessionID    string                 `json:"session_id,omitempty"`
	RequestID    string                 `json:"request_id,omitempty"`
	UserAgent    string                 `json:"user_agent,omitempty"`
	Location     *Location              `json:"location,omitempty"`

	// Cryptographic proof (for tamper detection)
	Hash      string `json:"hash,omitempty"`
	Signature string `json:"signature,omitempty"`
	PrevHash  string `json:"prev_hash,omitempty"` // Link to previous event for chain
}

// Location represents geographical location data
type Location struct {
	Country   string  `json:"country,omitempty"`
	Region    string  `json:"region,omitempty"`
	City      string  `json:"city,omitempty"`
	Latitude  float64 `json:"latitude,omitempty"`
	Longitude float64 `json:"longitude,omitempty"`
}

// NewEvent creates a new audit event
func NewEvent(eventType EventType, severity Severity, action, message string) *Event {
	return &Event{
		ID:        uuid.New().String(),
		Type:      eventType,
		Severity:  severity,
		Timestamp: time.Now().UTC(),
		Action:    action,
		Message:   message,
		Metadata:  make(map[string]interface{}),
	}
}

// WithActor sets the actor information
func (e *Event) WithActor(actorID, actorType, actorIP string) *Event {
	e.ActorID = actorID
	e.ActorType = actorType
	e.ActorIP = actorIP
	return e
}

// WithResource sets the resource information
func (e *Event) WithResource(resourceID, resourceType string) *Event {
	e.ResourceID = resourceID
	e.ResourceType = resourceType
	return e
}

// WithResult sets the result of the action
func (e *Event) WithResult(result string) *Event {
	e.Result = result
	return e
}

// WithError sets error information
func (e *Event) WithError(errorCode, errorMessage string) *Event {
	e.ErrorCode = errorCode
	e.ErrorMessage = errorMessage
	return e
}

// WithMetadata adds metadata to the event
func (e *Event) WithMetadata(key string, value interface{}) *Event {
	e.Metadata[key] = value
	return e
}

// WithRequest sets request-related information
func (e *Event) WithRequest(requestID, sessionID, userAgent string) *Event {
	e.RequestID = requestID
	e.SessionID = sessionID
	e.UserAgent = userAgent
	return e
}

// WithLocation sets geographical location
func (e *Event) WithLocation(location *Location) *Event {
	e.Location = location
	return e
}

// ToJSON serializes the event to JSON
func (e *Event) ToJSON() ([]byte, error) {
	return json.Marshal(e)
}

// FromJSON deserializes an event from JSON
func FromJSON(data []byte) (*Event, error) {
	var event Event
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event: %w", err)
	}
	return &event, nil
}

// SecurityContext provides additional security context for audit events
type SecurityContext struct {
	TLSVersion       string   `json:"tls_version,omitempty"`
	CipherSuite      string   `json:"cipher_suite,omitempty"`
	ClientCertSerial string   `json:"client_cert_serial,omitempty"`
	MFAUsed          bool     `json:"mfa_used,omitempty"`
	RiskScore        int      `json:"risk_score,omitempty"` // 0-100
	Flags            []string `json:"flags,omitempty"`      // ["suspicious_ip", "new_device", etc.]
}

// AuditFilter represents filtering criteria for audit logs
type AuditFilter struct {
	StartTime    *time.Time
	EndTime      *time.Time
	EventTypes   []EventType
	Severities   []Severity
	ActorID      string
	ResourceID   string
	ResourceType string
	Result       string
	Limit        int
	Offset       int
}

// EventStatistics represents aggregated audit statistics
type EventStatistics struct {
	TotalEvents      int64               `json:"total_events"`
	EventsByType     map[EventType]int64 `json:"events_by_type"`
	EventsBySeverity map[Severity]int64  `json:"events_by_severity"`
	FailedEvents     int64               `json:"failed_events"`
	SecurityEvents   int64               `json:"security_events"`
	TimeRange        TimeRange           `json:"time_range"`
}

// TimeRange represents a time range
type TimeRange struct {
	Start time.Time `json:"start"`
	End   time.Time `json:"end"`
}

// ComplianceReport represents a compliance-focused audit report
type ComplianceReport struct {
	ReportID        string                `json:"report_id"`
	GeneratedAt     time.Time             `json:"generated_at"`
	TimeRange       TimeRange             `json:"time_range"`
	TotalEvents     int64                 `json:"total_events"`
	Compliance      string                `json:"compliance"` // "SOC2", "GDPR", "HIPAA"
	Events          []*Event              `json:"events"`
	Statistics      *EventStatistics      `json:"statistics"`
	Violations      []ComplianceViolation `json:"violations,omitempty"`
	Recommendations []string              `json:"recommendations,omitempty"`
}

// ComplianceViolation represents a compliance violation
type ComplianceViolation struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Severity    Severity  `json:"severity"`
	Description string    `json:"description"`
	EventID     string    `json:"event_id"`
	Timestamp   time.Time `json:"timestamp"`
	Remediation string    `json:"remediation"`
}

// Helper functions for common audit events

// LogLicenseCreated logs a license creation event
func LogLicenseCreated(licenseID, actorID, actorIP string, metadata map[string]interface{}) *Event {
	event := NewEvent(EventLicenseCreated, SeverityInfo, "create_license", "License created successfully")
	event.WithActor(actorID, "user", actorIP).
		WithResource(licenseID, "license").
		WithResult("success")
	for k, v := range metadata {
		event.WithMetadata(k, v)
	}
	return event
}

// LogVerificationFailed logs a failed verification attempt
func LogVerificationFailed(licenseID, reason, clientIP string) *Event {
	event := NewEvent(EventVerificationFailed, SeverityWarning, "verify_license", "License verification failed")
	event.WithActor("system", "system", clientIP).
		WithResource(licenseID, "license").
		WithResult("failure").
		WithMetadata("reason", reason)
	return event
}

// LogSecurityIntrusion logs a security intrusion attempt
func LogSecurityIntrusion(actorIP, description string, metadata map[string]interface{}) *Event {
	event := NewEvent(EventSecurityIntrusion, SeverityCritical, "intrusion_detected", description)
	event.WithActor("unknown", "unknown", actorIP).
		WithResult("detected")
	for k, v := range metadata {
		event.WithMetadata(k, v)
	}
	return event
}

// LogTamperingDetected logs tampering detection
func LogTamperingDetected(resourceID, resourceType, description string) *Event {
	event := NewEvent(EventSecurityTampering, SeverityCritical, "tampering_detected", description)
	event.WithResource(resourceID, resourceType).
		WithResult("detected")
	return event
}

// LogAdminAction logs an administrative action
func LogAdminAction(actorID, actorIP, action, description string, metadata map[string]interface{}) *Event {
	event := NewEvent(EventAdminAction, SeverityInfo, action, description)
	event.WithActor(actorID, "admin", actorIP).
		WithResult("success")
	for k, v := range metadata {
		event.WithMetadata(k, v)
	}
	return event
}
