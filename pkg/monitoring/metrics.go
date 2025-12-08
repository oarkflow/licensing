package monitoring

import (
	"fmt"
	"sync"
	"time"
)

// SecurityMetrics tracks security-related metrics
type SecurityMetrics struct {
	mu sync.RWMutex

	// Authentication metrics
	TotalLoginAttempts  int64
	FailedLoginAttempts int64
	SuccessfulLogins    int64
	MFAUsage            int64

	// License metrics
	LicenseCreations     int64
	LicenseVerifications int64
	FailedVerifications  int64
	TamperingDetections  int64

	// Security events
	UnauthorizedAccess int64
	RateLimitHits      int64
	IntrusionAttempts  int64

	// System metrics
	KeyRotations int64
	AuditEvents  int64

	// Time-series data
	LastUpdated time.Time
}

// NewSecurityMetrics creates new security metrics tracker
func NewSecurityMetrics() *SecurityMetrics {
	return &SecurityMetrics{
		LastUpdated: time.Now(),
	}
}

// IncrementLoginAttempt increments login attempt counter
func (sm *SecurityMetrics) IncrementLoginAttempt(success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.TotalLoginAttempts++
	if success {
		sm.SuccessfulLogins++
	} else {
		sm.FailedLoginAttempts++
	}
	sm.LastUpdated = time.Now()
}

// IncrementLicenseVerification increments verification counter
func (sm *SecurityMetrics) IncrementLicenseVerification(success bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.LicenseVerifications++
	if !success {
		sm.FailedVerifications++
	}
	sm.LastUpdated = time.Now()
}

// RecordTampering records a tampering detection
func (sm *SecurityMetrics) RecordTampering() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.TamperingDetections++
	sm.LastUpdated = time.Now()
}

// RecordUnauthorizedAccess records unauthorized access attempt
func (sm *SecurityMetrics) RecordUnauthorizedAccess() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.UnauthorizedAccess++
	sm.LastUpdated = time.Now()
}

// RecordRateLimitHit records rate limit hit
func (sm *SecurityMetrics) RecordRateLimitHit() {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	sm.RateLimitHits++
	sm.LastUpdated = time.Now()
}

// GetSnapshot returns a snapshot of current metrics
func (sm *SecurityMetrics) GetSnapshot() map[string]interface{} {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	return map[string]interface{}{
		"authentication": map[string]int64{
			"total_attempts":    sm.TotalLoginAttempts,
			"failed_attempts":   sm.FailedLoginAttempts,
			"successful_logins": sm.SuccessfulLogins,
			"mfa_usage":         sm.MFAUsage,
		},
		"licenses": map[string]int64{
			"creations":            sm.LicenseCreations,
			"verifications":        sm.LicenseVerifications,
			"failed_verifications": sm.FailedVerifications,
			"tampering_detections": sm.TamperingDetections,
		},
		"security": map[string]int64{
			"unauthorized_access": sm.UnauthorizedAccess,
			"rate_limit_hits":     sm.RateLimitHits,
			"intrusion_attempts":  sm.IntrusionAttempts,
		},
		"system": map[string]int64{
			"key_rotations": sm.KeyRotations,
			"audit_events":  sm.AuditEvents,
		},
		"last_updated": sm.LastUpdated.Format(time.RFC3339),
	}
}

// Alert represents a security alert
type Alert struct {
	ID          string
	Type        AlertType
	Severity    AlertSeverity
	Title       string
	Description string
	Timestamp   time.Time
	Metadata    map[string]interface{}
}

// AlertType represents the type of alert
type AlertType string

const (
	AlertTypeAuthentication AlertType = "authentication"
	AlertTypeTampering      AlertType = "tampering"
	AlertTypeIntrusion      AlertType = "intrusion"
	AlertTypeRateLimit      AlertType = "rate_limit"
	AlertTypeSystemHealth   AlertType = "system_health"
)

// AlertSeverity represents alert severity
type AlertSeverity string

const (
	AlertSeverityInfo     AlertSeverity = "info"
	AlertSeverityWarning  AlertSeverity = "warning"
	AlertSeverityError    AlertSeverity = "error"
	AlertSeverityCritical AlertSeverity = "critical"
)

// AlertManager manages security alerts
type AlertManager struct {
	mu        sync.RWMutex
	alerts    []*Alert
	handlers  []AlertHandler
	maxAlerts int
}

// AlertHandler is a function that handles alerts
type AlertHandler func(*Alert)

// NewAlertManager creates a new alert manager
func NewAlertManager(maxAlerts int) *AlertManager {
	return &AlertManager{
		alerts:    make([]*Alert, 0),
		handlers:  make([]AlertHandler, 0),
		maxAlerts: maxAlerts,
	}
}

// RegisterHandler registers an alert handler
func (am *AlertManager) RegisterHandler(handler AlertHandler) {
	am.mu.Lock()
	defer am.mu.Unlock()
	am.handlers = append(am.handlers, handler)
}

// SendAlert sends a security alert
func (am *AlertManager) SendAlert(alert *Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()

	alert.Timestamp = time.Now()
	if alert.ID == "" {
		alert.ID = generateAlertID()
	}

	// Store alert
	am.alerts = append(am.alerts, alert)

	// Trim if exceeds max
	if len(am.alerts) > am.maxAlerts {
		am.alerts = am.alerts[len(am.alerts)-am.maxAlerts:]
	}

	// Notify handlers
	for _, handler := range am.handlers {
		go handler(alert)
	}
}

// GetRecentAlerts returns recent alerts
func (am *AlertManager) GetRecentAlerts(count int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if count > len(am.alerts) {
		count = len(am.alerts)
	}

	recent := make([]*Alert, count)
	copy(recent, am.alerts[len(am.alerts)-count:])
	return recent
}

// GetAlertsBySeverity returns alerts filtered by severity
func (am *AlertManager) GetAlertsBySeverity(severity AlertSeverity) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	filtered := make([]*Alert, 0)
	for _, alert := range am.alerts {
		if alert.Severity == severity {
			filtered = append(filtered, alert)
		}
	}
	return filtered
}

// generateAlertID generates a unique alert ID
func generateAlertID() string {
	return fmt.Sprintf("alert-%d", time.Now().UnixNano())
}

// HealthCheck represents a system health check
type HealthCheck struct {
	Name      string
	Status    HealthStatus
	Error     error
	LastCheck time.Time
}

// HealthStatus represents health status
type HealthStatus string

const (
	HealthStatusHealthy   HealthStatus = "healthy"
	HealthStatusDegraded  HealthStatus = "degraded"
	HealthStatusUnhealthy HealthStatus = "unhealthy"
)

// HealthMonitor monitors system health
type HealthMonitor struct {
	mu     sync.RWMutex
	checks map[string]*HealthCheck
}

// NewHealthMonitor creates a new health monitor
func NewHealthMonitor() *HealthMonitor {
	return &HealthMonitor{
		checks: make(map[string]*HealthCheck),
	}
}

// UpdateCheck updates a health check result
func (hm *HealthMonitor) UpdateCheck(name string, status HealthStatus, err error) {
	hm.mu.Lock()
	defer hm.mu.Unlock()

	hm.checks[name] = &HealthCheck{
		Name:      name,
		Status:    status,
		Error:     err,
		LastCheck: time.Now(),
	}
}

// GetOverallHealth returns overall system health
func (hm *HealthMonitor) GetOverallHealth() HealthStatus {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	if len(hm.checks) == 0 {
		return HealthStatusUnhealthy
	}

	hasUnhealthy := false
	hasDegraded := false

	for _, check := range hm.checks {
		switch check.Status {
		case HealthStatusUnhealthy:
			hasUnhealthy = true
		case HealthStatusDegraded:
			hasDegraded = true
		}
	}

	if hasUnhealthy {
		return HealthStatusUnhealthy
	}
	if hasDegraded {
		return HealthStatusDegraded
	}
	return HealthStatusHealthy
}

// GetChecks returns all health checks
func (hm *HealthMonitor) GetChecks() map[string]*HealthCheck {
	hm.mu.RLock()
	defer hm.mu.RUnlock()

	checks := make(map[string]*HealthCheck, len(hm.checks))
	for k, v := range hm.checks {
		checks[k] = v
	}
	return checks
}
