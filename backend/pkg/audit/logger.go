package audit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

// Logger is the audit logger interface
type Logger interface {
	Log(ctx context.Context, event *Event) error
	Query(ctx context.Context, filter *AuditFilter) ([]*Event, error)
	GetStatistics(ctx context.Context, filter *AuditFilter) (*EventStatistics, error)
	Close() error
}

// Storage is the interface for audit log storage backends
type Storage interface {
	Store(ctx context.Context, event *Event) error
	Retrieve(ctx context.Context, filter *AuditFilter) ([]*Event, error)
	Count(ctx context.Context, filter *AuditFilter) (int64, error)
	Close() error
}

// AuditLogger is the main audit logger implementation
type AuditLogger struct {
	storage        Storage
	signer         Signer // For signing events
	async          bool
	bufferSize     int
	eventChan      chan *Event
	wg             sync.WaitGroup
	ctx            context.Context
	cancel         context.CancelFunc
	lastEventHash  string
	hashMutex      sync.Mutex
	enableChaining bool // Link events in a chain for tamper detection
}

// Signer interface for signing audit events
type Signer interface {
	Sign(data []byte) (string, error)
	KeyID() string
}

// AuditLoggerConfig configures the audit logger
type AuditLoggerConfig struct {
	Storage        Storage
	Signer         Signer
	Async          bool
	BufferSize     int
	EnableChaining bool // Enable event chaining for tamper detection
}

// NewAuditLogger creates a new audit logger
func NewAuditLogger(config *AuditLoggerConfig) (*AuditLogger, error) {
	if config.Storage == nil {
		return nil, fmt.Errorf("storage backend is required")
	}

	if config.BufferSize == 0 {
		config.BufferSize = 1000
	}

	ctx, cancel := context.WithCancel(context.Background())

	logger := &AuditLogger{
		storage:        config.Storage,
		signer:         config.Signer,
		async:          config.Async,
		bufferSize:     config.BufferSize,
		eventChan:      make(chan *Event, config.BufferSize),
		ctx:            ctx,
		cancel:         cancel,
		enableChaining: config.EnableChaining,
	}

	if config.Async {
		logger.startWorker()
	}

	return logger, nil
}

// startWorker starts the async event processing worker
func (l *AuditLogger) startWorker() {
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		for {
			select {
			case event := <-l.eventChan:
				if err := l.processEvent(context.Background(), event); err != nil {
					// Log error but don't fail - audit logging should not block operations
					fmt.Printf("Failed to process audit event: %v\n", err)
				}
			case <-l.ctx.Done():
				// Drain remaining events
				for len(l.eventChan) > 0 {
					event := <-l.eventChan
					if err := l.processEvent(context.Background(), event); err != nil {
						fmt.Printf("Failed to process audit event during shutdown: %v\n", err)
					}
				}
				return
			}
		}
	}()
}

// Log logs an audit event
func (l *AuditLogger) Log(ctx context.Context, event *Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Set timestamp if not already set
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}

	if l.async {
		select {
		case l.eventChan <- event:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		default:
			// Buffer is full, process synchronously to not lose the event
			return l.processEvent(ctx, event)
		}
	}

	return l.processEvent(ctx, event)
}

// processEvent processes and stores an audit event
func (l *AuditLogger) processEvent(ctx context.Context, event *Event) error {
	// Add event chaining if enabled
	if l.enableChaining {
		l.hashMutex.Lock()
		event.PrevHash = l.lastEventHash
		l.hashMutex.Unlock()
	}

	// Calculate event hash
	eventHash, err := l.calculateEventHash(event)
	if err != nil {
		return fmt.Errorf("failed to calculate event hash: %w", err)
	}
	event.Hash = eventHash

	// Sign event if signer is available
	if l.signer != nil {
		signature, err := l.signer.Sign([]byte(eventHash))
		if err != nil {
			return fmt.Errorf("failed to sign event: %w", err)
		}
		event.Signature = signature
	}

	// Update last event hash for chaining
	if l.enableChaining {
		l.hashMutex.Lock()
		l.lastEventHash = eventHash
		l.hashMutex.Unlock()
	}

	// Store the event
	if err := l.storage.Store(ctx, event); err != nil {
		return fmt.Errorf("failed to store event: %w", err)
	}

	return nil
}

// calculateEventHash calculates a SHA-256 hash of the event for tamper detection
func (l *AuditLogger) calculateEventHash(event *Event) (string, error) {
	// Create a copy of the event without hash and signature
	eventCopy := *event
	eventCopy.Hash = ""
	eventCopy.Signature = ""

	// Serialize to JSON
	data, err := json.Marshal(eventCopy)
	if err != nil {
		return "", fmt.Errorf("failed to marshal event: %w", err)
	}

	// Calculate SHA-256 hash
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// Query retrieves audit events based on filter criteria
func (l *AuditLogger) Query(ctx context.Context, filter *AuditFilter) ([]*Event, error) {
	if filter == nil {
		filter = &AuditFilter{}
	}

	return l.storage.Retrieve(ctx, filter)
}

// GetStatistics retrieves aggregated statistics for audit events
func (l *AuditLogger) GetStatistics(ctx context.Context, filter *AuditFilter) (*EventStatistics, error) {
	events, err := l.Query(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}

	stats := &EventStatistics{
		TotalEvents:      int64(len(events)),
		EventsByType:     make(map[EventType]int64),
		EventsBySeverity: make(map[Severity]int64),
	}

	if len(events) > 0 {
		stats.TimeRange.Start = events[0].Timestamp
		stats.TimeRange.End = events[len(events)-1].Timestamp
	}

	for _, event := range events {
		stats.EventsByType[event.Type]++
		stats.EventsBySeverity[event.Severity]++

		if event.Result == "failure" {
			stats.FailedEvents++
		}

		// Count security events
		if event.Type == EventSecurityIntrusion ||
			event.Type == EventSecurityTampering ||
			event.Type == EventSecurityUnauthorized ||
			event.Type == EventSecurityBruteForce ||
			event.Type == EventSecurityAnomaly {
			stats.SecurityEvents++
		}
	}

	return stats, nil
}

// VerifyChain verifies the integrity of the event chain
func (l *AuditLogger) VerifyChain(ctx context.Context, events []*Event) (bool, []string) {
	if !l.enableChaining {
		return true, []string{"Event chaining not enabled"}
	}

	var errors []string
	var prevHash string

	for i, event := range events {
		// Verify hash
		calculatedHash, err := l.calculateEventHash(event)
		if err != nil {
			errors = append(errors, fmt.Sprintf("Event %d: failed to calculate hash: %v", i, err))
			continue
		}

		if calculatedHash != event.Hash {
			errors = append(errors, fmt.Sprintf("Event %d: hash mismatch (expected: %s, got: %s)",
				i, event.Hash, calculatedHash))
		}

		// Verify chain linkage
		if i > 0 && event.PrevHash != prevHash {
			errors = append(errors, fmt.Sprintf("Event %d: chain broken (expected prev_hash: %s, got: %s)",
				i, prevHash, event.PrevHash))
		}

		// Verify signature if present
		if event.Signature != "" && l.signer != nil {
			// Signature verification would go here
			// This would require a verifier interface
		}

		prevHash = event.Hash
	}

	return len(errors) == 0, errors
}

// GenerateComplianceReport generates a compliance-focused audit report
func (l *AuditLogger) GenerateComplianceReport(ctx context.Context, compliance string, startTime, endTime time.Time) (*ComplianceReport, error) {
	filter := &AuditFilter{
		StartTime: &startTime,
		EndTime:   &endTime,
	}

	events, err := l.Query(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to query events: %w", err)
	}

	stats, err := l.GetStatistics(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to get statistics: %w", err)
	}

	report := &ComplianceReport{
		ReportID:    fmt.Sprintf("compliance-%d", time.Now().Unix()),
		GeneratedAt: time.Now().UTC(),
		TimeRange: TimeRange{
			Start: startTime,
			End:   endTime,
		},
		TotalEvents: int64(len(events)),
		Compliance:  compliance,
		Events:      events,
		Statistics:  stats,
		Violations:  []ComplianceViolation{},
	}

	// Check for compliance violations
	report.Violations = l.checkComplianceViolations(events, compliance)

	// Generate recommendations
	report.Recommendations = l.generateRecommendations(events, stats, compliance)

	return report, nil
}

// checkComplianceViolations checks for compliance violations
func (l *AuditLogger) checkComplianceViolations(events []*Event, compliance string) []ComplianceViolation {
	var violations []ComplianceViolation

	switch compliance {
	case "SOC2":
		violations = append(violations, l.checkSOC2Violations(events)...)
	case "GDPR":
		violations = append(violations, l.checkGDPRViolations(events)...)
	case "HIPAA":
		violations = append(violations, l.checkHIPAAViolations(events)...)
	}

	return violations
}

// checkSOC2Violations checks for SOC2 compliance violations
func (l *AuditLogger) checkSOC2Violations(events []*Event) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for excessive failed authentication attempts
	failedAuthCount := 0
	for _, event := range events {
		if event.Type == EventAdminLogin && event.Result == "failure" {
			failedAuthCount++
		}
	}

	if failedAuthCount > 10 {
		violations = append(violations, ComplianceViolation{
			ID:          fmt.Sprintf("soc2-%d", time.Now().Unix()),
			Type:        "excessive_failed_auth",
			Severity:    SeverityWarning,
			Description: fmt.Sprintf("Excessive failed authentication attempts detected: %d", failedAuthCount),
			Timestamp:   time.Now().UTC(),
			Remediation: "Review authentication mechanisms and implement account lockout policies",
		})
	}

	return violations
}

// checkGDPRViolations checks for GDPR compliance violations
func (l *AuditLogger) checkGDPRViolations(events []*Event) []ComplianceViolation {
	var violations []ComplianceViolation

	// Check for data access without proper authorization
	for _, event := range events {
		if event.Type == EventSecurityUnauthorized && event.ResourceType == "license" {
			violations = append(violations, ComplianceViolation{
				ID:          fmt.Sprintf("gdpr-%s", event.ID),
				Type:        "unauthorized_data_access",
				Severity:    SeverityCritical,
				Description: "Unauthorized access to personal data detected",
				EventID:     event.ID,
				Timestamp:   event.Timestamp,
				Remediation: "Review access controls and implement stricter authorization policies",
			})
		}
	}

	return violations
}

// checkHIPAAViolations checks for HIPAA compliance violations
func (l *AuditLogger) checkHIPAAViolations(events []*Event) []ComplianceViolation {
	var violations []ComplianceViolation

	// HIPAA-specific checks would go here
	// This is a placeholder for healthcare-specific compliance

	return violations
}

// generateRecommendations generates security and compliance recommendations
func (l *AuditLogger) generateRecommendations(events []*Event, stats *EventStatistics, compliance string) []string {
	var recommendations []string

	// Check for high rate of failed verifications
	if stats.FailedEvents > stats.TotalEvents/10 {
		recommendations = append(recommendations,
			"High failure rate detected. Consider reviewing license verification logic and client implementations.")
	}

	// Check for security events
	if stats.SecurityEvents > 0 {
		recommendations = append(recommendations,
			"Security events detected. Review and investigate all security incidents immediately.")
	}

	// Compliance-specific recommendations
	switch compliance {
	case "SOC2":
		if stats.EventsByType[EventAdminAction] > 100 {
			recommendations = append(recommendations,
				"High volume of administrative actions. Consider implementing change approval workflows.")
		}
	case "GDPR":
		recommendations = append(recommendations,
			"Ensure all personal data access is logged and users can request data deletion.")
	}

	return recommendations
}

// Close closes the audit logger and flushes any pending events
func (l *AuditLogger) Close() error {
	if l.async {
		l.cancel()
		l.wg.Wait()
	}

	return l.storage.Close()
}

// Flush forces processing of all pending events (useful for async mode)
func (l *AuditLogger) Flush(ctx context.Context) error {
	if !l.async {
		return nil
	}

	// Wait for all events to be processed
	timeout := time.After(30 * time.Second)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-timeout:
			return fmt.Errorf("timeout waiting for events to flush")
		case <-ticker.C:
			if len(l.eventChan) == 0 {
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
