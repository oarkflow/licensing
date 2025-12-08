package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// SQLiteStorage implements audit log storage in SQLite
type SQLiteStorage struct {
	db *sql.DB
}

// NewSQLiteStorage creates a new SQLite audit storage
func NewSQLiteStorage(db *sql.DB) (*SQLiteStorage, error) {
	storage := &SQLiteStorage{db: db}
	if err := storage.initialize(); err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	return storage, nil
}

// initialize creates the audit log tables
func (s *SQLiteStorage) initialize() error {
	schema := `
	CREATE TABLE IF NOT EXISTS audit_logs (
		id TEXT PRIMARY KEY,
		type TEXT NOT NULL,
		severity TEXT NOT NULL,
		timestamp DATETIME NOT NULL,
		actor_id TEXT,
		actor_type TEXT,
		actor_ip TEXT,
		resource_id TEXT,
		resource_type TEXT,
		action TEXT NOT NULL,
		result TEXT NOT NULL,
		message TEXT NOT NULL,
		metadata TEXT, -- JSON
		error_code TEXT,
		error_message TEXT,
		session_id TEXT,
		request_id TEXT,
		user_agent TEXT,
		location TEXT, -- JSON
		hash TEXT,
		signature TEXT,
		prev_hash TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_audit_logs_type ON audit_logs(type);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_severity ON audit_logs(severity);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_actor_id ON audit_logs(actor_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_id ON audit_logs(resource_id);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_result ON audit_logs(result);
	CREATE INDEX IF NOT EXISTS idx_audit_logs_hash ON audit_logs(hash);

	-- Tamper detection trigger
	CREATE TRIGGER IF NOT EXISTS prevent_audit_update
	BEFORE UPDATE ON audit_logs
	BEGIN
		SELECT RAISE(FAIL, 'Audit logs are immutable and cannot be updated');
	END;

	CREATE TRIGGER IF NOT EXISTS prevent_audit_delete
	BEFORE DELETE ON audit_logs
	BEGIN
		SELECT RAISE(FAIL, 'Audit logs are immutable and cannot be deleted');
	END;
	`

	_, err := s.db.Exec(schema)
	return err
}

// Store stores an audit event
func (s *SQLiteStorage) Store(ctx context.Context, event *Event) error {
	metadataJSON, err := json.Marshal(event.Metadata)
	if err != nil {
		return fmt.Errorf("failed to marshal metadata: %w", err)
	}

	var locationJSON []byte
	if event.Location != nil {
		locationJSON, err = json.Marshal(event.Location)
		if err != nil {
			return fmt.Errorf("failed to marshal location: %w", err)
		}
	}

	query := `
		INSERT INTO audit_logs (
			id, type, severity, timestamp, actor_id, actor_type, actor_ip,
			resource_id, resource_type, action, result, message, metadata,
			error_code, error_message, session_id, request_id, user_agent,
			location, hash, signature, prev_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err = s.db.ExecContext(ctx, query,
		event.ID, event.Type, event.Severity, event.Timestamp,
		event.ActorID, event.ActorType, event.ActorIP,
		event.ResourceID, event.ResourceType, event.Action, event.Result, event.Message,
		string(metadataJSON), event.ErrorCode, event.ErrorMessage,
		event.SessionID, event.RequestID, event.UserAgent,
		string(locationJSON), event.Hash, event.Signature, event.PrevHash,
	)

	if err != nil {
		return fmt.Errorf("failed to insert audit event: %w", err)
	}

	return nil
}

// Retrieve retrieves audit events based on filter
func (s *SQLiteStorage) Retrieve(ctx context.Context, filter *AuditFilter) ([]*Event, error) {
	query := "SELECT * FROM audit_logs WHERE 1=1"
	args := []interface{}{}

	if filter.StartTime != nil {
		query += " AND timestamp >= ?"
		args = append(args, *filter.StartTime)
	}

	if filter.EndTime != nil {
		query += " AND timestamp <= ?"
		args = append(args, *filter.EndTime)
	}

	if len(filter.EventTypes) > 0 {
		placeholders := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			placeholders[i] = "?"
			args = append(args, string(et))
		}
		query += fmt.Sprintf(" AND type IN (%s)", strings.Join(placeholders, ","))
	}

	if len(filter.Severities) > 0 {
		placeholders := make([]string, len(filter.Severities))
		for i, s := range filter.Severities {
			placeholders[i] = "?"
			args = append(args, string(s))
		}
		query += fmt.Sprintf(" AND severity IN (%s)", strings.Join(placeholders, ","))
	}

	if filter.ActorID != "" {
		query += " AND actor_id = ?"
		args = append(args, filter.ActorID)
	}

	if filter.ResourceID != "" {
		query += " AND resource_id = ?"
		args = append(args, filter.ResourceID)
	}

	if filter.ResourceType != "" {
		query += " AND resource_type = ?"
		args = append(args, filter.ResourceType)
	}

	if filter.Result != "" {
		query += " AND result = ?"
		args = append(args, filter.Result)
	}

	query += " ORDER BY timestamp DESC"

	if filter.Limit > 0 {
		query += " LIMIT ?"
		args = append(args, filter.Limit)
	}

	if filter.Offset > 0 {
		query += " OFFSET ?"
		args = append(args, filter.Offset)
	}

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query audit events: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		event, err := s.scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, event)
	}

	return events, nil
}

// Count counts audit events based on filter
func (s *SQLiteStorage) Count(ctx context.Context, filter *AuditFilter) (int64, error) {
	query := "SELECT COUNT(*) FROM audit_logs WHERE 1=1"
	args := []interface{}{}

	if filter.StartTime != nil {
		query += " AND timestamp >= ?"
		args = append(args, *filter.StartTime)
	}

	if filter.EndTime != nil {
		query += " AND timestamp <= ?"
		args = append(args, *filter.EndTime)
	}

	if len(filter.EventTypes) > 0 {
		placeholders := make([]string, len(filter.EventTypes))
		for i, et := range filter.EventTypes {
			placeholders[i] = "?"
			args = append(args, string(et))
		}
		query += fmt.Sprintf(" AND type IN (%s)", strings.Join(placeholders, ","))
	}

	var count int64
	err := s.db.QueryRowContext(ctx, query, args...).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count audit events: %w", err)
	}

	return count, nil
}

// scanEvent scans a row into an Event
func (s *SQLiteStorage) scanEvent(row interface{ Scan(...interface{}) error }) (*Event, error) {
	var event Event
	var metadataJSON, locationJSON sql.NullString
	var createdAt time.Time

	err := row.Scan(
		&event.ID, &event.Type, &event.Severity, &event.Timestamp,
		&event.ActorID, &event.ActorType, &event.ActorIP,
		&event.ResourceID, &event.ResourceType, &event.Action, &event.Result, &event.Message,
		&metadataJSON, &event.ErrorCode, &event.ErrorMessage,
		&event.SessionID, &event.RequestID, &event.UserAgent,
		&locationJSON, &event.Hash, &event.Signature, &event.PrevHash,
		&createdAt,
	)

	if err != nil {
		return nil, err
	}

	if metadataJSON.Valid && metadataJSON.String != "" {
		if err := json.Unmarshal([]byte(metadataJSON.String), &event.Metadata); err != nil {
			return nil, fmt.Errorf("failed to unmarshal metadata: %w", err)
		}
	}

	if locationJSON.Valid && locationJSON.String != "" {
		event.Location = &Location{}
		if err := json.Unmarshal([]byte(locationJSON.String), event.Location); err != nil {
			return nil, fmt.Errorf("failed to unmarshal location: %w", err)
		}
	}

	return &event, nil
}

// Close closes the storage
func (s *SQLiteStorage) Close() error {
	// Don't close the database connection as it's managed externally
	return nil
}

// ExportToJSON exports audit logs to JSON format
func (s *SQLiteStorage) ExportToJSON(ctx context.Context, filter *AuditFilter) ([]byte, error) {
	events, err := s.Retrieve(ctx, filter)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve events: %w", err)
	}

	data, err := json.MarshalIndent(events, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal events: %w", err)
	}

	return data, nil
}

// GetEventChain retrieves a chain of events starting from a specific event
func (s *SQLiteStorage) GetEventChain(ctx context.Context, startEventID string, limit int) ([]*Event, error) {
	query := `
		WITH RECURSIVE event_chain AS (
			SELECT * FROM audit_logs WHERE id = ?
			UNION ALL
			SELECT a.* FROM audit_logs a
			INNER JOIN event_chain ec ON a.prev_hash = ec.hash
		)
		SELECT * FROM event_chain LIMIT ?
	`

	rows, err := s.db.QueryContext(ctx, query, startEventID, limit)
	if err != nil {
		return nil, fmt.Errorf("failed to query event chain: %w", err)
	}
	defer rows.Close()

	var events []*Event
	for rows.Next() {
		event, err := s.scanEvent(rows)
		if err != nil {
			return nil, fmt.Errorf("failed to scan event: %w", err)
		}
		events = append(events, event)
	}

	return events, nil
}
