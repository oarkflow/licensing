package licensing

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/oarkflow/squealx"
)

func ensureOfflineValidationSchema(db *squealx.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS offline_validation_tokens (
			token TEXT PRIMARY KEY,
			license_key TEXT NOT NULL,
			client_id TEXT NOT NULL,
			device_fingerprint TEXT NOT NULL,
			valid_until TIMESTAMP NOT NULL,
			usage_count INTEGER NOT NULL DEFAULT 0,
			max_uses INTEGER NOT NULL,
			is_revoked INTEGER NOT NULL DEFAULT 0,
			created_at TIMESTAMP NOT NULL,
			revoked_at TIMESTAMP,
			revoked_by TEXT,
			revoked_reason TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_offline_tokens_license ON offline_validation_tokens(license_key);`,
		`CREATE INDEX IF NOT EXISTS idx_offline_tokens_client ON offline_validation_tokens(client_id);`,
		`CREATE INDEX IF NOT EXISTS idx_offline_tokens_device ON offline_validation_tokens(device_fingerprint);`,

		`CREATE TABLE IF NOT EXISTS offline_validation_logs (
			id TEXT PRIMARY KEY,
			token TEXT NOT NULL,
			license_key TEXT NOT NULL,
			client_id TEXT NOT NULL,
			device_fingerprint TEXT NOT NULL,
			validation_time TIMESTAMP NOT NULL,
			success INTEGER NOT NULL,
			error_message TEXT,
			ip_address TEXT,
			user_agent TEXT,
			app_version TEXT,
			metadata TEXT
		);`,
		`CREATE INDEX IF NOT EXISTS idx_offline_logs_token ON offline_validation_logs(token);`,
		`CREATE INDEX IF NOT EXISTS idx_offline_logs_license ON offline_validation_logs(license_key);`,
		`CREATE INDEX IF NOT EXISTS idx_offline_logs_client ON offline_validation_logs(client_id);`,
	}

	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("offline validation schema creation failed: %w", err)
		}
	}
	return nil
}

// OfflineValidationToken methods for SQLiteStorage

func (s *SQLiteStorage) SaveOfflineValidationToken(ctx context.Context, token *OfflineValidationToken) error {
	if token == nil {
		return fmt.Errorf("offline validation token is nil")
	}

	query := `INSERT INTO offline_validation_tokens (
		token, license_key, client_id, device_fingerprint, valid_until,
		usage_count, max_uses, is_revoked, created_at, revoked_at, revoked_by, revoked_reason
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		token.Token, token.LicenseKey, token.ClientID, token.DeviceFingerprint,
		token.ValidUntil, token.UsageCount, token.MaxUses, token.IsRevoked,
		token.CreatedAt, token.RevokedAt, token.RevokedBy, token.RevokedReason,
	)

	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errOfflineTokenExists
		}
		return fmt.Errorf("failed to save offline validation token: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) GetOfflineValidationToken(ctx context.Context, token string) (*OfflineValidationToken, error) {
	query := `SELECT
		token, license_key, client_id, device_fingerprint, valid_until,
		usage_count, max_uses, is_revoked, created_at, revoked_at, revoked_by, revoked_reason
	FROM offline_validation_tokens WHERE token = ?`

	var offlineToken OfflineValidationToken
	var revokedAt, revokedBy, revokedReason sql.NullString
	var createdAt, validUntil sqliteTimeValue

	row := s.db.QueryRowContext(ctx, query, token)
	err := row.Scan(
		&offlineToken.Token, &offlineToken.LicenseKey, &offlineToken.ClientID,
		&offlineToken.DeviceFingerprint, &validUntil, &offlineToken.UsageCount,
		&offlineToken.MaxUses, &offlineToken.IsRevoked, &createdAt,
		&revokedAt, &revokedBy, &revokedReason,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, errOfflineTokenMissing
		}
		return nil, fmt.Errorf("failed to get offline validation token: %w", err)
	}

	offlineToken.CreatedAt = createdAt.Time
	offlineToken.ValidUntil = validUntil.Time

	if revokedAt.Valid {
		offlineToken.RevokedAt, _ = time.Parse(time.RFC3339, revokedAt.String)
	}
	if revokedBy.Valid {
		offlineToken.RevokedBy = revokedBy.String
	}
	if revokedReason.Valid {
		offlineToken.RevokedReason = revokedReason.String
	}

	return &offlineToken, nil
}

func (s *SQLiteStorage) UpdateOfflineValidationToken(ctx context.Context, token *OfflineValidationToken) error {
	if token == nil {
		return fmt.Errorf("offline validation token is nil")
	}

	query := `UPDATE offline_validation_tokens SET
		license_key = ?, client_id = ?, device_fingerprint = ?, valid_until = ?,
		usage_count = ?, max_uses = ?, is_revoked = ?, revoked_at = ?,
		revoked_by = ?, revoked_reason = ?
	WHERE token = ?`

	_, err := s.db.ExecContext(ctx, query,
		token.LicenseKey, token.ClientID, token.DeviceFingerprint, token.ValidUntil,
		token.UsageCount, token.MaxUses, token.IsRevoked, token.RevokedAt,
		token.RevokedBy, token.RevokedReason, token.Token,
	)

	if err != nil {
		return fmt.Errorf("failed to update offline validation token: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) DeleteOfflineValidationToken(ctx context.Context, token string) error {
	query := `DELETE FROM offline_validation_tokens WHERE token = ?`
	result, err := s.db.ExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to delete offline validation token: %w", err)
	}

	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to check rows affected: %w", err)
	}
	if rowsAffected == 0 {
		return errOfflineTokenMissing
	}

	return nil
}

func (s *SQLiteStorage) ListOfflineValidationTokens(ctx context.Context) ([]*OfflineValidationToken, error) {
	query := `SELECT
		token, license_key, client_id, device_fingerprint, valid_until,
		usage_count, max_uses, is_revoked, created_at, revoked_at, revoked_by, revoked_reason
	FROM offline_validation_tokens ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("failed to list offline validation tokens: %w", err)
	}
	defer rows.Close()

	var tokens []*OfflineValidationToken
	for rows.Next() {
		var token OfflineValidationToken
		var revokedAt, revokedBy, revokedReason sql.NullString
		var createdAt, validUntil sqliteTimeValue

		err := rows.Scan(
			&token.Token, &token.LicenseKey, &token.ClientID,
			&token.DeviceFingerprint, &validUntil, &token.UsageCount,
			&token.MaxUses, &token.IsRevoked, &createdAt,
			&revokedAt, &revokedBy, &revokedReason,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan offline validation token: %w", err)
		}

		token.CreatedAt = createdAt.Time
		token.ValidUntil = validUntil.Time

		if revokedAt.Valid {
			token.RevokedAt, _ = time.Parse(time.RFC3339, revokedAt.String)
		}
		if revokedBy.Valid {
			token.RevokedBy = revokedBy.String
		}
		if revokedReason.Valid {
			token.RevokedReason = revokedReason.String
		}

		tokens = append(tokens, &token)
	}

	return tokens, nil
}

func (s *SQLiteStorage) FindOfflineValidationTokensByLicense(ctx context.Context, licenseKey string) ([]*OfflineValidationToken, error) {
	query := `SELECT
		token, license_key, client_id, device_fingerprint, valid_until,
		usage_count, max_uses, is_revoked, created_at, revoked_at, revoked_by, revoked_reason
	FROM offline_validation_tokens WHERE license_key = ? ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, licenseKey)
	if err != nil {
		return nil, fmt.Errorf("failed to find offline validation tokens by license: %w", err)
	}
	defer rows.Close()

	var tokens []*OfflineValidationToken
	for rows.Next() {
		var token OfflineValidationToken
		var revokedAt, revokedBy, revokedReason sql.NullString
		var createdAt, validUntil sqliteTimeValue

		err := rows.Scan(
			&token.Token, &token.LicenseKey, &token.ClientID,
			&token.DeviceFingerprint, &validUntil, &token.UsageCount,
			&token.MaxUses, &token.IsRevoked, &createdAt,
			&revokedAt, &revokedBy, &revokedReason,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan offline validation token: %w", err)
		}

		token.CreatedAt = createdAt.Time
		token.ValidUntil = validUntil.Time

		if revokedAt.Valid {
			token.RevokedAt, _ = time.Parse(time.RFC3339, revokedAt.String)
		}
		if revokedBy.Valid {
			token.RevokedBy = revokedBy.String
		}
		if revokedReason.Valid {
			token.RevokedReason = revokedReason.String
		}

		tokens = append(tokens, &token)
	}

	return tokens, nil
}

func (s *SQLiteStorage) FindOfflineValidationTokensByClient(ctx context.Context, clientID string) ([]*OfflineValidationToken, error) {
	query := `SELECT
		token, license_key, client_id, device_fingerprint, valid_until,
		usage_count, max_uses, is_revoked, created_at, revoked_at, revoked_by, revoked_reason
	FROM offline_validation_tokens WHERE client_id = ? ORDER BY created_at DESC`

	rows, err := s.db.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to find offline validation tokens by client: %w", err)
	}
	defer rows.Close()

	var tokens []*OfflineValidationToken
	for rows.Next() {
		var token OfflineValidationToken
		var revokedAt, revokedBy, revokedReason sql.NullString
		var createdAt, validUntil sqliteTimeValue

		err := rows.Scan(
			&token.Token, &token.LicenseKey, &token.ClientID,
			&token.DeviceFingerprint, &validUntil, &token.UsageCount,
			&token.MaxUses, &token.IsRevoked, &createdAt,
			&revokedAt, &revokedBy, &revokedReason,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan offline validation token: %w", err)
		}

		token.CreatedAt = createdAt.Time
		token.ValidUntil = validUntil.Time

		if revokedAt.Valid {
			token.RevokedAt, _ = time.Parse(time.RFC3339, revokedAt.String)
		}
		if revokedBy.Valid {
			token.RevokedBy = revokedBy.String
		}
		if revokedReason.Valid {
			token.RevokedReason = revokedReason.String
		}

		tokens = append(tokens, &token)
	}

	return tokens, nil
}

// OfflineValidationLog methods for SQLiteStorage

func (s *SQLiteStorage) SaveOfflineValidationLog(ctx context.Context, log *OfflineValidationLog) error {
	if log == nil {
		return fmt.Errorf("offline validation log is nil")
	}

	query := `INSERT INTO offline_validation_logs (
		id, token, license_key, client_id, device_fingerprint,
		validation_time, success, error_message, ip_address, user_agent,
		app_version, metadata
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

	_, err := s.db.ExecContext(ctx, query,
		log.ID, log.Token, log.LicenseKey, log.ClientID, log.DeviceFingerprint,
		log.ValidationTime, log.Success, log.ErrorMessage, log.IPAddress,
		log.UserAgent, log.AppVersion, log.Metadata,
	)

	if err != nil {
		return fmt.Errorf("failed to save offline validation log: %w", err)
	}
	return nil
}

func (s *SQLiteStorage) ListOfflineValidationLogs(ctx context.Context, token string) ([]*OfflineValidationLog, error) {
	query := `SELECT
		id, token, license_key, client_id, device_fingerprint,
		validation_time, success, error_message, ip_address, user_agent,
		app_version, metadata
	FROM offline_validation_logs WHERE token = ? ORDER BY validation_time DESC`

	rows, err := s.db.QueryContext(ctx, query, token)
	if err != nil {
		return nil, fmt.Errorf("failed to list offline validation logs: %w", err)
	}
	defer rows.Close()

	var logs []*OfflineValidationLog
	for rows.Next() {
		var log OfflineValidationLog
		var validationTime sqliteTimeValue

		err := rows.Scan(
			&log.ID, &log.Token, &log.LicenseKey, &log.ClientID,
			&log.DeviceFingerprint, &validationTime, &log.Success,
			&log.ErrorMessage, &log.IPAddress, &log.UserAgent,
			&log.AppVersion, &log.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan offline validation log: %w", err)
		}

		log.ValidationTime = validationTime.Time
		logs = append(logs, &log)
	}

	return logs, nil
}

func (s *SQLiteStorage) FindOfflineValidationLogsByLicense(ctx context.Context, licenseKey string) ([]*OfflineValidationLog, error) {
	query := `SELECT
		id, token, license_key, client_id, device_fingerprint,
		validation_time, success, error_message, ip_address, user_agent,
		app_version, metadata
	FROM offline_validation_logs WHERE license_key = ? ORDER BY validation_time DESC`

	rows, err := s.db.QueryContext(ctx, query, licenseKey)
	if err != nil {
		return nil, fmt.Errorf("failed to find offline validation logs by license: %w", err)
	}
	defer rows.Close()

	var logs []*OfflineValidationLog
	for rows.Next() {
		var log OfflineValidationLog
		var validationTime sqliteTimeValue

		err := rows.Scan(
			&log.ID, &log.Token, &log.LicenseKey, &log.ClientID,
			&log.DeviceFingerprint, &validationTime, &log.Success,
			&log.ErrorMessage, &log.IPAddress, &log.UserAgent,
			&log.AppVersion, &log.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan offline validation log: %w", err)
		}

		log.ValidationTime = validationTime.Time
		logs = append(logs, &log)
	}

	return logs, nil
}

func (s *SQLiteStorage) FindOfflineValidationLogsByClient(ctx context.Context, clientID string) ([]*OfflineValidationLog, error) {
	query := `SELECT
		id, token, license_key, client_id, device_fingerprint,
		validation_time, success, error_message, ip_address, user_agent,
		app_version, metadata
	FROM offline_validation_logs WHERE client_id = ? ORDER BY validation_time DESC`

	rows, err := s.db.QueryContext(ctx, query, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to find offline validation logs by client: %w", err)
	}
	defer rows.Close()

	var logs []*OfflineValidationLog
	for rows.Next() {
		var log OfflineValidationLog
		var validationTime sqliteTimeValue

		err := rows.Scan(
			&log.ID, &log.Token, &log.LicenseKey, &log.ClientID,
			&log.DeviceFingerprint, &validationTime, &log.Success,
			&log.ErrorMessage, &log.IPAddress, &log.UserAgent,
			&log.AppVersion, &log.Metadata,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan offline validation log: %w", err)
		}

		log.ValidationTime = validationTime.Time
		logs = append(logs, &log)
	}

	return logs, nil
}
