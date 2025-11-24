package licensing

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type SQLiteStorage struct {
	db *sql.DB
}

func NewSQLiteStorage(path string) (*SQLiteStorage, error) {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "" || cleaned == "." {
		return nil, fmt.Errorf("sqlite storage path is required")
	}
	if err := os.MkdirAll(filepath.Dir(cleaned), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create sqlite directory: %w", err)
	}
	db, err := sql.Open("sqlite", cleaned)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}
	db.SetMaxOpenConns(1)
	db.SetConnMaxLifetime(0)
	if err := configureSQLite(db); err != nil {
		return nil, err
	}
	if err := ensureSQLiteSchema(db); err != nil {
		return nil, err
	}
	return &SQLiteStorage{db: db}, nil
}

func configureSQLite(db *sql.DB) error {
	pragmas := []string{
		"PRAGMA foreign_keys = ON;",
		"PRAGMA journal_mode = WAL;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA busy_timeout = 5000;",
	}
	for _, stmt := range pragmas {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite pragma failed: %w", err)
		}
	}
	return db.Ping()
}

func ensureSQLiteSchema(db *sql.DB) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS clients (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			email_lower TEXT NOT NULL UNIQUE,
			status TEXT NOT NULL,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			banned_at TIMESTAMP,
			ban_reason TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS licenses (
			id TEXT PRIMARY KEY,
			client_id TEXT NOT NULL,
			email TEXT NOT NULL,
			license_key TEXT NOT NULL,
			license_key_norm TEXT NOT NULL UNIQUE,
			is_revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at TIMESTAMP,
			revoke_reason TEXT,
			is_activated INTEGER NOT NULL DEFAULT 0,
			issued_at TIMESTAMP NOT NULL,
			last_activated_at TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			max_activations INTEGER NOT NULL,
			current_activations INTEGER NOT NULL,
			FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS license_devices (
            license_id TEXT NOT NULL,
            fingerprint TEXT NOT NULL,
            activated_at TIMESTAMP NOT NULL,
            last_seen_at TIMESTAMP NOT NULL,
            transport_key BLOB NOT NULL,
            PRIMARY KEY(license_id, fingerprint),
            FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
        );`,
		`CREATE TABLE IF NOT EXISTS license_authorized_users (
			license_id TEXT NOT NULL,
			email TEXT NOT NULL,
			email_lower TEXT NOT NULL,
			subject_client_id TEXT NOT NULL,
			provider_client_id TEXT NOT NULL,
			granted_at TIMESTAMP NOT NULL,
			PRIMARY KEY(license_id, email_lower),
			FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS activation_records (
            id TEXT PRIMARY KEY,
            license_id TEXT NOT NULL,
            client_id TEXT NOT NULL,
            device_fingerprint TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            success INTEGER NOT NULL,
            message TEXT,
            timestamp TIMESTAMP NOT NULL,
            FOREIGN KEY(license_id) REFERENCES licenses(id) ON DELETE CASCADE,
            FOREIGN KEY(client_id) REFERENCES clients(id) ON DELETE CASCADE
        );`,
		`CREATE TABLE IF NOT EXISTS admin_users (
            id TEXT PRIMARY KEY,
            username TEXT NOT NULL,
            username_lower TEXT NOT NULL UNIQUE,
            password_hash BLOB NOT NULL,
            created_at TIMESTAMP NOT NULL,
            updated_at TIMESTAMP NOT NULL
        );`,
		`CREATE TABLE IF NOT EXISTS api_keys (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            hash TEXT NOT NULL UNIQUE,
            prefix TEXT NOT NULL,
            created_at TIMESTAMP NOT NULL,
            last_used_at TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES admin_users(id) ON DELETE CASCADE
        );`,
		`CREATE INDEX IF NOT EXISTS idx_licenses_client_id ON licenses(client_id);`,
		`CREATE INDEX IF NOT EXISTS idx_activation_records_license_id ON activation_records(license_id);`,
		`CREATE INDEX IF NOT EXISTS idx_activation_records_client_id ON activation_records(client_id);`,
		`CREATE INDEX IF NOT EXISTS idx_license_authorized_users_license_id ON license_authorized_users(license_id);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite schema migration failed: %w", err)
		}
	}
	return nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func scanClientRow(scanner rowScanner) (*Client, error) {
	var c Client
	var banned sql.NullTime
	var banReason sql.NullString
	if err := scanner.Scan(
		&c.ID,
		&c.Email,
		&c.Status,
		&c.CreatedAt,
		&c.UpdatedAt,
		&banned,
		&banReason,
	); err != nil {
		return nil, err
	}
	if banned.Valid {
		c.BannedAt = banned.Time
	}
	if banReason.Valid {
		c.BanReason = banReason.String
	}
	return &c, nil
}

func scanLicenseRow(scanner rowScanner) (*License, error) {
	var lic License
	var revokedAt, lastActivated sql.NullTime
	var revokeReason sql.NullString
	var issuedAt, expiresAt time.Time
	var isRevoked, isActivated int
	if err := scanner.Scan(
		&lic.ID,
		&lic.ClientID,
		&lic.Email,
		&lic.LicenseKey,
		&isRevoked,
		&revokedAt,
		&revokeReason,
		&isActivated,
		&issuedAt,
		&lastActivated,
		&expiresAt,
		&lic.MaxActivations,
		&lic.CurrentActivations,
	); err != nil {
		return nil, err
	}
	lic.IsRevoked = isRevoked == 1
	lic.IsActivated = isActivated == 1
	lic.IssuedAt = issuedAt
	lic.ExpiresAt = expiresAt
	if revokedAt.Valid {
		lic.RevokedAt = revokedAt.Time
	}
	if revokeReason.Valid {
		lic.RevokeReason = revokeReason.String
	}
	if lastActivated.Valid {
		lic.LastActivatedAt = lastActivated.Time
	}
	lic.Devices = make(map[string]*LicenseDevice)
	return &lic, nil
}

func (s *SQLiteStorage) SaveClient(ctx context.Context, client *Client) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}
	query := `INSERT INTO clients (id, email, email_lower, status, created_at, updated_at, banned_at, ban_reason)
	          VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		client.ID,
		client.Email,
		normalizeEmail(client.Email),
		client.Status,
		client.CreatedAt,
		client.UpdatedAt,
		nullTime(client.BannedAt),
		client.BanReason,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errClientExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateClient(ctx context.Context, client *Client) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}
	query := `UPDATE clients
	          SET email = ?, email_lower = ?, status = ?, created_at = ?, updated_at = ?, banned_at = ?, ban_reason = ?
	          WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query,
		client.Email,
		normalizeEmail(client.Email),
		client.Status,
		client.CreatedAt,
		client.UpdatedAt,
		nullTime(client.BannedAt),
		client.BanReason,
		client.ID,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errClientExists
		}
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errClientMissing
	}
	return nil
}

func (s *SQLiteStorage) GetClient(ctx context.Context, clientID string) (*Client, error) {
	query := `SELECT id, email, status, created_at, updated_at, banned_at, ban_reason
	          FROM clients WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, clientID)
	client, err := scanClientRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errClientMissing
	}
	if err != nil {
		return nil, err
	}
	return cloneClient(client), nil
}

func (s *SQLiteStorage) GetClientByEmail(ctx context.Context, email string) (*Client, error) {
	query := `SELECT id, email, status, created_at, updated_at, banned_at, ban_reason
	          FROM clients WHERE email_lower = ?`
	row := s.db.QueryRowContext(ctx, query, normalizeEmail(email))
	client, err := scanClientRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errClientMissing
	}
	if err != nil {
		return nil, err
	}
	return cloneClient(client), nil
}

func (s *SQLiteStorage) ListClients(ctx context.Context) ([]*Client, error) {
	query := `SELECT id, email, status, created_at, updated_at, banned_at, ban_reason
	          FROM clients ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var clients []*Client
	for rows.Next() {
		client, err := scanClientRow(rows)
		if err != nil {
			return nil, err
		}
		clients = append(clients, cloneClient(client))
	}
	return clients, rows.Err()
}

func (s *SQLiteStorage) SaveLicense(ctx context.Context, license *License) error {
	if license == nil {
		return fmt.Errorf("license is nil")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		query := `INSERT INTO licenses (
			id, client_id, email, license_key, license_key_norm, is_revoked, revoked_at,
			revoke_reason, is_activated, issued_at, last_activated_at, expires_at, max_activations, current_activations)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := tx.ExecContext(ctx, query,
			license.ID,
			license.ClientID,
			license.Email,
			license.LicenseKey,
			normalizeLicenseKey(license.LicenseKey),
			boolToInt(license.IsRevoked),
			nullTime(license.RevokedAt),
			license.RevokeReason,
			boolToInt(license.IsActivated),
			license.IssuedAt,
			nullTime(license.LastActivatedAt),
			license.ExpiresAt,
			license.MaxActivations,
			license.CurrentActivations,
		)
		if err != nil {
			if isSQLiteUniqueErr(err) {
				return errLicenseExists
			}
			return err
		}
		if err := s.replaceDevices(ctx, tx, license.ID, license.Devices); err != nil {
			return err
		}
		return s.replaceAuthorizedUsers(ctx, tx, license.ID, license.AuthorizedUsers)
	})
}

func (s *SQLiteStorage) UpdateLicense(ctx context.Context, license *License) error {
	if license == nil {
		return fmt.Errorf("license is nil")
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		query := `UPDATE licenses SET
			client_id = ?, email = ?, license_key = ?, license_key_norm = ?,
            is_revoked = ?, revoked_at = ?, revoke_reason = ?, is_activated = ?, issued_at = ?,
            last_activated_at = ?, expires_at = ?, max_activations = ?, current_activations = ?
            WHERE id = ?`
		res, err := tx.ExecContext(ctx, query,
			license.ClientID,
			license.Email,
			license.LicenseKey,
			normalizeLicenseKey(license.LicenseKey),
			boolToInt(license.IsRevoked),
			nullTime(license.RevokedAt),
			license.RevokeReason,
			boolToInt(license.IsActivated),
			license.IssuedAt,
			nullTime(license.LastActivatedAt),
			license.ExpiresAt,
			license.MaxActivations,
			license.CurrentActivations,
			license.ID,
		)
		if err != nil {
			if isSQLiteUniqueErr(err) {
				return errLicenseExists
			}
			return err
		}
		rows, _ := res.RowsAffected()
		if rows == 0 {
			return errLicenseMissing
		}
		if err := s.replaceDevices(ctx, tx, license.ID, license.Devices); err != nil {
			return err
		}
		return s.replaceAuthorizedUsers(ctx, tx, license.ID, license.AuthorizedUsers)
	})
}

func (s *SQLiteStorage) GetLicense(ctx context.Context, licenseID string) (*License, error) {
	query := `SELECT id, client_id, email, license_key, is_revoked, revoked_at,
                     revoke_reason, is_activated, issued_at, last_activated_at, expires_at,
                     max_activations, current_activations
              FROM licenses WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, licenseID)
	license, err := scanLicenseRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errLicenseMissing
	}
	if err != nil {
		return nil, err
	}
	if err := s.loadDevices(ctx, license); err != nil {
		return nil, err
	}
	if err := s.loadAuthorizedUsers(ctx, license); err != nil {
		return nil, err
	}
	return cloneLicense(license), nil
}

func (s *SQLiteStorage) GetLicenseByKey(ctx context.Context, licenseKey string) (*License, error) {
	query := `SELECT id, client_id, email, license_key, is_revoked, revoked_at,
                     revoke_reason, is_activated, issued_at, last_activated_at, expires_at,
                     max_activations, current_activations
              FROM licenses WHERE license_key_norm = ?`
	row := s.db.QueryRowContext(ctx, query, normalizeLicenseKey(licenseKey))
	license, err := scanLicenseRow(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errLicenseMissing
	}
	if err != nil {
		return nil, err
	}
	if err := s.loadDevices(ctx, license); err != nil {
		return nil, err
	}
	if err := s.loadAuthorizedUsers(ctx, license); err != nil {
		return nil, err
	}
	return cloneLicense(license), nil
}

func (s *SQLiteStorage) ListLicenses(ctx context.Context) ([]*License, error) {
	query := `SELECT id, client_id, email, license_key, is_revoked, revoked_at,
                     revoke_reason, is_activated, issued_at, last_activated_at, expires_at,
                     max_activations, current_activations
              FROM licenses ORDER BY issued_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var licenses []*License
	for rows.Next() {
		license, err := scanLicenseRow(rows)
		if err != nil {
			return nil, err
		}
		if err := s.loadDevices(ctx, license); err != nil {
			return nil, err
		}
		if err := s.loadAuthorizedUsers(ctx, license); err != nil {
			return nil, err
		}
		licenses = append(licenses, cloneLicense(license))
	}
	return licenses, rows.Err()
}

func (s *SQLiteStorage) replaceDevices(ctx context.Context, tx *sql.Tx, licenseID string, devices map[string]*LicenseDevice) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM license_devices WHERE license_id = ?`, licenseID); err != nil {
		return err
	}
	if len(devices) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO license_devices (license_id, fingerprint, activated_at, last_seen_at, transport_key)
        VALUES (?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for fingerprint, device := range devices {
		if device == nil {
			continue
		}
		transport := append([]byte(nil), device.TransportKey...)
		if _, err := stmt.ExecContext(ctx, licenseID, fingerprint, device.ActivatedAt, device.LastSeenAt, transport); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStorage) loadDevices(ctx context.Context, license *License) error {
	rows, err := s.db.QueryContext(ctx, `SELECT fingerprint, activated_at, last_seen_at, transport_key
        FROM license_devices WHERE license_id = ?`, license.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	license.Devices = make(map[string]*LicenseDevice)
	for rows.Next() {
		var device LicenseDevice
		var transport []byte
		if err := rows.Scan(&device.Fingerprint, &device.ActivatedAt, &device.LastSeenAt, &transport); err != nil {
			return err
		}
		device.TransportKey = append([]byte(nil), transport...)
		license.Devices[device.Fingerprint] = &device
	}
	if err := rows.Err(); err != nil {
		return err
	}
	refreshLicenseDeviceStats(license)
	return nil
}

func (s *SQLiteStorage) replaceAuthorizedUsers(ctx context.Context, tx *sql.Tx, licenseID string, users map[string]*LicenseIdentity) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM license_authorized_users WHERE license_id = ?`, licenseID); err != nil {
		return err
	}
	if len(users) == 0 {
		return nil
	}
	stmt, err := tx.PrepareContext(ctx, `INSERT INTO license_authorized_users (license_id, email, email_lower, subject_client_id, provider_client_id, granted_at)
	        VALUES (?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, user := range users {
		if user == nil {
			continue
		}
		subjectID := strings.TrimSpace(user.ClientID)
		if subjectID == "" {
			return fmt.Errorf("authorized user missing client_id")
		}
		providerID := strings.TrimSpace(user.ProviderClientID)
		if providerID == "" {
			return fmt.Errorf("authorized user missing provider_client_id")
		}
		if _, err := stmt.ExecContext(ctx,
			licenseID,
			user.Email,
			normalizeEmail(user.Email),
			subjectID,
			providerID,
			user.GrantedAt,
		); err != nil {
			return err
		}
	}
	return nil
}

func (s *SQLiteStorage) loadAuthorizedUsers(ctx context.Context, license *License) error {
	rows, err := s.db.QueryContext(ctx, `SELECT email, subject_client_id, provider_client_id, granted_at
        FROM license_authorized_users WHERE license_id = ?`, license.ID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var users map[string]*LicenseIdentity
	for rows.Next() {
		var ident LicenseIdentity
		if err := rows.Scan(&ident.Email, &ident.ClientID, &ident.ProviderClientID, &ident.GrantedAt); err != nil {
			return err
		}
		if users == nil {
			users = make(map[string]*LicenseIdentity)
		}
		copyIdent := ident
		users[licenseIdentityKey(ident.Email)] = &copyIdent
	}
	if err := rows.Err(); err != nil {
		return err
	}
	license.AuthorizedUsers = users
	return nil
}

func (s *SQLiteStorage) RecordActivation(ctx context.Context, record *ActivationRecord) error {
	if record == nil {
		return fmt.Errorf("record is nil")
	}
	query := `INSERT INTO activation_records (id, license_id, client_id, device_fingerprint, ip_address, user_agent, success, message, timestamp)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		record.ID,
		record.LicenseID,
		record.ClientID,
		record.DeviceFingerprint,
		record.IPAddress,
		record.UserAgent,
		boolToInt(record.Success),
		record.Message,
		record.Timestamp,
	)
	return err
}

func (s *SQLiteStorage) ListActivations(ctx context.Context, licenseID string) ([]*ActivationRecord, error) {
	query := `SELECT id, license_id, client_id, device_fingerprint, ip_address, user_agent, success, message, timestamp
              FROM activation_records WHERE license_id = ? ORDER BY timestamp DESC`
	rows, err := s.db.QueryContext(ctx, query, licenseID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var records []*ActivationRecord
	for rows.Next() {
		var rec ActivationRecord
		var success int
		if err := rows.Scan(
			&rec.ID,
			&rec.LicenseID,
			&rec.ClientID,
			&rec.DeviceFingerprint,
			&rec.IPAddress,
			&rec.UserAgent,
			&success,
			&rec.Message,
			&rec.Timestamp,
		); err != nil {
			return nil, err
		}
		rec.Success = success == 1
		records = append(records, cloneActivationRecord(&rec))
	}
	return records, rows.Err()
}

func (s *SQLiteStorage) CreateAdminUser(ctx context.Context, user *AdminUser) error {
	if user == nil {
		return fmt.Errorf("admin user is nil")
	}
	query := `INSERT INTO admin_users (id, username, username_lower, password_hash, created_at, updated_at)
              VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		user.ID,
		user.Username,
		strings.ToLower(strings.TrimSpace(user.Username)),
		user.PasswordHash,
		user.CreatedAt,
		user.UpdatedAt,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errUserExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) GetAdminUser(ctx context.Context, userID string) (*AdminUser, error) {
	query := `SELECT id, username, password_hash, created_at, updated_at FROM admin_users WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, userID)
	var user AdminUser
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errUserMissing
		}
		return nil, err
	}
	return cloneAdminUser(&user), nil
}

func (s *SQLiteStorage) GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error) {
	query := `SELECT id, username, password_hash, created_at, updated_at FROM admin_users WHERE username_lower = ?`
	row := s.db.QueryRowContext(ctx, query, strings.ToLower(strings.TrimSpace(username)))
	var user AdminUser
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errUserMissing
		}
		return nil, err
	}
	return cloneAdminUser(&user), nil
}

func (s *SQLiteStorage) ListAdminUsers(ctx context.Context) ([]*AdminUser, error) {
	query := `SELECT id, username, password_hash, created_at, updated_at FROM admin_users ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*AdminUser
	for rows.Next() {
		var user AdminUser
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &user.CreatedAt, &user.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, cloneAdminUser(&user))
	}
	return users, rows.Err()
}

func (s *SQLiteStorage) SaveAPIKey(ctx context.Context, key *APIKeyRecord) error {
	if key == nil {
		return fmt.Errorf("api key is nil")
	}
	query := `INSERT INTO api_keys (id, user_id, hash, prefix, created_at, last_used_at)
              VALUES (?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		key.ID,
		key.UserID,
		key.Hash,
		key.Prefix,
		key.CreatedAt,
		nullTime(key.LastUsed),
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errAPIKeyExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateAPIKey(ctx context.Context, key *APIKeyRecord) error {
	if key == nil {
		return fmt.Errorf("api key is nil")
	}
	query := `UPDATE api_keys SET user_id = ?, hash = ?, prefix = ?, created_at = ?, last_used_at = ? WHERE id = ?`
	res, err := s.db.ExecContext(ctx, query,
		key.UserID,
		key.Hash,
		key.Prefix,
		key.CreatedAt,
		nullTime(key.LastUsed),
		key.ID,
	)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		return errAPIKeyMissing
	}
	return nil
}

func (s *SQLiteStorage) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error) {
	query := `SELECT id, user_id, hash, prefix, created_at, last_used_at FROM api_keys WHERE hash = ?`
	row := s.db.QueryRowContext(ctx, query, hash)
	var key APIKeyRecord
	var lastUsed sql.NullTime
	if err := row.Scan(&key.ID, &key.UserID, &key.Hash, &key.Prefix, &key.CreatedAt, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errAPIKeyMissing
		}
		return nil, err
	}
	if lastUsed.Valid {
		key.LastUsed = lastUsed.Time
	}
	return cloneAPIKeyRecord(&key), nil
}

func (s *SQLiteStorage) ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKeyRecord, error) {
	query := `SELECT id, user_id, hash, prefix, created_at, last_used_at FROM api_keys WHERE user_id = ? ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var keys []*APIKeyRecord
	for rows.Next() {
		var key APIKeyRecord
		var lastUsed sql.NullTime
		if err := rows.Scan(&key.ID, &key.UserID, &key.Hash, &key.Prefix, &key.CreatedAt, &lastUsed); err != nil {
			return nil, err
		}
		if lastUsed.Valid {
			key.LastUsed = lastUsed.Time
		}
		keys = append(keys, cloneAPIKeyRecord(&key))
	}
	return keys, rows.Err()
}

func (s *SQLiteStorage) withTx(ctx context.Context, fn func(*sql.Tx) error) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

func isSQLiteUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}
