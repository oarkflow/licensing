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

	"github.com/oarkflow/date"
	"github.com/oarkflow/squealx"
	"github.com/oarkflow/squealx/drivers/sqlite"
)

type SQLiteStorage struct {
	db *squealx.DB
}

func NewSQLiteStorage(path string) (*SQLiteStorage, error) {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	if cleaned == "" || cleaned == "." {
		return nil, fmt.Errorf("sqlite storage path is required")
	}
	if err := os.MkdirAll(filepath.Dir(cleaned), 0o700); err != nil {
		return nil, fmt.Errorf("failed to create sqlite directory: %w", err)
	}
	db, err := sqlite.Open(cleaned, "sqlite")
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

func configureSQLite(db *squealx.DB) error {
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

func ensureSQLiteSchema(db *squealx.DB) error {
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
			plan_slug TEXT NOT NULL,
			license_key TEXT NOT NULL,
			license_key_norm TEXT NOT NULL UNIQUE,
			is_revoked INTEGER NOT NULL DEFAULT 0,
			revoked_at TIMESTAMP,
			revoke_reason TEXT,
			is_activated INTEGER NOT NULL DEFAULT 0,
			issued_at TIMESTAMP NOT NULL,
			last_activated_at TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			current_activations INTEGER NOT NULL DEFAULT 0,
			max_devices INTEGER NOT NULL DEFAULT 0,
			check_mode TEXT NOT NULL DEFAULT 'each_execution',
			check_interval_seconds INTEGER NOT NULL DEFAULT 0,
			next_check_at TIMESTAMP,
			last_check_at TIMESTAMP,
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
	if err := ensureSQLiteColumn(db, "licenses", "max_devices", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(db, "licenses", "plan_slug", "TEXT NOT NULL DEFAULT ''"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(db, "licenses", "check_mode", "TEXT NOT NULL DEFAULT 'each_execution'"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(db, "licenses", "check_interval_seconds", "INTEGER NOT NULL DEFAULT 0"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(db, "licenses", "next_check_at", "TIMESTAMP"); err != nil {
		return err
	}
	if err := ensureSQLiteColumn(db, "licenses", "last_check_at", "TIMESTAMP"); err != nil {
		return err
	}
	hasMaxActivations, err := sqliteColumnExists(db, "licenses", "max_activations")
	if err != nil {
		return err
	}
	if hasMaxActivations {
		if _, err := db.Exec(`UPDATE licenses SET max_devices = CASE WHEN max_devices = 0 THEN max_activations ELSE max_devices END`); err != nil {
			return fmt.Errorf("sqlite migration update failed: %w", err)
		}
	}
	return nil
}

func ensureSQLiteColumn(db *squealx.DB, table, column, definition string) error {
	exists, err := sqliteColumnExists(db, table, column)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	stmt := fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, column, definition)
	if _, err := db.Exec(stmt); err != nil {
		return fmt.Errorf("failed to add column %s: %w", column, err)
	}
	return nil
}

func sqliteColumnExists(db *squealx.DB, table, column string) (bool, error) {
	query := fmt.Sprintf("PRAGMA table_info(%s);", table)
	rows, err := db.Query(query)
	if err != nil {
		return false, fmt.Errorf("failed to inspect table %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid    int
			name   string
			dummy1 interface{}
			dummy2 interface{}
			dummy3 interface{}
			dummy4 interface{}
		)
		if err := rows.Scan(&cid, &name, &dummy1, &dummy2, &dummy3, &dummy4); err != nil {
			return false, fmt.Errorf("failed to scan table info: %w", err)
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("failed to iterate table info: %w", err)
	}
	return false, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

type sqliteTimeValue struct {
	time.Time
}

func (stv *sqliteTimeValue) Scan(value any) error {
	if value == nil {
		stv.Time = time.Time{}
		return nil
	}
	t, err := parseSQLiteTime(value)
	if err != nil {
		return err
	}
	stv.Time = t.UTC()
	return nil
}

type sqliteNullTime struct {
	Time  time.Time
	Valid bool
}

func (snt *sqliteNullTime) Scan(value any) error {
	if value == nil {
		snt.Valid = false
		snt.Time = time.Time{}
		return nil
	}
	t, err := parseSQLiteTime(value)
	if err != nil {
		return err
	}
	snt.Time = t.UTC()
	snt.Valid = true
	return nil
}

func parseSQLiteTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case time.Time:
		return v, nil
	case string:
		return parseSQLiteTimeString(v)
	case []byte:
		return parseSQLiteTimeString(string(v))
	default:
		return time.Time{}, fmt.Errorf("unsupported time value type %T", value)
	}
}

func parseSQLiteTimeString(input string) (time.Time, error) {
	s := strings.TrimSpace(input)
	if s == "" {
		return time.Time{}, nil
	}
	t, err := date.Parse(s)
	if err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("unable to parse time %q", s)
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
	var createdAt, updatedAt sqliteTimeValue
	var banned sqliteNullTime
	var banReason sql.NullString
	if err := scanner.Scan(
		&c.ID,
		&c.Email,
		&c.Status,
		&createdAt,
		&updatedAt,
		&banned,
		&banReason,
	); err != nil {
		return nil, err
	}
	c.CreatedAt = createdAt.Time
	c.UpdatedAt = updatedAt.Time
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
	var revokedAt, lastActivated sqliteNullTime
	var revokeReason sql.NullString
	var issuedAt, expiresAt sqliteTimeValue
	var isRevoked, isActivated int
	var checkMode sql.NullString
	var checkInterval sql.NullInt64
	var nextCheck, lastCheck sqliteNullTime
	if err := scanner.Scan(
		&lic.ID,
		&lic.ClientID,
		&lic.Email,
		&lic.PlanSlug,
		&lic.LicenseKey,
		&isRevoked,
		&revokedAt,
		&revokeReason,
		&isActivated,
		&issuedAt,
		&lastActivated,
		&expiresAt,
		&lic.CurrentActivations,
		&lic.MaxDevices,
		&checkMode,
		&checkInterval,
		&nextCheck,
		&lastCheck,
	); err != nil {
		return nil, err
	}
	lic.IsRevoked = isRevoked == 1
	lic.IsActivated = isActivated == 1
	lic.IssuedAt = issuedAt.Time
	lic.ExpiresAt = expiresAt.Time
	if revokedAt.Valid {
		lic.RevokedAt = revokedAt.Time
	}
	if revokeReason.Valid {
		lic.RevokeReason = revokeReason.String
	}
	if lastActivated.Valid {
		lic.LastActivatedAt = lastActivated.Time
	}
	if checkInterval.Valid {
		lic.CheckIntervalSecs = checkInterval.Int64
	}
	lic.CheckMode = ParseLicenseCheckMode(checkMode.String)
	if nextCheck.Valid {
		lic.NextCheckAt = nextCheck.Time
	}
	if lastCheck.Valid {
		lic.LastCheckAt = lastCheck.Time
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
	return s.withTx(ctx, func(tx squealx.SQLTx) error {
		query := `INSERT INTO licenses (
			id, client_id, email, plan_slug, license_key, license_key_norm, is_revoked, revoked_at,
			revoke_reason, is_activated, issued_at, last_activated_at, expires_at, current_activations, max_devices,
			check_mode, check_interval_seconds, next_check_at, last_check_at)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
		_, err := tx.ExecContext(ctx, query,
			license.ID,
			license.ClientID,
			license.Email,
			license.PlanSlug,
			license.LicenseKey,
			normalizeLicenseKey(license.LicenseKey),
			boolToInt(license.IsRevoked),
			nullTime(license.RevokedAt),
			license.RevokeReason,
			boolToInt(license.IsActivated),
			license.IssuedAt,
			nullTime(license.LastActivatedAt),
			license.ExpiresAt,
			license.CurrentActivations,
			license.MaxDevices,
			license.CheckMode.String(),
			license.CheckIntervalSecs,
			nullTime(license.NextCheckAt),
			nullTime(license.LastCheckAt),
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
	return s.withTx(ctx, func(tx squealx.SQLTx) error {
		query := `UPDATE licenses SET
			client_id = ?, email = ?, plan_slug = ?, license_key = ?, license_key_norm = ?,
	            is_revoked = ?, revoked_at = ?, revoke_reason = ?, is_activated = ?, issued_at = ?,
	            last_activated_at = ?, expires_at = ?, current_activations = ?, max_devices = ?,
	            check_mode = ?, check_interval_seconds = ?, next_check_at = ?, last_check_at = ?
	            WHERE id = ?`
		res, err := tx.ExecContext(ctx, query,
			license.ClientID,
			license.Email,
			license.PlanSlug,
			license.LicenseKey,
			normalizeLicenseKey(license.LicenseKey),
			boolToInt(license.IsRevoked),
			nullTime(license.RevokedAt),
			license.RevokeReason,
			boolToInt(license.IsActivated),
			license.IssuedAt,
			nullTime(license.LastActivatedAt),
			license.ExpiresAt,
			license.CurrentActivations,
			license.MaxDevices,
			license.CheckMode.String(),
			license.CheckIntervalSecs,
			nullTime(license.NextCheckAt),
			nullTime(license.LastCheckAt),
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
	query := `SELECT id, client_id, email, plan_slug, license_key, is_revoked, revoked_at,
		revoke_reason, is_activated, issued_at, last_activated_at, expires_at,
		current_activations, max_devices, check_mode, check_interval_seconds, next_check_at, last_check_at
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
	query := `SELECT id, client_id, email, plan_slug, license_key, is_revoked, revoked_at,
		revoke_reason, is_activated, issued_at, last_activated_at, expires_at,
		current_activations, max_devices, check_mode, check_interval_seconds, next_check_at, last_check_at
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
	query := `SELECT id, client_id, email, plan_slug, license_key, is_revoked, revoked_at,
		revoke_reason, is_activated, issued_at, last_activated_at, expires_at,
		current_activations, max_devices, check_mode, check_interval_seconds, next_check_at, last_check_at
		FROM licenses ORDER BY issued_at DESC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var rawLicenses []*License
	for rows.Next() {
		license, err := scanLicenseRow(rows)
		if err != nil {
			return nil, err
		}
		rawLicenses = append(rawLicenses, license)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	licenses := make([]*License, 0, len(rawLicenses))
	for _, license := range rawLicenses {
		if err := s.loadDevices(ctx, license); err != nil {
			return nil, err
		}
		if err := s.loadAuthorizedUsers(ctx, license); err != nil {
			return nil, err
		}
		licenses = append(licenses, cloneLicense(license))
	}
	return licenses, nil
}

func (s *SQLiteStorage) replaceDevices(ctx context.Context, tx squealx.SQLTx, licenseID string, devices map[string]*LicenseDevice) error {
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
		var activatedAt, lastSeen sqliteTimeValue
		if err := rows.Scan(&device.Fingerprint, &activatedAt, &lastSeen, &transport); err != nil {
			return err
		}
		device.ActivatedAt = activatedAt.Time
		device.LastSeenAt = lastSeen.Time
		device.TransportKey = append([]byte(nil), transport...)
		license.Devices[device.Fingerprint] = &device
	}
	if err := rows.Err(); err != nil {
		return err
	}
	refreshLicenseDeviceStats(license)
	return nil
}

func (s *SQLiteStorage) replaceAuthorizedUsers(ctx context.Context, tx squealx.SQLTx, licenseID string, users map[string]*LicenseIdentity) error {
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
		var grantedAt sqliteTimeValue
		if err := rows.Scan(&ident.Email, &ident.ClientID, &ident.ProviderClientID, &grantedAt); err != nil {
			return err
		}
		ident.GrantedAt = grantedAt.Time
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
		var timestamp sqliteTimeValue
		if err := rows.Scan(
			&rec.ID,
			&rec.LicenseID,
			&rec.ClientID,
			&rec.DeviceFingerprint,
			&rec.IPAddress,
			&rec.UserAgent,
			&success,
			&rec.Message,
			&timestamp,
		); err != nil {
			return nil, err
		}
		rec.Timestamp = timestamp.Time
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
	var createdAt, updatedAt sqliteTimeValue
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errUserMissing
		}
		return nil, err
	}
	user.CreatedAt = createdAt.Time
	user.UpdatedAt = updatedAt.Time
	return cloneAdminUser(&user), nil
}

func (s *SQLiteStorage) GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error) {
	query := `SELECT id, username, password_hash, created_at, updated_at FROM admin_users WHERE username_lower = ?`
	row := s.db.QueryRowContext(ctx, query, strings.ToLower(strings.TrimSpace(username)))
	var user AdminUser
	var createdAt, updatedAt sqliteTimeValue
	if err := row.Scan(&user.ID, &user.Username, &user.PasswordHash, &createdAt, &updatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errUserMissing
		}
		return nil, err
	}
	user.CreatedAt = createdAt.Time
	user.UpdatedAt = updatedAt.Time
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
		var createdAt, updatedAt sqliteTimeValue
		if err := rows.Scan(&user.ID, &user.Username, &user.PasswordHash, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		user.CreatedAt = createdAt.Time
		user.UpdatedAt = updatedAt.Time
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
	var createdAt sqliteTimeValue
	var lastUsed sqliteNullTime
	if err := row.Scan(&key.ID, &key.UserID, &key.Hash, &key.Prefix, &createdAt, &lastUsed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errAPIKeyMissing
		}
		return nil, err
	}
	key.CreatedAt = createdAt.Time
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
		var createdAt sqliteTimeValue
		var lastUsed sqliteNullTime
		if err := rows.Scan(&key.ID, &key.UserID, &key.Hash, &key.Prefix, &createdAt, &lastUsed); err != nil {
			return nil, err
		}
		key.CreatedAt = createdAt.Time
		if lastUsed.Valid {
			key.LastUsed = lastUsed.Time
		}
		keys = append(keys, cloneAPIKeyRecord(&key))
	}
	return keys, rows.Err()
}

func (s *SQLiteStorage) withTx(ctx context.Context, fn func(squealx.SQLTx) error) error {
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
