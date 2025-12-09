package crm

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/oarkflow/squealx"
)

// SQLRepository persists CRM data into a relational database (SQLite or Postgres).
type SQLRepository struct {
	db      *squealx.DB
	dialect sqlDialect
}

type sqlDialect string

const (
	dialectSQLite   sqlDialect = "sqlite"
	dialectPostgres sqlDialect = "postgres"
)

// NewSQLRepository wires the CRM repository to an existing squealx.DB connection.
func NewSQLRepository(db *squealx.DB, driver string) (*SQLRepository, error) {
	if db == nil {
		return nil, errors.New("crm: db handle is required")
	}
	dialect := dialectSQLite
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "postgres", "postgresql", "pgx":
		dialect = dialectPostgres
	case "sqlite", "sqlite3", "modernc":
		dialect = dialectSQLite
	case "":
		// default sqlite
	default:
		return nil, fmt.Errorf("crm: unsupported sql dialect %q", driver)
	}
	return &SQLRepository{db: db, dialect: dialect}, nil
}

// Tenant operations

func (r *SQLRepository) CreateTenant(ctx context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is nil")
	}
	metadata, err := encodeStringMapJSON(tenant.Metadata)
	if err != nil {
		return err
	}
	query := `INSERT INTO tenants (
		id, name, slug, status, industry, region, billing_email, support_email, metadata, created_at, updated_at, deleted_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		tenant.ID,
		tenant.Name,
		tenant.Slug,
		string(tenant.Status),
		nullString(tenant.Industry),
		nullString(tenant.Region),
		nullString(tenant.BillingEmail),
		nullString(tenant.SupportEmail),
		metadata,
		tenant.CreatedAt.UTC(),
		tenant.UpdatedAt.UTC(),
		nullTime(tenant.DeletedAt),
	)
	return translateConstraintError(err, ErrTenantExists)
}

func (r *SQLRepository) UpdateTenant(ctx context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is nil")
	}
	metadata, err := encodeStringMapJSON(tenant.Metadata)
	if err != nil {
		return err
	}
	query := `UPDATE tenants SET
		name = ?,
		slug = ?,
		status = ?,
		industry = ?,
		region = ?,
		billing_email = ?,
		support_email = ?,
		metadata = ?,
		updated_at = ?,
		deleted_at = ?
		WHERE id = ?`
	res, err := r.exec(ctx, query,
		tenant.Name,
		tenant.Slug,
		string(tenant.Status),
		nullString(tenant.Industry),
		nullString(tenant.Region),
		nullString(tenant.BillingEmail),
		nullString(tenant.SupportEmail),
		metadata,
		tenant.UpdatedAt.UTC(),
		nullTime(tenant.DeletedAt),
		tenant.ID,
	)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrTenantMissing
	}
	return nil
}

func (r *SQLRepository) GetTenant(ctx context.Context, tenantID string) (*Tenant, error) {
	query := `SELECT id, name, slug, status, industry, region, billing_email, support_email, metadata, created_at, updated_at, deleted_at
		FROM tenants WHERE id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), tenantID)
	return scanTenant(row)
}

func (r *SQLRepository) GetTenantBySlug(ctx context.Context, slug string) (*Tenant, error) {
	query := `SELECT id, name, slug, status, industry, region, billing_email, support_email, metadata, created_at, updated_at, deleted_at
		FROM tenants WHERE lower(slug) = lower(?)`
	row := r.db.QueryRowContext(ctx, r.bind(query), slug)
	return scanTenant(row)
}

func (r *SQLRepository) ListTenants(ctx context.Context, opts ListTenantsOptions) ([]*Tenant, error) {
	query := `SELECT id, name, slug, status, industry, region, billing_email, support_email, metadata, created_at, updated_at, deleted_at FROM tenants`
	rows, err := r.query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tenants []*Tenant
	for rows.Next() {
		tenant, err := scanTenant(rows)
		if err != nil {
			return nil, err
		}
		tenants = append(tenants, tenant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	filtered := filterTenants(tenants, opts)
	start, end := clampWindow(len(filtered), opts.Offset, opts.Limit)
	return filtered[start:end], nil
}

func (r *SQLRepository) SaveTenantSettings(ctx context.Context, settings *TenantSettings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	loginModes, err := encodeStringSliceJSON(settings.LoginModes)
	if err != nil {
		return err
	}
	allowed, err := encodeStringSliceJSON(settings.AllowedOrigins)
	if err != nil {
		return err
	}
	metadata, err := encodeStringMapJSON(settings.Metadata)
	if err != nil {
		return err
	}
	query := `INSERT INTO tenant_settings (tenant_id, login_modes, allowed_origins, policy_version, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(tenant_id) DO UPDATE SET
			login_modes = excluded.login_modes,
			allowed_origins = excluded.allowed_origins,
			policy_version = excluded.policy_version,
			metadata = excluded.metadata,
			updated_at = excluded.updated_at`
	_, err = r.exec(ctx, query,
		settings.TenantID,
		loginModes,
		allowed,
		nullString(settings.PolicyVersion),
		metadata,
		settings.CreatedAt.UTC(),
		settings.UpdatedAt.UTC(),
	)
	return err
}

func (r *SQLRepository) GetTenantSettings(ctx context.Context, tenantID string) (*TenantSettings, error) {
	query := `SELECT tenant_id, login_modes, allowed_origins, policy_version, metadata, created_at, updated_at
		FROM tenant_settings WHERE tenant_id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), tenantID)
	var ts TenantSettings
	var loginModes, allowed, metadata []byte
	var policy sql.NullString
	if err := row.Scan(&ts.TenantID, &loginModes, &allowed, &policy, &metadata, &ts.CreatedAt, &ts.UpdatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTenantMissing
		}
		return nil, err
	}
	if err := decodeStringSliceJSON(loginModes, &ts.LoginModes); err != nil {
		return nil, err
	}
	if err := decodeStringSliceJSON(allowed, &ts.AllowedOrigins); err != nil {
		return nil, err
	}
	if err := decodeStringMapJSON(metadata, &ts.Metadata); err != nil {
		return nil, err
	}
	if policy.Valid {
		ts.PolicyVersion = policy.String
	}
	return &ts, nil
}

// CRM Users

func (r *SQLRepository) CreateCRMUser(ctx context.Context, user *CRMUser) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}
	attributes, err := encodeStringMapJSON(user.Attributes)
	if err != nil {
		return err
	}
	mfaMethods, err := encodeStringSliceJSON(user.MFAMethods)
	if err != nil {
		return err
	}
	query := `INSERT INTO crm_users (
		id, tenant_id, email, email_lower, username, username_lower, role, status, password_hash, mfa_enabled,
		mfa_methods, attributes, last_login_at, password_rotated_at, created_at, updated_at)
		VALUES (?, ?, ?, lower(?), ?, lower(?), ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		user.ID,
		user.TenantID,
		user.Email,
		user.Email,
		user.Username,
		user.Username,
		string(user.Role),
		string(user.Status),
		nullBytes(user.PasswordHash),
		boolToInt(user.MFAEnabled),
		mfaMethods,
		attributes,
		nullTime(user.LastLoginAt),
		nullTime(user.PasswordRotatedAt),
		user.CreatedAt.UTC(),
		user.UpdatedAt.UTC(),
	)
	return translateConstraintError(err, ErrUserExists)
}

func (r *SQLRepository) UpdateCRMUser(ctx context.Context, user *CRMUser) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}
	attributes, err := encodeStringMapJSON(user.Attributes)
	if err != nil {
		return err
	}
	mfaMethods, err := encodeStringSliceJSON(user.MFAMethods)
	if err != nil {
		return err
	}
	query := `UPDATE crm_users SET
		email = ?,
		email_lower = lower(?),
		username = ?,
		username_lower = lower(?),
		role = ?,
		status = ?,
		password_hash = ?,
		mfa_enabled = ?,
		mfa_methods = ?,
		attributes = ?,
		last_login_at = ?,
		password_rotated_at = ?,
		updated_at = ?
		WHERE id = ?`
	res, err := r.exec(ctx, query,
		user.Email,
		user.Email,
		user.Username,
		user.Username,
		string(user.Role),
		string(user.Status),
		nullBytes(user.PasswordHash),
		boolToInt(user.MFAEnabled),
		mfaMethods,
		attributes,
		nullTime(user.LastLoginAt),
		nullTime(user.PasswordRotatedAt),
		user.UpdatedAt.UTC(),
		user.ID,
	)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrUserMissing
	}
	return nil
}

func (r *SQLRepository) DeleteCRMUser(ctx context.Context, userID string) error {
	query := `DELETE FROM crm_users WHERE id = ?`
	res, err := r.exec(ctx, query, userID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrUserMissing
	}
	return nil
}

func (r *SQLRepository) GetCRMUser(ctx context.Context, userID string) (*CRMUser, error) {
	query := `SELECT id, tenant_id, email, username, role, status, password_hash, mfa_enabled, mfa_methods,
		attributes, last_login_at, password_rotated_at, created_at, updated_at
		FROM crm_users WHERE id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), userID)
	return r.scanUser(row)
}

func (r *SQLRepository) GetCRMUserByEmail(ctx context.Context, tenantID, email string) (*CRMUser, error) {
	query := `SELECT id, tenant_id, email, username, role, status, password_hash, mfa_enabled, mfa_methods,
		attributes, last_login_at, password_rotated_at, created_at, updated_at
		FROM crm_users WHERE tenant_id = ? AND email_lower = lower(?)`
	row := r.db.QueryRowContext(ctx, r.bind(query), tenantID, email)
	return r.scanUser(row)
}

func (r *SQLRepository) FindCRMUserByIdentifier(ctx context.Context, identifier string) (*CRMUser, error) {
	query := `SELECT id, tenant_id, email, username, role, status, password_hash, mfa_enabled, mfa_methods,
		attributes, last_login_at, password_rotated_at, created_at, updated_at
		FROM crm_users WHERE email_lower = lower(?) OR username_lower = lower(?) LIMIT 1`
	row := r.db.QueryRowContext(ctx, r.bind(query), identifier, identifier)
	return r.scanUser(row)
}

func (r *SQLRepository) ListCRMUsers(ctx context.Context, tenantID string) ([]*CRMUser, error) {
	query := `SELECT id, tenant_id, email, username, role, status, password_hash, mfa_enabled, mfa_methods,
		attributes, last_login_at, password_rotated_at, created_at, updated_at
		FROM crm_users WHERE tenant_id = ? ORDER BY lower(email)`
	rows, err := r.query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var users []*CRMUser
	for rows.Next() {
		user, err := r.scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, rows.Err()
}

// Contacts

func (r *SQLRepository) CreateContact(ctx context.Context, contact *Contact) error {
	if contact == nil {
		return fmt.Errorf("contact is nil")
	}
	tags, err := encodeStringSliceJSON(contact.Tags)
	if err != nil {
		return err
	}
	attributes, err := encodeStringMapJSON(contact.Attributes)
	if err != nil {
		return err
	}
	query := `INSERT INTO contacts (
		id, tenant_id, client_id, first_name, last_name, email, email_lower, phone, title, tags, attributes, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, lower(?), ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		contact.ID,
		contact.TenantID,
		nullString(contact.ClientID),
		contact.FirstName,
		contact.LastName,
		contact.Email,
		contact.Email,
		nullString(contact.Phone),
		nullString(contact.Title),
		tags,
		attributes,
		contact.CreatedAt.UTC(),
		contact.UpdatedAt.UTC(),
	)
	return translateConstraintError(err, ErrContactExists)
}

func (r *SQLRepository) UpdateContact(ctx context.Context, contact *Contact) error {
	if contact == nil {
		return fmt.Errorf("contact is nil")
	}
	tags, err := encodeStringSliceJSON(contact.Tags)
	if err != nil {
		return err
	}
	attributes, err := encodeStringMapJSON(contact.Attributes)
	if err != nil {
		return err
	}
	query := `UPDATE contacts SET
		client_id = ?,
		first_name = ?,
		last_name = ?,
		email = ?,
		email_lower = lower(?),
		phone = ?,
		title = ?,
		tags = ?,
		attributes = ?,
		updated_at = ?
		WHERE id = ?`
	res, err := r.exec(ctx, query,
		nullString(contact.ClientID),
		contact.FirstName,
		contact.LastName,
		contact.Email,
		contact.Email,
		nullString(contact.Phone),
		nullString(contact.Title),
		tags,
		attributes,
		contact.UpdatedAt.UTC(),
		contact.ID,
	)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrContactMissing
	}
	return nil
}

func (r *SQLRepository) DeleteContact(ctx context.Context, contactID string) error {
	query := `DELETE FROM contacts WHERE id = ?`
	res, err := r.exec(ctx, query, contactID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrContactMissing
	}
	return nil
}

func (r *SQLRepository) GetContact(ctx context.Context, contactID string) (*Contact, error) {
	query := `SELECT id, tenant_id, client_id, first_name, last_name, email, phone, title, tags, attributes, created_at, updated_at
		FROM contacts WHERE id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), contactID)
	return scanContact(row)
}

func (r *SQLRepository) ListContacts(ctx context.Context, opts ListContactsOptions) ([]*Contact, error) {
	query := `SELECT id, tenant_id, client_id, first_name, last_name, email, phone, title, tags, attributes, created_at, updated_at FROM contacts`
	rows, err := r.query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var contacts []*Contact
	for rows.Next() {
		contact, err := scanContact(rows)
		if err != nil {
			return nil, err
		}
		contacts = append(contacts, contact)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	filtered := filterContacts(contacts, opts)
	start, end := clampWindow(len(filtered), opts.Offset, opts.Limit)
	return filtered[start:end], nil
}

// Credential secrets

func (r *SQLRepository) SaveCredentialSecret(ctx context.Context, secret *CredentialSecret) error {
	if secret == nil {
		return fmt.Errorf("secret is nil")
	}
	metadata, err := encodeStringMapJSON(secret.Metadata)
	if err != nil {
		return err
	}
	query := `INSERT INTO credential_secrets (
		id, tenant_id, user_id, contact_id, type, version, hash, encrypted_value, metadata, expires_at, rotated_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		secret.ID,
		secret.TenantID,
		nullString(secret.UserID),
		nullString(secret.ContactID),
		string(secret.Type),
		secret.Version,
		nullBytes(secret.Hash),
		nullBytes(secret.EncryptedValue),
		metadata,
		nullTime(secret.ExpiresAt),
		nullTime(secret.RotatedAt),
		secret.CreatedAt.UTC(),
	)
	return err
}

func (r *SQLRepository) GetLatestCredentialSecret(ctx context.Context, tenantID, subjectID string, _ SessionSubjectType, secretType CredentialSecretType) (*CredentialSecret, error) {
	query := `SELECT id, tenant_id, user_id, contact_id, type, version, hash, encrypted_value, metadata, expires_at, rotated_at, created_at
		FROM credential_secrets
		WHERE tenant_id = ? AND type = ? AND (user_id = ? OR contact_id = ?)
		ORDER BY version DESC LIMIT 1`
	row := r.db.QueryRowContext(ctx, r.bind(query), tenantID, string(secretType), subjectID, subjectID)
	return scanSecret(row)
}

func (r *SQLRepository) ListCredentialSecrets(ctx context.Context, tenantID, subjectID string, secretType CredentialSecretType) ([]*CredentialSecret, error) {
	args := []any{tenantID}
	conditions := []string{"tenant_id = ?"}
	if secretType != "" {
		conditions = append(conditions, "type = ?")
		args = append(args, string(secretType))
	}
	if subjectID != "" {
		conditions = append(conditions, "(user_id = ? OR contact_id = ?)")
		args = append(args, subjectID, subjectID)
	}
	query := fmt.Sprintf(`SELECT id, tenant_id, user_id, contact_id, type, version, hash, encrypted_value, metadata, expires_at, rotated_at, created_at
		FROM credential_secrets WHERE %s ORDER BY version DESC`, strings.Join(conditions, " AND "))
	rows, err := r.query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*CredentialSecret
	for rows.Next() {
		secret, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, secret)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Version > list[j].Version })
	return list, nil
}

// Session tokens

func (r *SQLRepository) CreateSessionToken(ctx context.Context, token *SessionToken) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}
	audience, err := encodeStringSliceJSON(token.Audience)
	if err != nil {
		return err
	}
	scopes, err := encodeStringSliceJSON(token.Scopes)
	if err != nil {
		return err
	}
	metadata, err := encodeStringMapJSON(token.Metadata)
	if err != nil {
		return err
	}
	query := `INSERT INTO session_tokens (
		id, tenant_id, subject_id, subject_type, audience, scopes, issued_at, expires_at,
		not_before, revoked_at, revoked_by, device_fingerprint, client_ip, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		token.ID,
		token.TenantID,
		token.SubjectID,
		string(token.SubjectType),
		audience,
		scopes,
		token.IssuedAt.UTC(),
		token.ExpiresAt.UTC(),
		nullTime(token.NotBefore),
		nullTime(token.RevokedAt),
		nullString(token.RevokedBy),
		nullString(token.DeviceFingerprint),
		nullString(token.ClientIP),
		metadata,
	)
	return err
}

func (r *SQLRepository) UpdateSessionToken(ctx context.Context, token *SessionToken) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}
	audience, err := encodeStringSliceJSON(token.Audience)
	if err != nil {
		return err
	}
	scopes, err := encodeStringSliceJSON(token.Scopes)
	if err != nil {
		return err
	}
	metadata, err := encodeStringMapJSON(token.Metadata)
	if err != nil {
		return err
	}
	query := `UPDATE session_tokens SET
		audience = ?,
		scopes = ?,
		expires_at = ?,
		not_before = ?,
		revoked_at = ?,
		revoked_by = ?,
		device_fingerprint = ?,
		client_ip = ?,
		metadata = ?
		WHERE id = ?`
	res, err := r.exec(ctx, query,
		audience,
		scopes,
		token.ExpiresAt.UTC(),
		nullTime(token.NotBefore),
		nullTime(token.RevokedAt),
		nullString(token.RevokedBy),
		nullString(token.DeviceFingerprint),
		nullString(token.ClientIP),
		metadata,
		token.ID,
	)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrSessionMissing
	}
	return nil
}

func (r *SQLRepository) GetSessionToken(ctx context.Context, tokenID string) (*SessionToken, error) {
	query := `SELECT id, tenant_id, subject_id, subject_type, audience, scopes, issued_at, expires_at,
		not_before, revoked_at, revoked_by, device_fingerprint, client_ip, metadata
		FROM session_tokens WHERE id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), tokenID)
	return scanSessionToken(row)
}

func (r *SQLRepository) ListActiveSessionTokens(ctx context.Context, filter SessionTokenFilter) ([]*SessionToken, error) {
	query := `SELECT id, tenant_id, subject_id, subject_type, audience, scopes, issued_at, expires_at,
		not_before, revoked_at, revoked_by, device_fingerprint, client_ip, metadata
		FROM session_tokens`
	rows, err := r.query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	now := time.Now()
	var list []*SessionToken
	for rows.Next() {
		token, err := scanSessionToken(rows)
		if err != nil {
			return nil, err
		}
		if filter.TenantID != "" && token.TenantID != filter.TenantID {
			continue
		}
		if filter.SubjectID != "" && token.SubjectID != filter.SubjectID {
			continue
		}
		if filter.SubjectType != "" && token.SubjectType != filter.SubjectType {
			continue
		}
		if !filter.IncludeRevoked {
			if !token.RevokedAt.IsZero() || token.ExpiresAt.Before(now) {
				continue
			}
		}
		list = append(list, token)
	}
	return list, rows.Err()
}

func (r *SQLRepository) RevokeSessionTokens(ctx context.Context, filter SessionTokenFilter) (int, error) {
	conditions := []string{"1=1"}
	args := []any{}
	if filter.TenantID != "" {
		conditions = append(conditions, "tenant_id = ?")
		args = append(args, filter.TenantID)
	}
	if filter.SubjectID != "" {
		conditions = append(conditions, "subject_id = ?")
		args = append(args, filter.SubjectID)
	}
	if filter.SubjectType != "" {
		conditions = append(conditions, "subject_type = ?")
		args = append(args, string(filter.SubjectType))
	}
	query := fmt.Sprintf(`UPDATE session_tokens SET revoked_at = ?, revoked_by = COALESCE(revoked_by, 'system') WHERE %s AND revoked_at IS NULL`, strings.Join(conditions, " AND "))
	args = append([]any{time.Now().UTC()}, args...)
	res, err := r.exec(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	rows, _ := res.RowsAffected()
	return int(rows), nil
}

// Entitlements

func (r *SQLRepository) CreateEntitlementBinding(ctx context.Context, binding *EntitlementBinding) error {
	if binding == nil {
		return fmt.Errorf("binding is nil")
	}
	overrides, err := encodeFeatureOverrides(binding.FeatureOverrides)
	if err != nil {
		return err
	}
	query := `INSERT INTO entitlement_bindings (
		id, tenant_id, contact_id, client_id, product_id, product_slug, plan_id, plan_slug, status,
		feature_overrides, effective_at, expires_at, revoked_at, revocation_reason, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		binding.ID,
		binding.TenantID,
		nullString(binding.ContactID),
		nullString(binding.ClientID),
		binding.ProductID,
		nullString(binding.ProductSlug),
		binding.PlanID,
		nullString(binding.PlanSlug),
		string(binding.Status),
		overrides,
		binding.EffectiveAt.UTC(),
		nullTime(binding.ExpiresAt),
		nullTime(binding.RevokedAt),
		nullString(binding.RevocationReason),
		binding.CreatedAt.UTC(),
		binding.UpdatedAt.UTC(),
	)
	return err
}

func (r *SQLRepository) UpdateEntitlementBinding(ctx context.Context, binding *EntitlementBinding) error {
	if binding == nil {
		return fmt.Errorf("binding is nil")
	}
	overrides, err := encodeFeatureOverrides(binding.FeatureOverrides)
	if err != nil {
		return err
	}
	query := `UPDATE entitlement_bindings SET
		contact_id = ?,
		client_id = ?,
		product_id = ?,
		product_slug = ?,
		plan_id = ?,
		plan_slug = ?,
		status = ?,
		feature_overrides = ?,
		effective_at = ?,
		expires_at = ?,
		revoked_at = ?,
		revocation_reason = ?,
		updated_at = ?
		WHERE id = ?`
	res, err := r.exec(ctx, query,
		nullString(binding.ContactID),
		nullString(binding.ClientID),
		binding.ProductID,
		nullString(binding.ProductSlug),
		binding.PlanID,
		nullString(binding.PlanSlug),
		string(binding.Status),
		overrides,
		binding.EffectiveAt.UTC(),
		nullTime(binding.ExpiresAt),
		nullTime(binding.RevokedAt),
		nullString(binding.RevocationReason),
		binding.UpdatedAt.UTC(),
		binding.ID,
	)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrEntitlementMissing
	}
	return nil
}

func (r *SQLRepository) GetEntitlementBinding(ctx context.Context, bindingID string) (*EntitlementBinding, error) {
	query := `SELECT id, tenant_id, contact_id, client_id, product_id, product_slug, plan_id, plan_slug, status,
		feature_overrides, effective_at, expires_at, revoked_at, revocation_reason, created_at, updated_at
		FROM entitlement_bindings WHERE id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), bindingID)
	return scanEntitlement(row)
}

func (r *SQLRepository) ListEntitlementBindings(ctx context.Context, opts ListEntitlementsOptions) ([]*EntitlementBinding, error) {
	query := `SELECT id, tenant_id, contact_id, client_id, product_id, product_slug, plan_id, plan_slug, status,
		feature_overrides, effective_at, expires_at, revoked_at, revocation_reason, created_at, updated_at FROM entitlement_bindings`
	rows, err := r.query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*EntitlementBinding
	for rows.Next() {
		binding, err := scanEntitlement(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return filterEntitlements(list, opts), nil
}

// Product releases

func (r *SQLRepository) CreateProductRelease(ctx context.Context, release *ProductRelease) error {
	if release == nil {
		return fmt.Errorf("release is nil")
	}
	metadata, err := encodeStringMapJSON(release.Metadata)
	if err != nil {
		return err
	}
	query := `INSERT INTO product_releases (
		id, product_id, channel, version, summary, metadata, published_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		release.ID,
		release.ProductID,
		release.Channel,
		release.Version,
		nullString(release.Summary),
		metadata,
		release.PublishedAt.UTC(),
		release.CreatedAt.UTC(),
		release.UpdatedAt.UTC(),
	)
	return err
}

func (r *SQLRepository) UpdateProductRelease(ctx context.Context, release *ProductRelease) error {
	if release == nil {
		return fmt.Errorf("release is nil")
	}
	metadata, err := encodeStringMapJSON(release.Metadata)
	if err != nil {
		return err
	}
	query := `UPDATE product_releases SET
		product_id = ?,
		channel = ?,
		version = ?,
		summary = ?,
		metadata = ?,
		published_at = ?,
		updated_at = ?
		WHERE id = ?`
	res, err := r.exec(ctx, query,
		release.ProductID,
		release.Channel,
		release.Version,
		nullString(release.Summary),
		metadata,
		release.PublishedAt.UTC(),
		release.UpdatedAt.UTC(),
		release.ID,
	)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return fmt.Errorf("product release not found")
	}
	return nil
}

func (r *SQLRepository) DeleteProductRelease(ctx context.Context, releaseID string) error {
	query := `DELETE FROM product_releases WHERE id = ?`
	res, err := r.exec(ctx, query, releaseID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return fmt.Errorf("product release not found")
	}
	return nil
}

func (r *SQLRepository) GetProductRelease(ctx context.Context, releaseID string) (*ProductRelease, error) {
	query := `SELECT id, product_id, channel, version, summary, metadata, published_at, created_at, updated_at
		FROM product_releases WHERE id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), releaseID)
	return scanRelease(row)
}

func (r *SQLRepository) ListProductReleases(ctx context.Context, productID string, limit int) ([]*ProductRelease, error) {
	query := `SELECT id, product_id, channel, version, summary, metadata, published_at, created_at, updated_at
		FROM product_releases WHERE product_id = ? ORDER BY published_at DESC`
	rows, err := r.query(ctx, query, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*ProductRelease
	for rows.Next() {
		release, err := scanRelease(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, release)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	start, end := clampWindow(len(list), 0, limit)
	return list[start:end], nil
}

// Device ledger

func (r *SQLRepository) UpsertDeviceLedger(ctx context.Context, record *DeviceLedger) error {
	if record == nil {
		return fmt.Errorf("device ledger is nil")
	}
	metadata, err := encodeStringMapJSON(record.Metadata)
	if err != nil {
		return err
	}
	query := `INSERT INTO device_ledgers (
		id, tenant_id, client_id, license_id, device_fingerprint, last_seen_at, last_sync_at,
		pending_revocation, revocation_epoch, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			client_id = excluded.client_id,
			license_id = excluded.license_id,
			last_seen_at = excluded.last_seen_at,
			last_sync_at = excluded.last_sync_at,
			pending_revocation = excluded.pending_revocation,
			revocation_epoch = excluded.revocation_epoch,
			metadata = excluded.metadata,
			updated_at = excluded.updated_at`
	if record.ID == "" {
		record.ID = fmt.Sprintf("ledger-%s-%s", record.TenantID, record.DeviceFingerprint)
	}
	_, err = r.exec(ctx, query,
		record.ID,
		record.TenantID,
		nullString(record.ClientID),
		nullString(record.LicenseID),
		record.DeviceFingerprint,
		record.LastSeenAt.UTC(),
		nullTime(record.LastSyncAt),
		boolToInt(record.PendingRevocation),
		record.RevocationEpoch,
		metadata,
		record.CreatedAt.UTC(),
		record.UpdatedAt.UTC(),
	)
	return err
}

func (r *SQLRepository) GetDeviceLedgerByFingerprint(ctx context.Context, tenantID, fingerprint string) (*DeviceLedger, error) {
	query := `SELECT id, tenant_id, client_id, license_id, device_fingerprint, last_seen_at, last_sync_at,
		pending_revocation, revocation_epoch, metadata, created_at, updated_at
		FROM device_ledgers WHERE tenant_id = ? AND device_fingerprint = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), tenantID, fingerprint)
	return scanDeviceLedger(row)
}

func (r *SQLRepository) ListDeviceLedgers(ctx context.Context, filter DeviceLedgerFilter) ([]*DeviceLedger, error) {
	query := `SELECT id, tenant_id, client_id, license_id, device_fingerprint, last_seen_at, last_sync_at,
		pending_revocation, revocation_epoch, metadata, created_at, updated_at FROM device_ledgers`
	rows, err := r.query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*DeviceLedger
	for rows.Next() {
		record, err := scanDeviceLedger(rows)
		if err != nil {
			return nil, err
		}
		if filter.TenantID != "" && record.TenantID != filter.TenantID {
			continue
		}
		if filter.ClientID != "" && record.ClientID != filter.ClientID {
			continue
		}
		if filter.LicenseID != "" && record.LicenseID != filter.LicenseID {
			continue
		}
		if filter.Fingerprint != "" && record.DeviceFingerprint != filter.Fingerprint {
			continue
		}
		if filter.PendingOnly && !record.PendingRevocation {
			continue
		}
		list = append(list, record)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UpdatedAt.After(list[j].UpdatedAt) })
	return list, nil
}

// Service accounts

func (r *SQLRepository) CreateServiceAccount(ctx context.Context, sa *ServiceAccount) error {
	if sa == nil {
		return fmt.Errorf("service account is nil")
	}
	scopes, err := encodeStringSliceJSON(sa.Scopes)
	if err != nil {
		return err
	}
	query := `INSERT INTO service_accounts (
		id, tenant_id, name, description, scopes, created_by, last_used_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = r.exec(ctx, query,
		sa.ID,
		sa.TenantID,
		sa.Name,
		nullString(sa.Description),
		scopes,
		sa.CreatedBy,
		nullTime(sa.LastUsedAt),
		sa.CreatedAt.UTC(),
		sa.UpdatedAt.UTC(),
	)
	return translateConstraintError(err, fmt.Errorf("service account exists"))
}

func (r *SQLRepository) UpdateServiceAccount(ctx context.Context, sa *ServiceAccount) error {
	if sa == nil {
		return fmt.Errorf("service account is nil")
	}
	scopes, err := encodeStringSliceJSON(sa.Scopes)
	if err != nil {
		return err
	}
	query := `UPDATE service_accounts SET
		name = ?,
		description = ?,
		scopes = ?,
		last_used_at = ?,
		updated_at = ?
		WHERE id = ?`
	res, err := r.exec(ctx, query,
		sa.Name,
		nullString(sa.Description),
		scopes,
		nullTime(sa.LastUsedAt),
		sa.UpdatedAt.UTC(),
		sa.ID,
	)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrServiceAccountMissing
	}
	return nil
}

func (r *SQLRepository) DeleteServiceAccount(ctx context.Context, serviceAccountID string) error {
	query := `DELETE FROM service_accounts WHERE id = ?`
	res, err := r.exec(ctx, query, serviceAccountID)
	if err != nil {
		return err
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		return ErrServiceAccountMissing
	}
	return nil
}

func (r *SQLRepository) GetServiceAccount(ctx context.Context, serviceAccountID string) (*ServiceAccount, error) {
	query := `SELECT id, tenant_id, name, description, scopes, created_by, last_used_at, created_at, updated_at
		FROM service_accounts WHERE id = ?`
	row := r.db.QueryRowContext(ctx, r.bind(query), serviceAccountID)
	return scanServiceAccount(row)
}

func (r *SQLRepository) ListServiceAccounts(ctx context.Context, tenantID string) ([]*ServiceAccount, error) {
	query := `SELECT id, tenant_id, name, description, scopes, created_by, last_used_at, created_at, updated_at
		FROM service_accounts WHERE tenant_id = ? ORDER BY lower(name)`
	rows, err := r.query(ctx, query, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*ServiceAccount
	for rows.Next() {
		sa, err := scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, sa)
	}
	return list, rows.Err()
}

// --- helpers ---

type rowScanner interface {
	Scan(dest ...any) error
}

func (r *SQLRepository) exec(ctx context.Context, query string, args ...any) (sql.Result, error) {
	return r.db.ExecContext(ctx, r.bind(query), args...)
}

func (r *SQLRepository) query(ctx context.Context, query string, args ...any) (squealx.SQLRows, error) {
	return r.db.QueryContext(ctx, r.bind(query), args...)
}

func (r *SQLRepository) bind(query string) string {
	if r.dialect != dialectPostgres {
		return query
	}
	var b strings.Builder
	b.Grow(len(query) + 10)
	idx := 1
	for i := 0; i < len(query); i++ {
		if query[i] == '?' {
			fmt.Fprintf(&b, "$%d", idx)
			idx++
			continue
		}
		b.WriteByte(query[i])
	}
	return b.String()
}

func scanTenant(rs rowScanner) (*Tenant, error) {
	var t Tenant
	var status string
	var industry, region, billing, support sql.NullString
	var metadata []byte
	var deleted sql.NullTime
	if err := rs.Scan(
		&t.ID,
		&t.Name,
		&t.Slug,
		&status,
		&industry,
		&region,
		&billing,
		&support,
		&metadata,
		&t.CreatedAt,
		&t.UpdatedAt,
		&deleted,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrTenantMissing
		}
		return nil, err
	}
	t.Status = TenantStatus(status)
	if industry.Valid {
		t.Industry = industry.String
	}
	if region.Valid {
		t.Region = region.String
	}
	if billing.Valid {
		t.BillingEmail = billing.String
	}
	if support.Valid {
		t.SupportEmail = support.String
	}
	if err := decodeStringMapJSON(metadata, &t.Metadata); err != nil {
		return nil, err
	}
	if deleted.Valid {
		t.DeletedAt = deleted.Time
	}
	return &t, nil
}

func (r *SQLRepository) scanUser(rs rowScanner) (*CRMUser, error) {
	var u CRMUser
	var role, status string
	var password []byte
	var mfaMethods, attributes []byte
	var lastLogin, rotated sql.NullTime
	if err := rs.Scan(
		&u.ID,
		&u.TenantID,
		&u.Email,
		&u.Username,
		&role,
		&status,
		&password,
		&u.MFAEnabled,
		&mfaMethods,
		&attributes,
		&lastLogin,
		&rotated,
		&u.CreatedAt,
		&u.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserMissing
		}
		return nil, err
	}
	u.Role = CRMUserRole(role)
	u.Status = CRMUserStatus(status)
	u.PasswordHash = append([]byte(nil), password...)
	if err := decodeStringSliceJSON(mfaMethods, &u.MFAMethods); err != nil {
		return nil, err
	}
	if err := decodeStringMapJSON(attributes, &u.Attributes); err != nil {
		return nil, err
	}
	if lastLogin.Valid {
		u.LastLoginAt = lastLogin.Time
	}
	if rotated.Valid {
		u.PasswordRotatedAt = rotated.Time
	}
	return &u, nil
}

func scanContact(rs rowScanner) (*Contact, error) {
	var c Contact
	var clientID, phone, title sql.NullString
	var tagsJSON, attrsJSON []byte
	if err := rs.Scan(
		&c.ID,
		&c.TenantID,
		&clientID,
		&c.FirstName,
		&c.LastName,
		&c.Email,
		&phone,
		&title,
		&tagsJSON,
		&attrsJSON,
		&c.CreatedAt,
		&c.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrContactMissing
		}
		return nil, err
	}
	if clientID.Valid {
		c.ClientID = clientID.String
	}
	if phone.Valid {
		c.Phone = phone.String
	}
	if title.Valid {
		c.Title = title.String
	}
	if err := decodeStringSliceJSON(tagsJSON, &c.Tags); err != nil {
		return nil, err
	}
	if err := decodeStringMapJSON(attrsJSON, &c.Attributes); err != nil {
		return nil, err
	}
	return &c, nil
}

func scanSecret(rs rowScanner) (*CredentialSecret, error) {
	var cs CredentialSecret
	var secretType string
	var metadata []byte
	var expires, rotated sql.NullTime
	var userID, contactID sql.NullString
	var hash, encrypted []byte
	if err := rs.Scan(
		&cs.ID,
		&cs.TenantID,
		&userID,
		&contactID,
		&secretType,
		&cs.Version,
		&hash,
		&encrypted,
		&metadata,
		&expires,
		&rotated,
		&cs.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSecretMissing
		}
		return nil, err
	}
	cs.Type = CredentialSecretType(secretType)
	if userID.Valid {
		cs.UserID = userID.String
	}
	if contactID.Valid {
		cs.ContactID = contactID.String
	}
	cs.Hash = append([]byte(nil), hash...)
	cs.EncryptedValue = append([]byte(nil), encrypted...)
	if err := decodeStringMapJSON(metadata, &cs.Metadata); err != nil {
		return nil, err
	}
	if expires.Valid {
		cs.ExpiresAt = expires.Time
	}
	if rotated.Valid {
		cs.RotatedAt = rotated.Time
	}
	return &cs, nil
}

func scanSessionToken(rs rowScanner) (*SessionToken, error) {
	var st SessionToken
	var subjectType string
	var audience, scopes, metadata []byte
	var notBefore, revoked sql.NullTime
	var revokedBy, device, client sql.NullString
	if err := rs.Scan(
		&st.ID,
		&st.TenantID,
		&st.SubjectID,
		&subjectType,
		&audience,
		&scopes,
		&st.IssuedAt,
		&st.ExpiresAt,
		&notBefore,
		&revoked,
		&revokedBy,
		&device,
		&client,
		&metadata,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrSessionMissing
		}
		return nil, err
	}
	st.SubjectType = SessionSubjectType(subjectType)
	if err := decodeStringSliceJSON(audience, &st.Audience); err != nil {
		return nil, err
	}
	if err := decodeStringSliceJSON(scopes, &st.Scopes); err != nil {
		return nil, err
	}
	if err := decodeStringMapJSON(metadata, &st.Metadata); err != nil {
		return nil, err
	}
	if notBefore.Valid {
		st.NotBefore = notBefore.Time
	}
	if revoked.Valid {
		st.RevokedAt = revoked.Time
	}
	if revokedBy.Valid {
		st.RevokedBy = revokedBy.String
	}
	if device.Valid {
		st.DeviceFingerprint = device.String
	}
	if client.Valid {
		st.ClientIP = client.String
	}
	return &st, nil
}

func scanEntitlement(rs rowScanner) (*EntitlementBinding, error) {
	var eb EntitlementBinding
	var status string
	var contactID, clientID, productSlug, planSlug, revocationReason sql.NullString
	var overrides []byte
	var expires, revoked sql.NullTime
	if err := rs.Scan(
		&eb.ID,
		&eb.TenantID,
		&contactID,
		&clientID,
		&eb.ProductID,
		&productSlug,
		&eb.PlanID,
		&planSlug,
		&status,
		&overrides,
		&eb.EffectiveAt,
		&expires,
		&revoked,
		&revocationReason,
		&eb.CreatedAt,
		&eb.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrEntitlementMissing
		}
		return nil, err
	}
	if contactID.Valid {
		eb.ContactID = contactID.String
	}
	if clientID.Valid {
		eb.ClientID = clientID.String
	}
	if productSlug.Valid {
		eb.ProductSlug = productSlug.String
	}
	if planSlug.Valid {
		eb.PlanSlug = planSlug.String
	}
	if revocationReason.Valid {
		eb.RevocationReason = revocationReason.String
	}
	if expires.Valid {
		eb.ExpiresAt = expires.Time
	}
	if revoked.Valid {
		eb.RevokedAt = revoked.Time
	}
	eb.Status = EntitlementStatus(status)
	if err := decodeFeatureOverrides(overrides, &eb.FeatureOverrides); err != nil {
		return nil, err
	}
	return &eb, nil
}

func scanRelease(rs rowScanner) (*ProductRelease, error) {
	var pr ProductRelease
	var summary sql.NullString
	var metadata []byte
	if err := rs.Scan(
		&pr.ID,
		&pr.ProductID,
		&pr.Channel,
		&pr.Version,
		&summary,
		&metadata,
		&pr.PublishedAt,
		&pr.CreatedAt,
		&pr.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("product release not found")
		}
		return nil, err
	}
	if summary.Valid {
		pr.Summary = summary.String
	}
	if err := decodeStringMapJSON(metadata, &pr.Metadata); err != nil {
		return nil, err
	}
	return &pr, nil
}

func scanDeviceLedger(rs rowScanner) (*DeviceLedger, error) {
	var dl DeviceLedger
	var clientID, licenseID sql.NullString
	var lastSync sql.NullTime
	var metadata []byte
	if err := rs.Scan(
		&dl.ID,
		&dl.TenantID,
		&clientID,
		&licenseID,
		&dl.DeviceFingerprint,
		&dl.LastSeenAt,
		&lastSync,
		&dl.PendingRevocation,
		&dl.RevocationEpoch,
		&metadata,
		&dl.CreatedAt,
		&dl.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("device ledger missing")
		}
		return nil, err
	}
	if clientID.Valid {
		dl.ClientID = clientID.String
	}
	if licenseID.Valid {
		dl.LicenseID = licenseID.String
	}
	if lastSync.Valid {
		dl.LastSyncAt = lastSync.Time
	}
	if err := decodeStringMapJSON(metadata, &dl.Metadata); err != nil {
		return nil, err
	}
	return &dl, nil
}

func scanServiceAccount(rs rowScanner) (*ServiceAccount, error) {
	var sa ServiceAccount
	var description sql.NullString
	var scopes []byte
	var lastUsed sql.NullTime
	if err := rs.Scan(
		&sa.ID,
		&sa.TenantID,
		&sa.Name,
		&description,
		&scopes,
		&sa.CreatedBy,
		&lastUsed,
		&sa.CreatedAt,
		&sa.UpdatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrServiceAccountMissing
		}
		return nil, err
	}
	if description.Valid {
		sa.Description = description.String
	}
	if lastUsed.Valid {
		sa.LastUsedAt = lastUsed.Time
	}
	if err := decodeStringSliceJSON(scopes, &sa.Scopes); err != nil {
		return nil, err
	}
	return &sa, nil
}

// JSON helpers

func encodeStringMapJSON(data map[string]string) (string, error) {
	if len(data) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(data)
	return string(b), err
}

func encodeStringSliceJSON(values []string) (string, error) {
	if len(values) == 0 {
		return "[]", nil
	}
	b, err := json.Marshal(values)
	return string(b), err
}

func encodeFeatureOverrides(data map[string]FeatureOverride) (string, error) {
	if len(data) == 0 {
		return "{}", nil
	}
	b, err := json.Marshal(data)
	return string(b), err
}

func decodeStringMapJSON(raw []byte, dest *map[string]string) error {
	if len(raw) == 0 {
		*dest = nil
		return nil
	}
	var tmp map[string]string
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return err
	}
	*dest = tmp
	return nil
}

func decodeStringSliceJSON(raw []byte, dest *[]string) error {
	if len(raw) == 0 {
		*dest = nil
		return nil
	}
	var tmp []string
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return err
	}
	*dest = tmp
	return nil
}

func decodeFeatureOverrides(raw []byte, dest *map[string]FeatureOverride) error {
	if len(raw) == 0 {
		*dest = nil
		return nil
	}
	var tmp map[string]FeatureOverride
	if err := json.Unmarshal(raw, &tmp); err != nil {
		return err
	}
	*dest = tmp
	return nil
}

// misc helpers

func nullString(s string) any {
	if strings.TrimSpace(s) == "" {
		return nil
	}
	return s
}

func nullBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}

func nullTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t.UTC()
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func filterTenants(list []*Tenant, opts ListTenantsOptions) []*Tenant {
	statusSet := make(map[TenantStatus]struct{}, len(opts.Statuses))
	for _, s := range opts.Statuses {
		statusSet[s] = struct{}{}
	}
	query := strings.ToLower(strings.TrimSpace(opts.Query))
	var result []*Tenant
	for _, tenant := range list {
		if len(statusSet) > 0 {
			if _, ok := statusSet[tenant.Status]; !ok {
				continue
			}
		}
		if query != "" {
			if !strings.Contains(strings.ToLower(tenant.Name+" "+tenant.Slug), query) {
				continue
			}
		}
		result = append(result, tenant)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result
}

func filterContacts(list []*Contact, opts ListContactsOptions) []*Contact {
	query := strings.ToLower(strings.TrimSpace(opts.Query))
	tagSet := make(map[string]struct{}, len(opts.Tags))
	for _, tag := range opts.Tags {
		tagSet[strings.ToLower(tag)] = struct{}{}
	}
	var result []*Contact
	for _, contact := range list {
		if opts.TenantID != "" && contact.TenantID != opts.TenantID {
			continue
		}
		if opts.ClientID != "" && contact.ClientID != opts.ClientID {
			continue
		}
		if len(tagSet) > 0 && !contactHasTags(contact, tagSet) {
			continue
		}
		if query != "" {
			needle := strings.ToLower(contact.FirstName + " " + contact.LastName + " " + contact.Email)
			if !strings.Contains(needle, query) {
				continue
			}
		}
		result = append(result, contact)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].CreatedAt.Before(result[j].CreatedAt) })
	return result
}

func filterEntitlements(list []*EntitlementBinding, opts ListEntitlementsOptions) []*EntitlementBinding {
	statusSet := make(map[EntitlementStatus]struct{}, len(opts.Statuses))
	for _, s := range opts.Statuses {
		statusSet[s] = struct{}{}
	}
	var result []*EntitlementBinding
	for _, binding := range list {
		if opts.TenantID != "" && binding.TenantID != opts.TenantID {
			continue
		}
		if opts.ContactID != "" && binding.ContactID != opts.ContactID {
			continue
		}
		if opts.ProductID != "" && binding.ProductID != opts.ProductID {
			continue
		}
		if len(statusSet) > 0 {
			if _, ok := statusSet[binding.Status]; !ok {
				continue
			}
		}
		result = append(result, binding)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].EffectiveAt.Before(result[j].EffectiveAt) })
	return result
}

func translateConstraintError(err error, conflict error) error {
	if err == nil {
		return nil
	}
	if isUniqueViolation(err) {
		if conflict != nil {
			return conflict
		}
		return fmt.Errorf("constraint: %w", err)
	}
	return err
}

func isUniqueViolation(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique")
}
