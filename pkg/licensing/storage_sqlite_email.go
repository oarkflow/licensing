package licensing

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	email "github.com/oarkflow/licensing/pkg/email"
	"github.com/oarkflow/squealx"
)

func (s *SQLiteStorage) SaveEmailProvider(ctx context.Context, provider *email.EmailProvider) error {
	if provider == nil {
		return fmt.Errorf("email provider is nil")
	}
	if provider.ID == "" {
		return fmt.Errorf("email provider id is required")
	}
	slugLower := normalizeSlug(provider.Slug)
	if slugLower == "" {
		return fmt.Errorf("email provider slug is required")
	}
	now := time.Now().UTC()
	if provider.CreatedAt.IsZero() {
		provider.CreatedAt = now
	}
	provider.UpdatedAt = now

	configJSON, err := encodeJSONRequired(provider.Config)
	if err != nil {
		return err
	}
	metadataJSON, err := encodeStringMapNullable(provider.Metadata)
	if err != nil {
		return err
	}

	query := `INSERT INTO email_providers
        (id, name, slug, slug_lower, type, config, priority, max_retries, retry_base_ms, retry_max_ms, retry_jitter_pct,
         is_default, enabled, success_count, failure_count, metadata, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		provider.ID,
		provider.Name,
		provider.Slug,
		slugLower,
		provider.Type,
		configJSON,
		provider.Priority,
		provider.MaxRetries,
		provider.RetryBaseMS,
		provider.RetryMaxMS,
		provider.RetryJitterPct,
		boolToInt(provider.IsDefault),
		boolToInt(provider.Enabled),
		provider.SuccessCount,
		provider.FailureCount,
		metadataJSON,
		provider.CreatedAt,
		provider.UpdatedAt,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errEmailProviderExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateEmailProvider(ctx context.Context, provider *email.EmailProvider) error {
	if provider == nil {
		return fmt.Errorf("email provider is nil")
	}
	slugLower := normalizeSlug(provider.Slug)
	if slugLower == "" {
		return fmt.Errorf("email provider slug is required")
	}
	provider.UpdatedAt = time.Now().UTC()
	configJSON, err := encodeJSONRequired(provider.Config)
	if err != nil {
		return err
	}
	metadataJSON, err := encodeStringMapNullable(provider.Metadata)
	if err != nil {
		return err
	}

	query := `UPDATE email_providers
        SET name=?, slug=?, slug_lower=?, type=?, config=?, priority=?, max_retries=?, retry_base_ms=?, retry_max_ms=?, retry_jitter_pct=?,
            is_default=?, enabled=?, success_count=?, failure_count=?, metadata=?, updated_at=?
        WHERE id=?`
	result, err := s.db.ExecContext(ctx, query,
		provider.Name,
		provider.Slug,
		slugLower,
		provider.Type,
		configJSON,
		provider.Priority,
		provider.MaxRetries,
		provider.RetryBaseMS,
		provider.RetryMaxMS,
		provider.RetryJitterPct,
		boolToInt(provider.IsDefault),
		boolToInt(provider.Enabled),
		provider.SuccessCount,
		provider.FailureCount,
		metadataJSON,
		provider.UpdatedAt,
		provider.ID,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errEmailProviderExists
		}
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errEmailProviderMissing
	}
	return nil
}

func (s *SQLiteStorage) ListEmailProviders(ctx context.Context, includeDisabled bool) ([]*email.EmailProvider, error) {
	var (
		rows squealx.SQLRows
		err  error
	)
	base := `SELECT id, name, slug, slug_lower, type, config, priority, max_retries, retry_base_ms, retry_max_ms, retry_jitter_pct,
        is_default, enabled, success_count, failure_count, metadata, created_at, updated_at FROM email_providers`
	if includeDisabled {
		rows, err = s.db.QueryContext(ctx, base+" ORDER BY priority ASC, name ASC")
	} else {
		rows, err = s.db.QueryContext(ctx, base+" WHERE enabled = 1 ORDER BY priority ASC, name ASC")
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var providers []*email.EmailProvider
	for rows.Next() {
		provider, err := scanEmailProvider(rows)
		if err != nil {
			return nil, err
		}
		providers = append(providers, provider)
	}
	return providers, rows.Err()
}

func (s *SQLiteStorage) GetEmailProvider(ctx context.Context, providerID string) (*email.EmailProvider, error) {
	query := `SELECT id, name, slug, slug_lower, type, config, priority, max_retries, retry_base_ms, retry_max_ms, retry_jitter_pct,
        is_default, enabled, success_count, failure_count, metadata, created_at, updated_at FROM email_providers WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, providerID)
	provider, err := scanEmailProvider(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errEmailProviderMissing
		}
		return nil, err
	}
	return provider, nil
}

func (s *SQLiteStorage) DeleteEmailProvider(ctx context.Context, providerID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM email_providers WHERE id = ?`, providerID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errEmailProviderMissing
	}
	return nil
}

func (s *SQLiteStorage) SaveEmailTemplate(ctx context.Context, tpl *email.EmailTemplate) error {
	if tpl == nil {
		return fmt.Errorf("email template is nil")
	}
	if tpl.ID == "" {
		return fmt.Errorf("email template id is required")
	}
	slugLower := normalizeSlug(tpl.Slug)
	if slugLower == "" {
		return fmt.Errorf("email template slug is required")
	}
	now := time.Now().UTC()
	if tpl.CreatedAt.IsZero() {
		tpl.CreatedAt = now
	}
	tpl.UpdatedAt = now

	metadataJSON, err := encodeJSONNullable(tpl.Metadata)
	if err != nil {
		return err
	}
	defaultProvider := nullableString(tpl.DefaultProviderID)
	maxRetries := nullFromIntPtr(tpl.MaxRetriesOverride)

	query := `INSERT INTO email_templates
        (id, name, slug, slug_lower, category, subject, html_body, text_body, description, metadata, default_provider_id,
         max_retries_override, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		tpl.ID,
		tpl.Name,
		tpl.Slug,
		slugLower,
		tpl.Category,
		tpl.Subject,
		tpl.HTMLBody,
		tpl.TextBody,
		tpl.Description,
		metadataJSON,
		defaultProvider,
		maxRetries,
		tpl.CreatedAt,
		tpl.UpdatedAt,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errEmailTemplateExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateEmailTemplate(ctx context.Context, tpl *email.EmailTemplate) error {
	if tpl == nil {
		return fmt.Errorf("email template is nil")
	}
	slugLower := normalizeSlug(tpl.Slug)
	if slugLower == "" {
		return fmt.Errorf("email template slug is required")
	}
	tpl.UpdatedAt = time.Now().UTC()
	metadataJSON, err := encodeJSONNullable(tpl.Metadata)
	if err != nil {
		return err
	}
	defaultProvider := nullableString(tpl.DefaultProviderID)
	maxRetries := nullFromIntPtr(tpl.MaxRetriesOverride)

	query := `UPDATE email_templates
        SET name=?, slug=?, slug_lower=?, category=?, subject=?, html_body=?, text_body=?, description=?, metadata=?,
            default_provider_id=?, max_retries_override=?, updated_at=?
        WHERE id=?`
	result, err := s.db.ExecContext(ctx, query,
		tpl.Name,
		tpl.Slug,
		slugLower,
		tpl.Category,
		tpl.Subject,
		tpl.HTMLBody,
		tpl.TextBody,
		tpl.Description,
		metadataJSON,
		defaultProvider,
		maxRetries,
		tpl.UpdatedAt,
		tpl.ID,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errEmailTemplateExists
		}
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errEmailTemplateMissing
	}
	return nil
}

func (s *SQLiteStorage) ListEmailTemplates(ctx context.Context) ([]*email.EmailTemplate, error) {
	query := `SELECT id, name, slug, slug_lower, category, subject, html_body, text_body, description, metadata,
        default_provider_id, max_retries_override, created_at, updated_at FROM email_templates ORDER BY category ASC, name ASC`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var templates []*email.EmailTemplate
	for rows.Next() {
		tpl, err := scanEmailTemplate(rows)
		if err != nil {
			return nil, err
		}
		templates = append(templates, tpl)
	}
	return templates, rows.Err()
}

func (s *SQLiteStorage) GetEmailTemplate(ctx context.Context, templateID string) (*email.EmailTemplate, error) {
	query := `SELECT id, name, slug, slug_lower, category, subject, html_body, text_body, description, metadata,
        default_provider_id, max_retries_override, created_at, updated_at FROM email_templates WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, templateID)
	tpl, err := scanEmailTemplate(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errEmailTemplateMissing
		}
		return nil, err
	}
	return tpl, nil
}

func (s *SQLiteStorage) GetEmailTemplateBySlug(ctx context.Context, slug string) (*email.EmailTemplate, error) {
	slugLower := normalizeSlug(slug)
	if slugLower == "" {
		return nil, errEmailTemplateMissing
	}
	query := `SELECT id, name, slug, slug_lower, category, subject, html_body, text_body, description, metadata,
        default_provider_id, max_retries_override, created_at, updated_at FROM email_templates WHERE slug_lower = ?`
	row := s.db.QueryRowContext(ctx, query, slugLower)
	tpl, err := scanEmailTemplate(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errEmailTemplateMissing
		}
		return nil, err
	}
	return tpl, nil
}

func (s *SQLiteStorage) DeleteEmailTemplate(ctx context.Context, templateID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM email_templates WHERE id = ?`, templateID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errEmailTemplateMissing
	}
	return nil
}

func (s *SQLiteStorage) SaveEmailTemplateRoute(ctx context.Context, route *email.EmailTemplateRoute) error {
	if route == nil {
		return fmt.Errorf("email template route is nil")
	}
	if route.ID == "" {
		return fmt.Errorf("email template route id is required")
	}
	if strings.TrimSpace(route.TemplateID) == "" && strings.TrimSpace(route.Category) == "" {
		return fmt.Errorf("route must target a template or category")
	}
	now := time.Now().UTC()
	if route.CreatedAt.IsZero() {
		route.CreatedAt = now
	}
	route.UpdatedAt = now

	templateID := nullableString(route.TemplateID)
	category := nullableString(route.Category)
	retryOverride := nullFromIntPtr(route.RetryLimitOverride)

	query := `INSERT INTO email_template_routes
        (id, template_id, category, provider_id, priority, retry_limit_override, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		route.ID,
		templateID,
		category,
		route.ProviderID,
		route.Priority,
		retryOverride,
		boolToInt(route.Enabled),
		route.CreatedAt,
		route.UpdatedAt,
	)
	if err != nil {
		if isSQLiteUniqueErr(err) {
			return errEmailRouteExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) ListEmailTemplateRoutes(ctx context.Context, templateID, category string) ([]*email.EmailTemplateRoute, error) {
	var (
		rows squealx.SQLRows
		err  error
	)
	if strings.TrimSpace(templateID) != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, template_id, category, provider_id, priority, retry_limit_override, enabled, created_at, updated_at
             FROM email_template_routes WHERE template_id = ? ORDER BY priority ASC, created_at ASC`, templateID)
	} else if strings.TrimSpace(category) != "" {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, template_id, category, provider_id, priority, retry_limit_override, enabled, created_at, updated_at
             FROM email_template_routes WHERE template_id IS NULL AND lower(category) = ? ORDER BY priority ASC, created_at ASC`,
			strings.ToLower(strings.TrimSpace(category)))
	} else {
		rows, err = s.db.QueryContext(ctx,
			`SELECT id, template_id, category, provider_id, priority, retry_limit_override, enabled, created_at, updated_at
             FROM email_template_routes ORDER BY priority ASC, created_at ASC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var routes []*email.EmailTemplateRoute
	for rows.Next() {
		route, err := scanEmailTemplateRoute(rows)
		if err != nil {
			return nil, err
		}
		routes = append(routes, route)
	}
	return routes, rows.Err()
}

func (s *SQLiteStorage) DeleteEmailTemplateRoute(ctx context.Context, routeID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM email_template_routes WHERE id = ?`, routeID)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errEmailRouteMissing
	}
	return nil
}

func (s *SQLiteStorage) EnqueueEmail(ctx context.Context, msg *email.EmailMessage) error {
	if msg == nil {
		return fmt.Errorf("email message is nil")
	}
	if strings.TrimSpace(msg.To) == "" {
		return fmt.Errorf("recipient address is required")
	}
	now := time.Now().UTC()
	if msg.CreatedAt.IsZero() {
		msg.CreatedAt = now
	}
	msg.UpdatedAt = now
	if msg.NextAttemptAt.IsZero() {
		msg.NextAttemptAt = now
	}
	if msg.Status == "" {
		msg.Status = email.MessageStatusQueued
	}

	templateID := nullableString(msg.TemplateID)
	providerID := nullableString(msg.ProviderID)
	ccJSON, err := encodeStringSliceNullable(msg.CC)
	if err != nil {
		return err
	}
	bccJSON, err := encodeStringSliceNullable(msg.BCC)
	if err != nil {
		return err
	}
	variablesJSON, err := encodeJSONNullable(msg.Variables)
	if err != nil {
		return err
	}
	metadataJSON, err := encodeStringMapNullable(msg.Metadata)
	if err != nil {
		return err
	}

	query := `INSERT INTO email_messages
        (id, template_id, provider_id, to_address, cc, bcc, subject, rendered_html, rendered_text,
         variables, metadata, status, retry_count, failover_count, max_retries, last_error,
         next_attempt_at, last_attempt_at, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		msg.ID,
		templateID,
		providerID,
		msg.To,
		ccJSON,
		bccJSON,
		msg.Subject,
		msg.RenderedHTML,
		msg.RenderedText,
		variablesJSON,
		metadataJSON,
		msg.Status,
		msg.RetryCount,
		msg.FailoverCount,
		msg.MaxRetries,
		msg.LastError,
		msg.NextAttemptAt,
		sql.NullTime{Time: msg.LastAttemptAt, Valid: !msg.LastAttemptAt.IsZero()},
		msg.CreatedAt,
		msg.UpdatedAt,
	)
	if err != nil {
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateEmailMessage(ctx context.Context, msg *email.EmailMessage) error {
	if msg == nil {
		return fmt.Errorf("email message is nil")
	}
	msg.UpdatedAt = time.Now().UTC()

	providerID := nullableString(msg.ProviderID)
	ccJSON, err := encodeStringSliceNullable(msg.CC)
	if err != nil {
		return err
	}
	bccJSON, err := encodeStringSliceNullable(msg.BCC)
	if err != nil {
		return err
	}
	variablesJSON, err := encodeJSONNullable(msg.Variables)
	if err != nil {
		return err
	}
	metadataJSON, err := encodeStringMapNullable(msg.Metadata)
	if err != nil {
		return err
	}

	query := `UPDATE email_messages
        SET template_id = ?, provider_id = ?, to_address = ?, cc = ?, bcc = ?, subject = ?, rendered_html = ?, rendered_text = ?,
            variables = ?, metadata = ?, status = ?, retry_count = ?, failover_count = ?, max_retries = ?, last_error = ?,
            next_attempt_at = ?, last_attempt_at = ?, updated_at = ?
        WHERE id = ?`
	result, err := s.db.ExecContext(ctx, query,
		msg.TemplateID,
		providerID,
		msg.To,
		ccJSON,
		bccJSON,
		msg.Subject,
		msg.RenderedHTML,
		msg.RenderedText,
		variablesJSON,
		metadataJSON,
		msg.Status,
		msg.RetryCount,
		msg.FailoverCount,
		msg.MaxRetries,
		msg.LastError,
		msg.NextAttemptAt,
		sql.NullTime{Time: msg.LastAttemptAt, Valid: !msg.LastAttemptAt.IsZero()},
		msg.UpdatedAt,
		msg.ID,
	)
	if err != nil {
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errEmailMessageMissing
	}
	return nil
}

func (s *SQLiteStorage) GetEmailMessage(ctx context.Context, messageID string) (*email.EmailMessage, error) {
	query := `SELECT id, template_id, provider_id, to_address, cc, bcc, subject, rendered_html, rendered_text,
        variables, metadata, status, retry_count, failover_count, max_retries, last_error,
        next_attempt_at, last_attempt_at, created_at, updated_at FROM email_messages WHERE id = ?`
	row := s.db.QueryRowContext(ctx, query, messageID)
	msg, err := scanEmailMessage(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errEmailMessageMissing
		}
		return nil, err
	}
	return msg, nil
}

func (s *SQLiteStorage) LeaseNextEmail(ctx context.Context, dueBefore time.Time) (*email.EmailMessage, error) {
	var leased *email.EmailMessage
	err := s.withTx(ctx, func(tx squealx.SQLTx) error {
		query := `SELECT id FROM email_messages
            WHERE status IN (?, ?) AND (next_attempt_at IS NULL OR next_attempt_at <= ?)
            ORDER BY COALESCE(next_attempt_at, '1970-01-01'), created_at
            LIMIT 1`
		row := tx.QueryRowContext(ctx, query, email.MessageStatusQueued, email.MessageStatusRetrying, dueBefore)
		var messageID string
		if err := row.Scan(&messageID); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return nil
			}
			return err
		}
		now := time.Now().UTC()
		update := `UPDATE email_messages SET status = ?, last_attempt_at = ?, updated_at = ? WHERE id = ? AND status IN (?, ?)`
		result, err := tx.ExecContext(ctx, update,
			email.MessageStatusSending,
			now,
			now,
			messageID,
			email.MessageStatusQueued,
			email.MessageStatusRetrying,
		)
		if err != nil {
			return err
		}
		rows, _ := result.RowsAffected()
		if rows == 0 {
			return nil
		}
		msg, err := scanEmailMessage(tx.QueryRowContext(ctx, `SELECT id, template_id, provider_id, to_address, cc, bcc, subject, rendered_html, rendered_text,
            variables, metadata, status, retry_count, failover_count, max_retries, last_error, next_attempt_at, last_attempt_at, created_at, updated_at FROM email_messages WHERE id = ?`, messageID))
		if err != nil {
			return err
		}
		leased = msg
		return nil
	})
	if err != nil {
		return nil, err
	}
	return leased, nil
}

func (s *SQLiteStorage) AppendEmailEvent(ctx context.Context, event *email.EmailEvent) error {
	if event == nil {
		return fmt.Errorf("email event is nil")
	}
	if event.ID == "" {
		return fmt.Errorf("email event id is required")
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	payloadJSON, err := encodeJSONNullable(event.Payload)
	if err != nil {
		return err
	}
	query := `INSERT INTO email_events (id, message_id, provider_id, event_type, payload, created_at) VALUES (?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		event.ID,
		event.MessageID,
		event.ProviderID,
		event.EventType,
		payloadJSON,
		event.CreatedAt,
	)
	return err
}

func (s *SQLiteStorage) ListEmailEvents(ctx context.Context, messageID string) ([]*email.EmailEvent, error) {
	query := `SELECT id, message_id, provider_id, event_type, payload, created_at FROM email_events WHERE message_id = ? ORDER BY created_at ASC`
	rows, err := s.db.QueryContext(ctx, query, messageID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*email.EmailEvent
	for rows.Next() {
		event, err := scanEmailEvent(rows)
		if err != nil {
			return nil, err
		}
		events = append(events, event)
	}
	return events, rows.Err()
}

// --- scanning & encoding helpers ---

func scanEmailProvider(scanner rowScanner) (*email.EmailProvider, error) {
	var (
		record             email.EmailProvider
		configJSON         sql.NullString
		metadataJSON       sql.NullString
		isDefault, enabled int
		createdAt          sqliteTimeValue
		updatedAt          sqliteTimeValue
	)
	if err := scanner.Scan(
		&record.ID,
		&record.Name,
		&record.Slug,
		new(string),
		&record.Type,
		&configJSON,
		&record.Priority,
		&record.MaxRetries,
		&record.RetryBaseMS,
		&record.RetryMaxMS,
		&record.RetryJitterPct,
		&isDefault,
		&enabled,
		&record.SuccessCount,
		&record.FailureCount,
		&metadataJSON,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	record.IsDefault = intToBool(isDefault)
	record.Enabled = intToBool(enabled)
	record.CreatedAt = createdAt.Time
	record.UpdatedAt = updatedAt.Time
	cfg, err := decodeJSONMap(configJSON)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	record.Config = cfg
	metadata, err := decodeStringMap(metadataJSON)
	if err != nil {
		return nil, err
	}
	record.Metadata = metadata
	return &record, nil
}

func scanEmailTemplate(scanner rowScanner) (*email.EmailTemplate, error) {
	var (
		tpl               email.EmailTemplate
		metadataJSON      sql.NullString
		defaultProviderID sql.NullString
		maxRetries        sql.NullInt64
		createdAt         sqliteTimeValue
		updatedAt         sqliteTimeValue
	)
	if err := scanner.Scan(
		&tpl.ID,
		&tpl.Name,
		&tpl.Slug,
		new(string),
		&tpl.Category,
		&tpl.Subject,
		&tpl.HTMLBody,
		&tpl.TextBody,
		&tpl.Description,
		&metadataJSON,
		&defaultProviderID,
		&maxRetries,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	tpl.CreatedAt = createdAt.Time
	tpl.UpdatedAt = updatedAt.Time
	if defaultProviderID.Valid {
		tpl.DefaultProviderID = defaultProviderID.String
	}
	meta, err := decodeGenericMap(metadataJSON)
	if err != nil {
		return nil, err
	}
	tpl.Metadata = meta
	tpl.MaxRetriesOverride = intPtrFromNull(maxRetries)
	return &tpl, nil
}

func scanEmailTemplateRoute(scanner rowScanner) (*email.EmailTemplateRoute, error) {
	var (
		route         email.EmailTemplateRoute
		templateID    sql.NullString
		category      sql.NullString
		retryOverride sql.NullInt64
		enabled       int
		createdAt     sqliteTimeValue
		updatedAt     sqliteTimeValue
	)
	if err := scanner.Scan(
		&route.ID,
		&templateID,
		&category,
		&route.ProviderID,
		&route.Priority,
		&retryOverride,
		&enabled,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	if templateID.Valid {
		route.TemplateID = templateID.String
	}
	if category.Valid {
		route.Category = category.String
	}
	route.RetryLimitOverride = intPtrFromNull(retryOverride)
	route.Enabled = intToBool(enabled)
	route.CreatedAt = createdAt.Time
	route.UpdatedAt = updatedAt.Time
	return &route, nil
}

func scanEmailMessage(scanner rowScanner) (*email.EmailMessage, error) {
	var (
		msg           email.EmailMessage
		providerID    sql.NullString
		ccJSON        sql.NullString
		bccJSON       sql.NullString
		variablesJSON sql.NullString
		metadataJSON  sql.NullString
		status        string
		nextAttempt   sqliteNullTime
		lastAttempt   sqliteNullTime
		createdAt     sqliteTimeValue
		updatedAt     sqliteTimeValue
	)
	if err := scanner.Scan(
		&msg.ID,
		&msg.TemplateID,
		&providerID,
		&msg.To,
		&ccJSON,
		&bccJSON,
		&msg.Subject,
		&msg.RenderedHTML,
		&msg.RenderedText,
		&variablesJSON,
		&metadataJSON,
		&status,
		&msg.RetryCount,
		&msg.FailoverCount,
		&msg.MaxRetries,
		&msg.LastError,
		&nextAttempt,
		&lastAttempt,
		&createdAt,
		&updatedAt,
	); err != nil {
		return nil, err
	}
	if providerID.Valid {
		msg.ProviderID = providerID.String
	}
	msg.Status = email.MessageStatus(status)
	if nextAttempt.Valid {
		msg.NextAttemptAt = nextAttempt.Time
	}
	if lastAttempt.Valid {
		msg.LastAttemptAt = lastAttempt.Time
	}
	msg.CreatedAt = createdAt.Time
	msg.UpdatedAt = updatedAt.Time
	cc, err := decodeStringSlice(ccJSON)
	if err != nil {
		return nil, err
	}
	msg.CC = cc
	bcc, err := decodeStringSlice(bccJSON)
	if err != nil {
		return nil, err
	}
	msg.BCC = bcc
	vars, err := decodeJSONMap(variablesJSON)
	if err != nil {
		return nil, err
	}
	msg.Variables = vars
	metadata, err := decodeStringMap(metadataJSON)
	if err != nil {
		return nil, err
	}
	msg.Metadata = metadata
	return &msg, nil
}

func scanEmailEvent(scanner rowScanner) (*email.EmailEvent, error) {
	var (
		evt         email.EmailEvent
		payloadJSON sql.NullString
		createdAt   sqliteTimeValue
	)
	if err := scanner.Scan(&evt.ID, &evt.MessageID, &evt.ProviderID, &evt.EventType, &payloadJSON, &createdAt); err != nil {
		return nil, err
	}
	evt.CreatedAt = createdAt.Time
	payload, err := decodeJSONMap(payloadJSON)
	if err != nil {
		return nil, err
	}
	evt.Payload = payload
	return &evt, nil
}

func encodeJSONRequired(value map[string]any) (string, error) {
	if value == nil {
		return "{}", nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func encodeJSONNullable(value map[string]any) (sql.NullString, error) {
	if value == nil {
		return sql.NullString{}, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(raw), Valid: true}, nil
}

func encodeStringMapNullable(value map[string]string) (sql.NullString, error) {
	if len(value) == 0 {
		return sql.NullString{}, nil
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(raw), Valid: true}, nil
}

func encodeStringSliceNullable(values []string) (sql.NullString, error) {
	if len(values) == 0 {
		return sql.NullString{}, nil
	}
	raw, err := json.Marshal(values)
	if err != nil {
		return sql.NullString{}, err
	}
	return sql.NullString{String: string(raw), Valid: true}, nil
}

func decodeJSONMap(raw sql.NullString) (map[string]any, error) {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeGenericMap(raw sql.NullString) (map[string]any, error) {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeStringMap(raw sql.NullString) (map[string]string, error) {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	var out map[string]string
	if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func decodeStringSlice(raw sql.NullString) ([]string, error) {
	if !raw.Valid || strings.TrimSpace(raw.String) == "" {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal([]byte(raw.String), &out); err != nil {
		return nil, err
	}
	return out, nil
}

func nullableString(value string) sql.NullString {
	if strings.TrimSpace(value) == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: value, Valid: true}
}

func nullFromIntPtr(ptr *int) sql.NullInt64 {
	if ptr == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*ptr), Valid: true}
}

func intPtrFromNull(value sql.NullInt64) *int {
	if !value.Valid {
		return nil
	}
	v := int(value.Int64)
	return &v
}
