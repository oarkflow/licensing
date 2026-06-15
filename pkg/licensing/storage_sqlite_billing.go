package licensing

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

var (
	errPaymentGatewayMissing  = fmt.Errorf("payment gateway not found")
	errPaymentGatewayExists   = fmt.Errorf("payment gateway already exists")
	errPaymentMethodMissing   = fmt.Errorf("payment method not found")
	errPaymentMethodExists    = fmt.Errorf("payment method already exists")
	errBillingInvoiceMissing  = fmt.Errorf("billing invoice not found")
	errBillingInvoiceExists   = fmt.Errorf("billing invoice already exists")
	errPaymentAttemptMissing  = fmt.Errorf("payment attempt not found")
	errPaymentAttemptExists   = fmt.Errorf("payment attempt already exists")
	errBillingApprovalMissing = fmt.Errorf("billing approval request not found")
	errBillingApprovalExists  = fmt.Errorf("billing approval request already exists")
	errBillingWebhookMissing  = fmt.Errorf("billing webhook event not found")
	errBillingWebhookExists   = fmt.Errorf("billing webhook event already exists")
)

func billingMapJSON(values map[string]string) (string, error) {
	if len(values) == 0 {
		return "", nil
	}
	b, err := json.Marshal(values)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func decodeBillingMap(input sql.NullString) map[string]string {
	if !input.Valid || strings.TrimSpace(input.String) == "" {
		return nil
	}
	values := make(map[string]string)
	if err := json.Unmarshal([]byte(input.String), &values); err != nil {
		return nil
	}
	return values
}

func (s *SQLiteStorage) SavePaymentGateway(ctx context.Context, gateway *PaymentGatewayConfig) error {
	if gateway == nil {
		return fmt.Errorf("payment gateway is nil")
	}
	now := time.Now()
	if gateway.CreatedAt.IsZero() {
		gateway.CreatedAt = now
	}
	gateway.UpdatedAt = now
	configJSON, err := billingMapJSON(gateway.Config)
	if err != nil {
		return err
	}
	metadataJSON, err := billingMapJSON(gateway.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO payment_gateways
		(id, name, provider, environment, enabled, is_default, supports_recurring, requires_approval, config, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		gateway.ID, gateway.Name, gateway.Provider, gateway.Environment, boolToInt(gateway.Enabled), boolToInt(gateway.IsDefault),
		boolToInt(gateway.SupportsRecurring), boolToInt(gateway.RequiresApproval), nullString(configJSON), nullString(metadataJSON),
		gateway.CreatedAt, gateway.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errPaymentGatewayExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdatePaymentGateway(ctx context.Context, gateway *PaymentGatewayConfig) error {
	if gateway == nil {
		return fmt.Errorf("payment gateway is nil")
	}
	gateway.UpdatedAt = time.Now()
	configJSON, err := billingMapJSON(gateway.Config)
	if err != nil {
		return err
	}
	metadataJSON, err := billingMapJSON(gateway.Metadata)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE payment_gateways SET
		name=?, provider=?, environment=?, enabled=?, is_default=?, supports_recurring=?, requires_approval=?, config=?, metadata=?, updated_at=?
		WHERE id=?`,
		gateway.Name, gateway.Provider, gateway.Environment, boolToInt(gateway.Enabled), boolToInt(gateway.IsDefault),
		boolToInt(gateway.SupportsRecurring), boolToInt(gateway.RequiresApproval), nullString(configJSON), nullString(metadataJSON),
		gateway.UpdatedAt, gateway.ID)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errPaymentGatewayMissing
	}
	return nil
}

func (s *SQLiteStorage) GetPaymentGateway(ctx context.Context, gatewayID string) (*PaymentGatewayConfig, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, name, provider, environment, enabled, is_default, supports_recurring, requires_approval, config, metadata, created_at, updated_at FROM payment_gateways WHERE id=?`, gatewayID)
	return s.scanPaymentGateway(row)
}

func (s *SQLiteStorage) ListPaymentGateways(ctx context.Context) ([]*PaymentGatewayConfig, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, name, provider, environment, enabled, is_default, supports_recurring, requires_approval, config, metadata, created_at, updated_at FROM payment_gateways ORDER BY name ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var gateways []*PaymentGatewayConfig
	for rows.Next() {
		gateway, err := s.scanPaymentGateway(rows)
		if err != nil {
			return nil, err
		}
		gateways = append(gateways, gateway)
	}
	return gateways, rows.Err()
}

func (s *SQLiteStorage) scanPaymentGateway(scanner productRowScanner) (*PaymentGatewayConfig, error) {
	gateway := &PaymentGatewayConfig{}
	var enabled, isDefault, supportsRecurring, requiresApproval int
	var configJSON, metadataJSON sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&gateway.ID, &gateway.Name, &gateway.Provider, &gateway.Environment, &enabled, &isDefault,
		&supportsRecurring, &requiresApproval, &configJSON, &metadataJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errPaymentGatewayMissing
	}
	if err != nil {
		return nil, err
	}
	gateway.Enabled = intToBool(enabled)
	gateway.IsDefault = intToBool(isDefault)
	gateway.SupportsRecurring = intToBool(supportsRecurring)
	gateway.RequiresApproval = intToBool(requiresApproval)
	gateway.Config = decodeBillingMap(configJSON)
	gateway.Metadata = decodeBillingMap(metadataJSON)
	gateway.CreatedAt = createdAt.Time
	gateway.UpdatedAt = updatedAt.Time
	return gateway, nil
}

func (s *SQLiteStorage) SavePaymentMethod(ctx context.Context, method *PaymentMethod) error {
	if method == nil {
		return fmt.Errorf("payment method is nil")
	}
	now := time.Now()
	if method.CreatedAt.IsZero() {
		method.CreatedAt = now
	}
	method.UpdatedAt = now
	metadataJSON, err := billingMapJSON(method.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO payment_methods
		(id, client_id, gateway_id, type, status, display_name, gateway_customer_id, gateway_payment_method_id, is_default, requires_approval, approved_at, expires_at, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		method.ID, method.ClientID, method.GatewayID, method.Type, method.Status, nullString(method.DisplayName),
		nullString(method.GatewayCustomerID), nullString(method.GatewayPaymentMethodID), boolToInt(method.IsDefault), boolToInt(method.RequiresApproval),
		nullTime(method.ApprovedAt), nullTime(method.ExpiresAt), nullString(metadataJSON), method.CreatedAt, method.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errPaymentMethodExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) GetPaymentMethod(ctx context.Context, methodID string) (*PaymentMethod, error) {
	row := s.db.QueryRowContext(ctx, paymentMethodSelectSQL()+` WHERE id=?`, methodID)
	return s.scanPaymentMethod(row)
}

func (s *SQLiteStorage) UpdatePaymentMethod(ctx context.Context, method *PaymentMethod) error {
	if method == nil {
		return fmt.Errorf("payment method is nil")
	}
	method.UpdatedAt = time.Now()
	metadataJSON, err := billingMapJSON(method.Metadata)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE payment_methods SET
		client_id=?, gateway_id=?, type=?, status=?, display_name=?, gateway_customer_id=?, gateway_payment_method_id=?, is_default=?, requires_approval=?, approved_at=?, expires_at=?, metadata=?, updated_at=?
		WHERE id=?`,
		method.ClientID, method.GatewayID, method.Type, method.Status, nullString(method.DisplayName),
		nullString(method.GatewayCustomerID), nullString(method.GatewayPaymentMethodID), boolToInt(method.IsDefault), boolToInt(method.RequiresApproval),
		nullTime(method.ApprovedAt), nullTime(method.ExpiresAt), nullString(metadataJSON), method.UpdatedAt, method.ID)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errPaymentMethodMissing
	}
	return nil
}

func (s *SQLiteStorage) ListPaymentMethodsByClient(ctx context.Context, clientID string) ([]*PaymentMethod, error) {
	rows, err := s.db.QueryContext(ctx, paymentMethodSelectSQL()+` WHERE client_id=? ORDER BY created_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var methods []*PaymentMethod
	for rows.Next() {
		method, err := s.scanPaymentMethod(rows)
		if err != nil {
			return nil, err
		}
		methods = append(methods, method)
	}
	return methods, rows.Err()
}

func paymentMethodSelectSQL() string {
	return `SELECT id, client_id, gateway_id, type, status, display_name, gateway_customer_id, gateway_payment_method_id, is_default, requires_approval, approved_at, expires_at, metadata, created_at, updated_at FROM payment_methods`
}

func (s *SQLiteStorage) scanPaymentMethod(scanner productRowScanner) (*PaymentMethod, error) {
	method := &PaymentMethod{}
	var displayName, customerID, paymentMethodID, metadataJSON sql.NullString
	var isDefault, requiresApproval int
	var approvedAt, expiresAt, createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&method.ID, &method.ClientID, &method.GatewayID, &method.Type, &method.Status, &displayName,
		&customerID, &paymentMethodID, &isDefault, &requiresApproval, &approvedAt, &expiresAt, &metadataJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errPaymentMethodMissing
	}
	if err != nil {
		return nil, err
	}
	method.DisplayName = displayName.String
	method.GatewayCustomerID = customerID.String
	method.GatewayPaymentMethodID = paymentMethodID.String
	method.IsDefault = intToBool(isDefault)
	method.RequiresApproval = intToBool(requiresApproval)
	method.ApprovedAt = approvedAt.Time
	method.ExpiresAt = expiresAt.Time
	method.Metadata = decodeBillingMap(metadataJSON)
	method.CreatedAt = createdAt.Time
	method.UpdatedAt = updatedAt.Time
	return method, nil
}

func (s *SQLiteStorage) SaveBillingInvoice(ctx context.Context, invoice *BillingInvoice) error {
	if invoice == nil {
		return fmt.Errorf("billing invoice is nil")
	}
	now := time.Now()
	if invoice.CreatedAt.IsZero() {
		invoice.CreatedAt = now
	}
	invoice.UpdatedAt = now
	metadataJSON, err := billingMapJSON(invoice.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO billing_invoices
		(id, subscription_id, client_id, product_id, plan_id, status, currency, subtotal_amount, discount_amount, tax_amount, total_amount, period_start, period_end, due_at, paid_at, voided_at, gateway_id, gateway_invoice_id, hosted_invoice_url, attempt_count, next_payment_attempt_at, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		invoice.ID, invoice.SubscriptionID, invoice.ClientID, invoice.ProductID, invoice.PlanID, invoice.Status, invoice.Currency,
		invoice.SubtotalAmount, invoice.DiscountAmount, invoice.TaxAmount, invoice.TotalAmount, invoice.PeriodStart, invoice.PeriodEnd, invoice.DueAt,
		nullTime(invoice.PaidAt), nullTime(invoice.VoidedAt), nullString(invoice.GatewayID), nullString(invoice.GatewayInvoiceID),
		nullString(invoice.HostedInvoiceURL), invoice.AttemptCount, nullTime(invoice.NextPaymentAttemptAt), nullString(metadataJSON), invoice.CreatedAt, invoice.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errBillingInvoiceExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) GetBillingInvoice(ctx context.Context, invoiceID string) (*BillingInvoice, error) {
	row := s.db.QueryRowContext(ctx, billingInvoiceSelectSQL()+` WHERE id=?`, invoiceID)
	return s.scanBillingInvoice(row)
}

func (s *SQLiteStorage) UpdateBillingInvoice(ctx context.Context, invoice *BillingInvoice) error {
	if invoice == nil {
		return fmt.Errorf("billing invoice is nil")
	}
	invoice.UpdatedAt = time.Now()
	metadataJSON, err := billingMapJSON(invoice.Metadata)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE billing_invoices SET
		subscription_id=?, client_id=?, product_id=?, plan_id=?, status=?, currency=?, subtotal_amount=?, discount_amount=?, tax_amount=?, total_amount=?, period_start=?, period_end=?, due_at=?, paid_at=?, voided_at=?, gateway_id=?, gateway_invoice_id=?, hosted_invoice_url=?, attempt_count=?, next_payment_attempt_at=?, metadata=?, updated_at=?
		WHERE id=?`,
		invoice.SubscriptionID, invoice.ClientID, invoice.ProductID, invoice.PlanID, invoice.Status, invoice.Currency,
		invoice.SubtotalAmount, invoice.DiscountAmount, invoice.TaxAmount, invoice.TotalAmount, invoice.PeriodStart, invoice.PeriodEnd, invoice.DueAt,
		nullTime(invoice.PaidAt), nullTime(invoice.VoidedAt), nullString(invoice.GatewayID), nullString(invoice.GatewayInvoiceID),
		nullString(invoice.HostedInvoiceURL), invoice.AttemptCount, nullTime(invoice.NextPaymentAttemptAt), nullString(metadataJSON), invoice.UpdatedAt, invoice.ID)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errBillingInvoiceMissing
	}
	return nil
}

func (s *SQLiteStorage) ListBillingInvoicesBySubscription(ctx context.Context, subscriptionID string) ([]*BillingInvoice, error) {
	rows, err := s.db.QueryContext(ctx, billingInvoiceSelectSQL()+` WHERE subscription_id=? ORDER BY due_at DESC`, subscriptionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var invoices []*BillingInvoice
	for rows.Next() {
		invoice, err := s.scanBillingInvoice(rows)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, invoice)
	}
	return invoices, rows.Err()
}

func (s *SQLiteStorage) ListBillingInvoicesByClient(ctx context.Context, clientID string) ([]*BillingInvoice, error) {
	rows, err := s.db.QueryContext(ctx, billingInvoiceSelectSQL()+` WHERE client_id=? ORDER BY due_at DESC`, clientID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var invoices []*BillingInvoice
	for rows.Next() {
		invoice, err := s.scanBillingInvoice(rows)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, invoice)
	}
	return invoices, rows.Err()
}

func (s *SQLiteStorage) ListDueBillingInvoices(ctx context.Context, dueBefore time.Time) ([]*BillingInvoice, error) {
	rows, err := s.db.QueryContext(ctx, billingInvoiceSelectSQL()+` WHERE status IN (?, ?, ?) AND due_at<=? ORDER BY due_at ASC`,
		InvoiceStatusOpen, InvoiceStatusPaymentFailed, InvoiceStatusPendingPayment, dueBefore)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var invoices []*BillingInvoice
	for rows.Next() {
		invoice, err := s.scanBillingInvoice(rows)
		if err != nil {
			return nil, err
		}
		invoices = append(invoices, invoice)
	}
	return invoices, rows.Err()
}

func billingInvoiceSelectSQL() string {
	return `SELECT id, subscription_id, client_id, product_id, plan_id, status, currency, subtotal_amount, discount_amount, tax_amount, total_amount, period_start, period_end, due_at, paid_at, voided_at, gateway_id, gateway_invoice_id, hosted_invoice_url, attempt_count, next_payment_attempt_at, metadata, created_at, updated_at FROM billing_invoices`
}

func (s *SQLiteStorage) scanBillingInvoice(scanner productRowScanner) (*BillingInvoice, error) {
	invoice := &BillingInvoice{}
	var gatewayID, gatewayInvoiceID, hostedURL, metadataJSON sql.NullString
	var periodStart, periodEnd, dueAt, paidAt, voidedAt, nextAttemptAt, createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&invoice.ID, &invoice.SubscriptionID, &invoice.ClientID, &invoice.ProductID, &invoice.PlanID, &invoice.Status,
		&invoice.Currency, &invoice.SubtotalAmount, &invoice.DiscountAmount, &invoice.TaxAmount, &invoice.TotalAmount, &periodStart,
		&periodEnd, &dueAt, &paidAt, &voidedAt, &gatewayID, &gatewayInvoiceID, &hostedURL, &invoice.AttemptCount, &nextAttemptAt,
		&metadataJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errBillingInvoiceMissing
	}
	if err != nil {
		return nil, err
	}
	invoice.PeriodStart = periodStart.Time
	invoice.PeriodEnd = periodEnd.Time
	invoice.DueAt = dueAt.Time
	invoice.PaidAt = paidAt.Time
	invoice.VoidedAt = voidedAt.Time
	invoice.GatewayID = gatewayID.String
	invoice.GatewayInvoiceID = gatewayInvoiceID.String
	invoice.HostedInvoiceURL = hostedURL.String
	invoice.NextPaymentAttemptAt = nextAttemptAt.Time
	invoice.Metadata = decodeBillingMap(metadataJSON)
	invoice.CreatedAt = createdAt.Time
	invoice.UpdatedAt = updatedAt.Time
	return invoice, nil
}

func (s *SQLiteStorage) SavePaymentAttempt(ctx context.Context, attempt *PaymentAttempt) error {
	if attempt == nil {
		return fmt.Errorf("payment attempt is nil")
	}
	now := time.Now()
	if attempt.CreatedAt.IsZero() {
		attempt.CreatedAt = now
	}
	if attempt.AttemptedAt.IsZero() {
		attempt.AttemptedAt = now
	}
	attempt.UpdatedAt = now
	metadataJSON, err := billingMapJSON(attempt.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO payment_attempts
		(id, invoice_id, subscription_id, gateway_id, payment_method_id, status, amount, currency, gateway_payment_intent_id, error_code, error_message, attempted_at, next_retry_at, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		attempt.ID, attempt.InvoiceID, attempt.SubscriptionID, attempt.GatewayID, nullString(attempt.PaymentMethodID), attempt.Status,
		attempt.Amount, attempt.Currency, nullString(attempt.GatewayPaymentIntentID), nullString(attempt.ErrorCode), nullString(attempt.ErrorMessage),
		attempt.AttemptedAt, nullTime(attempt.NextRetryAt), nullString(metadataJSON), attempt.CreatedAt, attempt.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errPaymentAttemptExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) ListPaymentAttemptsByInvoice(ctx context.Context, invoiceID string) ([]*PaymentAttempt, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, invoice_id, subscription_id, gateway_id, payment_method_id, status, amount, currency, gateway_payment_intent_id, error_code, error_message, attempted_at, next_retry_at, metadata, created_at, updated_at FROM payment_attempts WHERE invoice_id=? ORDER BY attempted_at DESC`, invoiceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var attempts []*PaymentAttempt
	for rows.Next() {
		attempt, err := s.scanPaymentAttempt(rows)
		if err != nil {
			return nil, err
		}
		attempts = append(attempts, attempt)
	}
	return attempts, rows.Err()
}

func (s *SQLiteStorage) scanPaymentAttempt(scanner productRowScanner) (*PaymentAttempt, error) {
	attempt := &PaymentAttempt{}
	var paymentMethodID, intentID, errorCode, errorMessage, metadataJSON sql.NullString
	var attemptedAt, nextRetryAt, createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&attempt.ID, &attempt.InvoiceID, &attempt.SubscriptionID, &attempt.GatewayID, &paymentMethodID,
		&attempt.Status, &attempt.Amount, &attempt.Currency, &intentID, &errorCode, &errorMessage, &attemptedAt, &nextRetryAt,
		&metadataJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errPaymentAttemptMissing
	}
	if err != nil {
		return nil, err
	}
	attempt.PaymentMethodID = paymentMethodID.String
	attempt.GatewayPaymentIntentID = intentID.String
	attempt.ErrorCode = errorCode.String
	attempt.ErrorMessage = errorMessage.String
	attempt.AttemptedAt = attemptedAt.Time
	attempt.NextRetryAt = nextRetryAt.Time
	attempt.Metadata = decodeBillingMap(metadataJSON)
	attempt.CreatedAt = createdAt.Time
	attempt.UpdatedAt = updatedAt.Time
	return attempt, nil
}

func (s *SQLiteStorage) SaveBillingApprovalRequest(ctx context.Context, approval *BillingApprovalRequest) error {
	if approval == nil {
		return fmt.Errorf("billing approval request is nil")
	}
	now := time.Now()
	if approval.CreatedAt.IsZero() {
		approval.CreatedAt = now
	}
	if approval.RequestedAt.IsZero() {
		approval.RequestedAt = now
	}
	approval.UpdatedAt = now
	metadataJSON, err := billingMapJSON(approval.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO billing_approval_requests
		(id, subject_type, subject_id, client_id, status, reason, requested_by, decided_by, requested_at, decided_at, expires_at, metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		approval.ID, approval.SubjectType, approval.SubjectID, nullString(approval.ClientID), approval.Status, nullString(approval.Reason),
		nullString(approval.RequestedBy), nullString(approval.DecidedBy), approval.RequestedAt, nullTime(approval.DecidedAt), nullTime(approval.ExpiresAt),
		nullString(metadataJSON), approval.CreatedAt, approval.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errBillingApprovalExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) GetBillingApprovalRequest(ctx context.Context, approvalID string) (*BillingApprovalRequest, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, subject_type, subject_id, client_id, status, reason, requested_by, decided_by, requested_at, decided_at, expires_at, metadata, created_at, updated_at FROM billing_approval_requests WHERE id=?`, approvalID)
	return s.scanBillingApprovalRequest(row)
}

func (s *SQLiteStorage) UpdateBillingApprovalRequest(ctx context.Context, approval *BillingApprovalRequest) error {
	if approval == nil {
		return fmt.Errorf("billing approval request is nil")
	}
	approval.UpdatedAt = time.Now()
	metadataJSON, err := billingMapJSON(approval.Metadata)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE billing_approval_requests SET
		subject_type=?, subject_id=?, client_id=?, status=?, reason=?, requested_by=?, decided_by=?, requested_at=?, decided_at=?, expires_at=?, metadata=?, updated_at=?
		WHERE id=?`,
		approval.SubjectType, approval.SubjectID, nullString(approval.ClientID), approval.Status, nullString(approval.Reason),
		nullString(approval.RequestedBy), nullString(approval.DecidedBy), approval.RequestedAt, nullTime(approval.DecidedAt), nullTime(approval.ExpiresAt),
		nullString(metadataJSON), approval.UpdatedAt, approval.ID)
	if err != nil {
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errBillingApprovalMissing
	}
	return nil
}

func (s *SQLiteStorage) ListBillingApprovalRequests(ctx context.Context, status string) ([]*BillingApprovalRequest, error) {
	query := `SELECT id, subject_type, subject_id, client_id, status, reason, requested_by, decided_by, requested_at, decided_at, expires_at, metadata, created_at, updated_at FROM billing_approval_requests`
	var args []any
	if strings.TrimSpace(status) != "" {
		query += ` WHERE status=?`
		args = append(args, status)
	}
	query += ` ORDER BY requested_at ASC`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var approvals []*BillingApprovalRequest
	for rows.Next() {
		approval, err := s.scanBillingApprovalRequest(rows)
		if err != nil {
			return nil, err
		}
		approvals = append(approvals, approval)
	}
	return approvals, rows.Err()
}

func (s *SQLiteStorage) SaveBillingWebhookEvent(ctx context.Context, event *BillingWebhookEvent) error {
	if event == nil {
		return fmt.Errorf("billing webhook event is nil")
	}
	now := time.Now()
	if event.CreatedAt.IsZero() {
		event.CreatedAt = now
	}
	if event.ReceivedAt.IsZero() {
		event.ReceivedAt = now
	}
	event.UpdatedAt = now
	metadataJSON, err := billingMapJSON(event.Metadata)
	if err != nil {
		return err
	}
	_, err = s.db.ExecContext(ctx, `INSERT INTO billing_webhook_events
		(id, gateway_id, provider, event_id, event_type, status, payload, signature, processed_at, error_message, correlation_id, metadata, received_at, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		event.ID, event.GatewayID, event.Provider, event.EventID, event.EventType, event.Status, nullString(event.Payload), nullString(event.Signature),
		nullTime(event.ProcessedAt), nullString(event.ErrorMessage), nullString(event.CorrelationID), nullString(metadataJSON), event.ReceivedAt, event.CreatedAt, event.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errBillingWebhookExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateBillingWebhookEvent(ctx context.Context, event *BillingWebhookEvent) error {
	if event == nil {
		return fmt.Errorf("billing webhook event is nil")
	}
	event.UpdatedAt = time.Now()
	metadataJSON, err := billingMapJSON(event.Metadata)
	if err != nil {
		return err
	}
	result, err := s.db.ExecContext(ctx, `UPDATE billing_webhook_events SET
		gateway_id=?, provider=?, event_id=?, event_type=?, status=?, payload=?, signature=?, processed_at=?, error_message=?, correlation_id=?, metadata=?, received_at=?, updated_at=?
		WHERE id=?`,
		event.GatewayID, event.Provider, event.EventID, event.EventType, event.Status, nullString(event.Payload), nullString(event.Signature),
		nullTime(event.ProcessedAt), nullString(event.ErrorMessage), nullString(event.CorrelationID), nullString(metadataJSON), event.ReceivedAt, event.UpdatedAt, event.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errBillingWebhookExists
		}
		return err
	}
	if rows, _ := result.RowsAffected(); rows == 0 {
		return errBillingWebhookMissing
	}
	return nil
}

func (s *SQLiteStorage) GetBillingWebhookEventByProviderEvent(ctx context.Context, gatewayID, eventID string) (*BillingWebhookEvent, error) {
	row := s.db.QueryRowContext(ctx, billingWebhookSelectSQL()+` WHERE gateway_id=? AND event_id=?`, gatewayID, eventID)
	return s.scanBillingWebhookEvent(row)
}

func billingWebhookSelectSQL() string {
	return `SELECT id, gateway_id, provider, event_id, event_type, status, payload, signature, processed_at, error_message, correlation_id, metadata, received_at, created_at, updated_at FROM billing_webhook_events`
}

func (s *SQLiteStorage) scanBillingWebhookEvent(scanner productRowScanner) (*BillingWebhookEvent, error) {
	event := &BillingWebhookEvent{}
	var payload, signature, errorMessage, correlationID, metadataJSON sql.NullString
	var processedAt, receivedAt, createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&event.ID, &event.GatewayID, &event.Provider, &event.EventID, &event.EventType, &event.Status, &payload,
		&signature, &processedAt, &errorMessage, &correlationID, &metadataJSON, &receivedAt, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errBillingWebhookMissing
	}
	if err != nil {
		return nil, err
	}
	event.Payload = payload.String
	event.Signature = signature.String
	event.ProcessedAt = processedAt.Time
	event.ErrorMessage = errorMessage.String
	event.CorrelationID = correlationID.String
	event.Metadata = decodeBillingMap(metadataJSON)
	event.ReceivedAt = receivedAt.Time
	event.CreatedAt = createdAt.Time
	event.UpdatedAt = updatedAt.Time
	return event, nil
}

func (s *SQLiteStorage) scanBillingApprovalRequest(scanner productRowScanner) (*BillingApprovalRequest, error) {
	approval := &BillingApprovalRequest{}
	var clientID, reason, requestedBy, decidedBy, metadataJSON sql.NullString
	var requestedAt, decidedAt, expiresAt, createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&approval.ID, &approval.SubjectType, &approval.SubjectID, &clientID, &approval.Status, &reason,
		&requestedBy, &decidedBy, &requestedAt, &decidedAt, &expiresAt, &metadataJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errBillingApprovalMissing
	}
	if err != nil {
		return nil, err
	}
	approval.ClientID = clientID.String
	approval.Reason = reason.String
	approval.RequestedBy = requestedBy.String
	approval.DecidedBy = decidedBy.String
	approval.RequestedAt = requestedAt.Time
	approval.DecidedAt = decidedAt.Time
	approval.ExpiresAt = expiresAt.Time
	approval.Metadata = decodeBillingMap(metadataJSON)
	approval.CreatedAt = createdAt.Time
	approval.UpdatedAt = updatedAt.Time
	return approval, nil
}
