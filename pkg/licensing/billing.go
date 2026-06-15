package licensing

import (
	"context"
	"time"
)

const (
	BillingGatewayStripe = "stripe"
	BillingGatewayPayPal = "paypal"
	BillingGatewayManual = "manual"

	PaymentMethodStatusPendingApproval = "pending_approval"
	PaymentMethodStatusActive          = "active"
	PaymentMethodStatusDisabled        = "disabled"
	PaymentMethodStatusExpired         = "expired"

	InvoiceStatusDraft          = "draft"
	InvoiceStatusOpen           = "open"
	InvoiceStatusPaid           = "paid"
	InvoiceStatusVoid           = "void"
	InvoiceStatusPaymentFailed  = "payment_failed"
	InvoiceStatusPendingPayment = "pending_payment"

	PaymentAttemptStatusPending   = "pending"
	PaymentAttemptStatusSucceeded = "succeeded"
	PaymentAttemptStatusFailed    = "failed"
	PaymentAttemptStatusRetrying  = "retrying"

	ApprovalStatusPending  = "pending"
	ApprovalStatusApproved = "approved"
	ApprovalStatusRejected = "rejected"
	ApprovalStatusExpired  = "expired"

	WebhookStatusReceived  = "received"
	WebhookStatusProcessed = "processed"
	WebhookStatusFailed    = "failed"
)

// PaymentGatewayConfig stores tenant/admin configured gateway details without
// binding subscription logic to a single provider.
type PaymentGatewayConfig struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Provider          string            `json:"provider"`
	Environment       string            `json:"environment"`
	Enabled           bool              `json:"enabled"`
	IsDefault         bool              `json:"is_default"`
	SupportsRecurring bool              `json:"supports_recurring"`
	RequiresApproval  bool              `json:"requires_approval"`
	Config            map[string]string `json:"config,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// PaymentMethod represents a customer payment instrument stored at a gateway.
type PaymentMethod struct {
	ID                     string            `json:"id"`
	ClientID               string            `json:"client_id"`
	GatewayID              string            `json:"gateway_id"`
	Type                   string            `json:"type"`
	Status                 string            `json:"status"`
	DisplayName            string            `json:"display_name,omitempty"`
	GatewayCustomerID      string            `json:"gateway_customer_id,omitempty"`
	GatewayPaymentMethodID string            `json:"gateway_payment_method_id,omitempty"`
	IsDefault              bool              `json:"is_default"`
	RequiresApproval       bool              `json:"requires_approval"`
	ApprovedAt             time.Time         `json:"approved_at,omitempty"`
	ExpiresAt              time.Time         `json:"expires_at,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
}

// BillingInvoice is the local source of truth for what should be collected.
type BillingInvoice struct {
	ID                   string            `json:"id"`
	SubscriptionID       string            `json:"subscription_id"`
	ClientID             string            `json:"client_id"`
	ProductID            string            `json:"product_id"`
	PlanID               string            `json:"plan_id"`
	Status               string            `json:"status"`
	Currency             string            `json:"currency"`
	SubtotalAmount       int64             `json:"subtotal_amount"`
	DiscountAmount       int64             `json:"discount_amount"`
	TaxAmount            int64             `json:"tax_amount"`
	TotalAmount          int64             `json:"total_amount"`
	PeriodStart          time.Time         `json:"period_start"`
	PeriodEnd            time.Time         `json:"period_end"`
	DueAt                time.Time         `json:"due_at"`
	PaidAt               time.Time         `json:"paid_at,omitempty"`
	VoidedAt             time.Time         `json:"voided_at,omitempty"`
	GatewayID            string            `json:"gateway_id,omitempty"`
	GatewayInvoiceID     string            `json:"gateway_invoice_id,omitempty"`
	HostedInvoiceURL     string            `json:"hosted_invoice_url,omitempty"`
	AttemptCount         int               `json:"attempt_count"`
	NextPaymentAttemptAt time.Time         `json:"next_payment_attempt_at,omitempty"`
	Metadata             map[string]string `json:"metadata,omitempty"`
	CreatedAt            time.Time         `json:"created_at"`
	UpdatedAt            time.Time         `json:"updated_at"`
}

// PaymentAttempt captures gateway collection attempts for retry and audit flows.
type PaymentAttempt struct {
	ID                     string            `json:"id"`
	InvoiceID              string            `json:"invoice_id"`
	SubscriptionID         string            `json:"subscription_id"`
	GatewayID              string            `json:"gateway_id"`
	PaymentMethodID        string            `json:"payment_method_id,omitempty"`
	Status                 string            `json:"status"`
	Amount                 int64             `json:"amount"`
	Currency               string            `json:"currency"`
	GatewayPaymentIntentID string            `json:"gateway_payment_intent_id,omitempty"`
	ErrorCode              string            `json:"error_code,omitempty"`
	ErrorMessage           string            `json:"error_message,omitempty"`
	AttemptedAt            time.Time         `json:"attempted_at"`
	NextRetryAt            time.Time         `json:"next_retry_at,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
	CreatedAt              time.Time         `json:"created_at"`
	UpdatedAt              time.Time         `json:"updated_at"`
}

// BillingApprovalRequest tracks manual approval gates for clients or admins.
type BillingApprovalRequest struct {
	ID          string            `json:"id"`
	SubjectType string            `json:"subject_type"`
	SubjectID   string            `json:"subject_id"`
	ClientID    string            `json:"client_id,omitempty"`
	Status      string            `json:"status"`
	Reason      string            `json:"reason,omitempty"`
	RequestedBy string            `json:"requested_by,omitempty"`
	DecidedBy   string            `json:"decided_by,omitempty"`
	RequestedAt time.Time         `json:"requested_at"`
	DecidedAt   time.Time         `json:"decided_at,omitempty"`
	ExpiresAt   time.Time         `json:"expires_at,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CreatedAt   time.Time         `json:"created_at"`
	UpdatedAt   time.Time         `json:"updated_at"`
}

// BillingWebhookEvent stores gateway webhooks for idempotent replay and audit.
type BillingWebhookEvent struct {
	ID            string            `json:"id"`
	GatewayID     string            `json:"gateway_id"`
	Provider      string            `json:"provider"`
	EventID       string            `json:"event_id"`
	EventType     string            `json:"event_type"`
	Status        string            `json:"status"`
	Payload       string            `json:"payload,omitempty"`
	Signature     string            `json:"signature,omitempty"`
	ProcessedAt   time.Time         `json:"processed_at,omitempty"`
	ErrorMessage  string            `json:"error_message,omitempty"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
	ReceivedAt    time.Time         `json:"received_at"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

type CheckoutSessionRequest struct {
	Subscription *Subscription     `json:"subscription"`
	Invoice      *BillingInvoice   `json:"invoice,omitempty"`
	SuccessURL   string            `json:"success_url,omitempty"`
	CancelURL    string            `json:"cancel_url,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type CheckoutSession struct {
	ID         string            `json:"id"`
	URL        string            `json:"url,omitempty"`
	ExpiresAt  time.Time         `json:"expires_at,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
	ProviderID string            `json:"provider_id,omitempty"`
}

type PaymentMethodSetupRequest struct {
	ClientID  string            `json:"client_id"`
	ReturnURL string            `json:"return_url,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty"`
}

type PaymentMethodSetupSession struct {
	ID         string            `json:"id"`
	URL        string            `json:"url,omitempty"`
	ProviderID string            `json:"provider_id,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type PaymentCaptureResult struct {
	Status                 string            `json:"status"`
	GatewayPaymentIntentID string            `json:"gateway_payment_intent_id,omitempty"`
	HostedInvoiceURL       string            `json:"hosted_invoice_url,omitempty"`
	ErrorCode              string            `json:"error_code,omitempty"`
	ErrorMessage           string            `json:"error_message,omitempty"`
	Metadata               map[string]string `json:"metadata,omitempty"`
}

type WebhookVerificationResult struct {
	EventID       string            `json:"event_id"`
	EventType     string            `json:"event_type"`
	CorrelationID string            `json:"correlation_id,omitempty"`
	Metadata      map[string]string `json:"metadata,omitempty"`
}

type PaymentGatewayAdapter interface {
	Provider() string
	CreateCheckoutSession(ctx context.Context, gateway *PaymentGatewayConfig, req CheckoutSessionRequest) (*CheckoutSession, error)
	CreatePaymentMethodSetup(ctx context.Context, gateway *PaymentGatewayConfig, req PaymentMethodSetupRequest) (*PaymentMethodSetupSession, error)
	SyncSubscription(ctx context.Context, gateway *PaymentGatewayConfig, sub *Subscription) (*Subscription, error)
	CapturePayment(ctx context.Context, gateway *PaymentGatewayConfig, invoice *BillingInvoice, method *PaymentMethod) (*PaymentCaptureResult, error)
	CancelSubscription(ctx context.Context, gateway *PaymentGatewayConfig, sub *Subscription) error
	VerifyWebhook(ctx context.Context, gateway *PaymentGatewayConfig, payload []byte, signature string) (*WebhookVerificationResult, error)
}

func clonePaymentGatewayConfig(g *PaymentGatewayConfig) *PaymentGatewayConfig {
	if g == nil {
		return nil
	}
	clone := *g
	clone.Config = cloneStringMap(g.Config)
	clone.Metadata = cloneStringMap(g.Metadata)
	return &clone
}

func clonePaymentMethod(m *PaymentMethod) *PaymentMethod {
	if m == nil {
		return nil
	}
	clone := *m
	clone.Metadata = cloneStringMap(m.Metadata)
	return &clone
}

func cloneBillingInvoice(i *BillingInvoice) *BillingInvoice {
	if i == nil {
		return nil
	}
	clone := *i
	clone.Metadata = cloneStringMap(i.Metadata)
	return &clone
}

func clonePaymentAttempt(a *PaymentAttempt) *PaymentAttempt {
	if a == nil {
		return nil
	}
	clone := *a
	clone.Metadata = cloneStringMap(a.Metadata)
	return &clone
}

func cloneBillingApprovalRequest(a *BillingApprovalRequest) *BillingApprovalRequest {
	if a == nil {
		return nil
	}
	clone := *a
	clone.Metadata = cloneStringMap(a.Metadata)
	return &clone
}

func cloneBillingWebhookEvent(e *BillingWebhookEvent) *BillingWebhookEvent {
	if e == nil {
		return nil
	}
	clone := *e
	clone.Metadata = cloneStringMap(e.Metadata)
	return &clone
}
