package licensing

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type ManualGatewayAdapter struct{}

func (ManualGatewayAdapter) Provider() string { return BillingGatewayManual }

func (ManualGatewayAdapter) CreateCheckoutSession(_ context.Context, gateway *PaymentGatewayConfig, req CheckoutSessionRequest) (*CheckoutSession, error) {
	if req.Invoice == nil {
		return nil, fmt.Errorf("invoice is required")
	}
	url := ""
	if gateway != nil && gateway.Config != nil {
		url = gateway.Config["payment_instructions_url"]
	}
	return &CheckoutSession{
		ID:        "manual_" + req.Invoice.ID,
		URL:       url,
		ExpiresAt: req.Invoice.DueAt,
		Metadata:  map[string]string{"collection_method": CollectionMethodManual},
	}, nil
}

func (ManualGatewayAdapter) CreatePaymentMethodSetup(_ context.Context, _ *PaymentGatewayConfig, req PaymentMethodSetupRequest) (*PaymentMethodSetupSession, error) {
	return &PaymentMethodSetupSession{
		ID:       "manual_setup_" + req.ClientID,
		Metadata: map[string]string{"requires_approval": "true"},
	}, nil
}

func (ManualGatewayAdapter) SyncSubscription(_ context.Context, _ *PaymentGatewayConfig, sub *Subscription) (*Subscription, error) {
	clone := cloneSubscription(sub)
	if clone == nil {
		return nil, fmt.Errorf("subscription is nil")
	}
	clone.CollectionMethod = CollectionMethodManual
	return clone, nil
}

func (ManualGatewayAdapter) CapturePayment(_ context.Context, _ *PaymentGatewayConfig, invoice *BillingInvoice, _ *PaymentMethod) (*PaymentCaptureResult, error) {
	if invoice == nil {
		return nil, fmt.Errorf("invoice is nil")
	}
	status := strings.ToLower(strings.TrimSpace(invoice.Metadata["manual_status"]))
	switch status {
	case "paid", "approved":
		return &PaymentCaptureResult{
			Status:                 PaymentAttemptStatusSucceeded,
			GatewayPaymentIntentID: "manual_" + invoice.ID,
			Metadata:               map[string]string{"manual_status": status},
		}, nil
	case "rejected", "failed":
		return &PaymentCaptureResult{
			Status:       PaymentAttemptStatusFailed,
			ErrorCode:    "manual_payment_rejected",
			ErrorMessage: "manual payment was rejected",
			Metadata:     map[string]string{"manual_status": status},
		}, nil
	default:
		return &PaymentCaptureResult{
			Status:       PaymentAttemptStatusPending,
			ErrorCode:    "manual_payment_pending",
			ErrorMessage: "manual payment is pending approval or settlement",
			Metadata:     map[string]string{"manual_status": "pending"},
		}, nil
	}
}

func (ManualGatewayAdapter) CancelSubscription(_ context.Context, _ *PaymentGatewayConfig, _ *Subscription) error {
	return nil
}

func (ManualGatewayAdapter) VerifyWebhook(_ context.Context, _ *PaymentGatewayConfig, payload []byte, _ string) (*WebhookVerificationResult, error) {
	var evt struct {
		ID            string            `json:"id"`
		Type          string            `json:"type"`
		CorrelationID string            `json:"correlation_id"`
		Metadata      map[string]string `json:"metadata"`
	}
	if err := json.Unmarshal(payload, &evt); err != nil {
		return nil, err
	}
	if evt.ID == "" {
		evt.ID = fmt.Sprintf("manual_%x", sha256.Sum256(payload))[:24]
	}
	return &WebhookVerificationResult{EventID: evt.ID, EventType: evt.Type, CorrelationID: evt.CorrelationID, Metadata: evt.Metadata}, nil
}

type StripeGatewayAdapter struct{}

func (StripeGatewayAdapter) Provider() string { return BillingGatewayStripe }

func (StripeGatewayAdapter) CreateCheckoutSession(_ context.Context, gateway *PaymentGatewayConfig, req CheckoutSessionRequest) (*CheckoutSession, error) {
	if req.Invoice == nil {
		return nil, fmt.Errorf("invoice is required")
	}
	if err := requireStripeConfig(gateway); err != nil {
		return nil, err
	}
	return &CheckoutSession{
		ID:         "stripe_checkout_" + req.Invoice.ID,
		URL:        gateway.Config["checkout_url"],
		ExpiresAt:  time.Now().Add(24 * time.Hour),
		ProviderID: gateway.Config["account_id"],
		Metadata:   map[string]string{"gateway": BillingGatewayStripe},
	}, nil
}

func (StripeGatewayAdapter) CreatePaymentMethodSetup(_ context.Context, gateway *PaymentGatewayConfig, req PaymentMethodSetupRequest) (*PaymentMethodSetupSession, error) {
	if err := requireStripeConfig(gateway); err != nil {
		return nil, err
	}
	return &PaymentMethodSetupSession{
		ID:         "stripe_setup_" + req.ClientID,
		URL:        gateway.Config["setup_url"],
		ProviderID: gateway.Config["account_id"],
		Metadata:   map[string]string{"gateway": BillingGatewayStripe},
	}, nil
}

func (StripeGatewayAdapter) SyncSubscription(_ context.Context, gateway *PaymentGatewayConfig, sub *Subscription) (*Subscription, error) {
	if err := requireStripeConfig(gateway); err != nil {
		return nil, err
	}
	clone := cloneSubscription(sub)
	if clone == nil {
		return nil, fmt.Errorf("subscription is nil")
	}
	if clone.GatewaySubscriptionID == "" {
		clone.GatewaySubscriptionID = "stripe_sub_" + clone.ID
	}
	return clone, nil
}

func (StripeGatewayAdapter) CapturePayment(_ context.Context, gateway *PaymentGatewayConfig, invoice *BillingInvoice, _ *PaymentMethod) (*PaymentCaptureResult, error) {
	if err := requireStripeConfig(gateway); err != nil {
		return nil, err
	}
	if invoice == nil {
		return nil, fmt.Errorf("invoice is nil")
	}
	if strings.EqualFold(gateway.Config["mock_capture"], "succeeded") {
		return &PaymentCaptureResult{
			Status:                 PaymentAttemptStatusSucceeded,
			GatewayPaymentIntentID: "pi_" + invoice.ID,
			HostedInvoiceURL:       gateway.Config["invoice_url"],
			Metadata:               map[string]string{"stripe_mode": "mock"},
		}, nil
	}
	return &PaymentCaptureResult{
		Status:       PaymentAttemptStatusPending,
		ErrorCode:    "stripe_capture_external",
		ErrorMessage: "stripe capture requires external Stripe API integration or webhook confirmation",
		Metadata:     map[string]string{"stripe_mode": "external"},
	}, nil
}

func (StripeGatewayAdapter) CancelSubscription(_ context.Context, gateway *PaymentGatewayConfig, _ *Subscription) error {
	return requireStripeConfig(gateway)
}

func (StripeGatewayAdapter) VerifyWebhook(_ context.Context, gateway *PaymentGatewayConfig, payload []byte, signature string) (*WebhookVerificationResult, error) {
	if gateway == nil {
		return nil, fmt.Errorf("payment gateway is nil")
	}
	secret := gateway.Config["webhook_secret"]
	if secret != "" {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(payload)
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(signature)) {
			return nil, fmt.Errorf("invalid stripe webhook signature")
		}
	}
	var evt struct {
		ID   string `json:"id"`
		Type string `json:"type"`
		Data struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &evt); err != nil {
		return nil, err
	}
	metadata := map[string]string{}
	if evt.Data.Object != nil {
		if rawMetadata, ok := evt.Data.Object["metadata"].(map[string]any); ok {
			if invoiceID, ok := rawMetadata["invoice_id"].(string); ok {
				metadata["invoice_id"] = invoiceID
			}
		}
	}
	return &WebhookVerificationResult{EventID: evt.ID, EventType: evt.Type, Metadata: metadata}, nil
}

func requireStripeConfig(gateway *PaymentGatewayConfig) error {
	if gateway == nil {
		return fmt.Errorf("payment gateway is nil")
	}
	if gateway.Provider != BillingGatewayStripe {
		return fmt.Errorf("gateway is not stripe")
	}
	if gateway.Config == nil || gateway.Config["account_id"] == "" {
		return fmt.Errorf("stripe gateway requires account_id config")
	}
	return nil
}

func DefaultBillingAdapters() map[string]PaymentGatewayAdapter {
	return map[string]PaymentGatewayAdapter{
		BillingGatewayManual: ManualGatewayAdapter{},
		BillingGatewayStripe: StripeGatewayAdapter{},
	}
}
