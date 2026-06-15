package licensing

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	email "github.com/oarkflow/licensing/pkg/email"
)

type BillingManager struct {
	storage  Storage
	adapters map[string]PaymentGatewayAdapter
	now      func() time.Time
}

type BillingRunResult struct {
	InvoicesCreated int      `json:"invoices_created"`
	InvoicesPaid    int      `json:"invoices_paid"`
	InvoicesPending int      `json:"invoices_pending"`
	InvoicesFailed  int      `json:"invoices_failed"`
	RemindersQueued int      `json:"reminders_queued"`
	Subscriptions   []string `json:"subscriptions,omitempty"`
	Errors          []string `json:"errors,omitempty"`
}

func NewBillingManager(storage Storage, adapters map[string]PaymentGatewayAdapter) *BillingManager {
	if adapters == nil {
		adapters = DefaultBillingAdapters()
	}
	return &BillingManager{storage: storage, adapters: adapters, now: time.Now}
}

func (bm *BillingManager) GenerateRenewalInvoices(ctx context.Context, dueBefore time.Time) (*BillingRunResult, error) {
	result := &BillingRunResult{}
	subs, err := bm.storage.ListSubscriptions(ctx)
	if err != nil {
		return nil, err
	}
	for _, sub := range subs {
		if !bm.subscriptionNeedsInvoice(sub, dueBefore) {
			continue
		}
		existing, err := bm.storage.ListBillingInvoicesBySubscription(ctx, sub.ID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sub.ID, err))
			continue
		}
		if hasOpenInvoiceForPeriod(existing, sub.NextBillingDate) {
			continue
		}
		invoice, err := bm.NewInvoiceFromSubscription(ctx, sub)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sub.ID, err))
			continue
		}
		if err := bm.storage.SaveBillingInvoice(ctx, invoice); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sub.ID, err))
			continue
		}
		result.InvoicesCreated++
		result.Subscriptions = append(result.Subscriptions, sub.ID)
	}
	return result, nil
}

func (bm *BillingManager) ProcessDueInvoices(ctx context.Context, dueBefore time.Time) (*BillingRunResult, error) {
	result := &BillingRunResult{}
	invoices, err := bm.storage.ListDueBillingInvoices(ctx, dueBefore)
	if err != nil {
		return nil, err
	}
	for _, invoice := range invoices {
		if invoice.Status == InvoiceStatusPaid || invoice.Status == InvoiceStatusVoid {
			continue
		}
		attempt, err := bm.captureInvoice(ctx, invoice)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", invoice.ID, err))
			continue
		}
		if err := bm.storage.SavePaymentAttempt(ctx, attempt); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", invoice.ID, err))
			continue
		}
		switch attempt.Status {
		case PaymentAttemptStatusSucceeded:
			if err := bm.MarkInvoicePaid(ctx, invoice.ID, attempt.GatewayPaymentIntentID); err != nil {
				result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", invoice.ID, err))
				continue
			}
			result.InvoicesPaid++
		case PaymentAttemptStatusPending:
			invoice.Status = InvoiceStatusPendingPayment
			invoice.AttemptCount++
			if attempt.NextRetryAt.IsZero() {
				invoice.NextPaymentAttemptAt = bm.now().Add(24 * time.Hour)
			} else {
				invoice.NextPaymentAttemptAt = attempt.NextRetryAt
			}
			_ = bm.storage.UpdateBillingInvoice(ctx, invoice)
			result.InvoicesPending++
		default:
			invoice.Status = InvoiceStatusPaymentFailed
			invoice.AttemptCount++
			invoice.NextPaymentAttemptAt = bm.nextRetryAt(invoice.AttemptCount)
			_ = bm.storage.UpdateBillingInvoice(ctx, invoice)
			_ = bm.markSubscriptionPastDue(ctx, invoice.SubscriptionID)
			result.InvoicesFailed++
		}
	}
	return result, nil
}

func (bm *BillingManager) QueueBillingReminders(ctx context.Context, dueBefore time.Time) (*BillingRunResult, error) {
	result := &BillingRunResult{}
	now := bm.now()
	subs, err := bm.storage.ListSubscriptions(ctx)
	if err != nil {
		return nil, err
	}
	for _, sub := range subs {
		if sub.Status != SubscriptionStatusActive && sub.Status != SubscriptionStatusPastDue {
			continue
		}
		reminderAt := sub.NextReminderAt
		if reminderAt.IsZero() {
			reminderAt = sub.NextBillingDate.AddDate(0, 0, -3)
		}
		if reminderAt.IsZero() || reminderAt.After(dueBefore) || (!sub.LastReminderAt.IsZero() && sub.LastReminderAt.After(now.Add(-20*time.Hour))) {
			continue
		}
		client, err := bm.storage.GetClient(ctx, sub.ClientID)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sub.ID, err))
			continue
		}
		subject := "Subscription renewal reminder"
		body := fmt.Sprintf("Your subscription renews on %s.", sub.NextBillingDate.Format("2006-01-02"))
		if sub.Status == SubscriptionStatusPastDue {
			subject = "Payment retry reminder"
			body = fmt.Sprintf("Your subscription payment is past due. Please update payment before %s.", sub.EndDate.AddDate(0, 0, sub.GracePeriodDays).Format("2006-01-02"))
		}
		msg := &email.EmailMessage{
			ID:           uuid.New().String(),
			To:           client.Email,
			Subject:      subject,
			RenderedText: body,
			RenderedHTML: "<p>" + body + "</p>",
			Variables: map[string]any{
				"subscription_id":   sub.ID,
				"next_billing_date": sub.NextBillingDate,
				"status":            sub.Status,
			},
			Metadata: map[string]string{
				"category":        "billing",
				"subscription_id": sub.ID,
				"client_id":       sub.ClientID,
			},
			Status:        email.MessageStatusQueued,
			MaxRetries:    3,
			NextAttemptAt: now,
			CreatedAt:     now,
			UpdatedAt:     now,
		}
		if err := bm.storage.EnqueueEmail(ctx, msg); err != nil {
			result.Errors = append(result.Errors, fmt.Sprintf("%s: %v", sub.ID, err))
			continue
		}
		sub.LastReminderAt = now
		sub.NextReminderAt = now.Add(24 * time.Hour)
		_ = bm.storage.UpdateSubscription(ctx, sub)
		result.RemindersQueued++
		result.Subscriptions = append(result.Subscriptions, sub.ID)
	}
	return result, nil
}

func (bm *BillingManager) NewInvoiceFromSubscription(ctx context.Context, sub *Subscription) (*BillingInvoice, error) {
	if sub == nil {
		return nil, fmt.Errorf("subscription is nil")
	}
	plan, err := bm.storage.GetPlan(ctx, sub.PlanID)
	if err != nil {
		return nil, err
	}
	quantity := sub.Quantity
	if quantity < 1 {
		quantity = 1
	}
	unit := plan.PricePerDevice
	if unit <= 0 {
		unit = plan.Price
	}
	subtotal := unit * int64(quantity)
	start := sub.NextBillingDate
	if start.IsZero() {
		start = sub.EndDate
	}
	if start.IsZero() {
		start = bm.now()
	}
	end := addBillingCycle(start, sub.BillingCycle)
	now := bm.now()
	status := InvoiceStatusOpen
	if sub.CollectionMethod == CollectionMethodManual || sub.ApprovalStatus == ApprovalStatusPending {
		status = InvoiceStatusPendingPayment
	}
	return &BillingInvoice{
		ID:             uuid.New().String(),
		SubscriptionID: sub.ID,
		ClientID:       sub.ClientID,
		ProductID:      sub.ProductID,
		PlanID:         sub.PlanID,
		Status:         status,
		Currency:       plan.Currency,
		SubtotalAmount: subtotal,
		TotalAmount:    subtotal,
		PeriodStart:    start,
		PeriodEnd:      end,
		DueAt:          start,
		GatewayID:      sub.GatewayID,
		Metadata: map[string]string{
			"collection_method": sub.CollectionMethod,
			"quantity":          fmt.Sprintf("%d", quantity),
		},
		CreatedAt: now,
		UpdatedAt: now,
	}, nil
}

func (bm *BillingManager) MarkInvoicePaid(ctx context.Context, invoiceID, gatewayPaymentIntentID string) error {
	invoice, err := bm.storage.GetBillingInvoice(ctx, invoiceID)
	if err != nil {
		return err
	}
	now := bm.now()
	invoice.Status = InvoiceStatusPaid
	invoice.PaidAt = now
	if gatewayPaymentIntentID != "" {
		invoice.GatewayInvoiceID = gatewayPaymentIntentID
	}
	invoice.NextPaymentAttemptAt = time.Time{}
	if err := bm.storage.UpdateBillingInvoice(ctx, invoice); err != nil {
		return err
	}
	sub, err := bm.storage.GetSubscription(ctx, invoice.SubscriptionID)
	if err != nil {
		return err
	}
	sub.Status = SubscriptionStatusActive
	sub.FailureCount = 0
	sub.EndDate = invoice.PeriodEnd
	sub.NextBillingDate = invoice.PeriodEnd
	sub.ApprovalStatus = ApprovalStatusApproved
	sub.LastReminderAt = time.Time{}
	sub.NextReminderAt = time.Time{}
	if err := bm.storage.UpdateSubscription(ctx, sub); err != nil {
		return err
	}
	if sub.LicenseID == "" {
		return nil
	}
	license, err := bm.storage.GetLicense(ctx, sub.LicenseID)
	if err != nil {
		return nil
	}
	if license.ExpiresAt.Before(invoice.PeriodEnd) {
		license.ExpiresAt = invoice.PeriodEnd
		license.IsRevoked = false
		license.RevokedAt = time.Time{}
		license.RevokeReason = ""
		return bm.storage.UpdateLicense(ctx, license)
	}
	return nil
}

func (bm *BillingManager) CancelSubscription(ctx context.Context, subscriptionID, reason string, atPeriodEnd bool) (*Subscription, error) {
	sub, err := bm.storage.GetSubscription(ctx, subscriptionID)
	if err != nil {
		return nil, err
	}
	if sub.GatewayID != "" {
		gateway, err := bm.storage.GetPaymentGateway(ctx, sub.GatewayID)
		if err == nil {
			if adapter := bm.adapters[gateway.Provider]; adapter != nil {
				_ = adapter.CancelSubscription(ctx, gateway, sub)
			}
		}
	}
	sub.AutoRenew = false
	sub.CancelReason = reason
	sub.CancelledAt = bm.now()
	if !atPeriodEnd {
		sub.Status = SubscriptionStatusCancelled
	}
	if err := bm.storage.UpdateSubscription(ctx, sub); err != nil {
		return nil, err
	}
	return sub, nil
}

func (bm *BillingManager) ResumeSubscription(ctx context.Context, subscriptionID string) (*Subscription, error) {
	sub, err := bm.storage.GetSubscription(ctx, subscriptionID)
	if err != nil {
		return nil, err
	}
	if sub.Status == SubscriptionStatusCancelled || sub.Status == SubscriptionStatusPaused {
		sub.Status = SubscriptionStatusActive
	}
	sub.AutoRenew = true
	sub.CancelledAt = time.Time{}
	sub.CancelReason = ""
	if err := bm.storage.UpdateSubscription(ctx, sub); err != nil {
		return nil, err
	}
	return sub, nil
}

func (bm *BillingManager) subscriptionNeedsInvoice(sub *Subscription, dueBefore time.Time) bool {
	if sub == nil || !sub.AutoRenew || sub.Status == SubscriptionStatusCancelled || sub.Status == SubscriptionStatusExpired || sub.BillingCycle == "lifetime" {
		return false
	}
	due := sub.NextBillingDate
	if due.IsZero() {
		due = sub.EndDate
	}
	return !due.IsZero() && !due.After(dueBefore)
}

func hasOpenInvoiceForPeriod(invoices []*BillingInvoice, periodStart time.Time) bool {
	for _, invoice := range invoices {
		if invoice.Status == InvoiceStatusPaid || invoice.Status == InvoiceStatusVoid {
			continue
		}
		if invoice.PeriodStart.Equal(periodStart) {
			return true
		}
	}
	return false
}

func (bm *BillingManager) captureInvoice(ctx context.Context, invoice *BillingInvoice) (*PaymentAttempt, error) {
	now := bm.now()
	sub, err := bm.storage.GetSubscription(ctx, invoice.SubscriptionID)
	if err != nil {
		return nil, err
	}
	var gateway *PaymentGatewayConfig
	if invoice.GatewayID != "" {
		gateway, err = bm.storage.GetPaymentGateway(ctx, invoice.GatewayID)
		if err != nil {
			return nil, err
		}
	}
	if gateway == nil {
		gateway = &PaymentGatewayConfig{ID: BillingGatewayManual, Provider: BillingGatewayManual, Enabled: true}
	}
	adapter := bm.adapters[gateway.Provider]
	if adapter == nil {
		return nil, fmt.Errorf("no billing adapter registered for %s", gateway.Provider)
	}
	var method *PaymentMethod
	if sub.PaymentMethodID != "" {
		method, _ = bm.storage.GetPaymentMethod(ctx, sub.PaymentMethodID)
	}
	result, err := adapter.CapturePayment(ctx, gateway, invoice, method)
	if err != nil {
		return nil, err
	}
	attempt := &PaymentAttempt{
		ID:                     uuid.New().String(),
		InvoiceID:              invoice.ID,
		SubscriptionID:         invoice.SubscriptionID,
		GatewayID:              gateway.ID,
		Status:                 result.Status,
		Amount:                 invoice.TotalAmount,
		Currency:               invoice.Currency,
		GatewayPaymentIntentID: result.GatewayPaymentIntentID,
		ErrorCode:              result.ErrorCode,
		ErrorMessage:           result.ErrorMessage,
		AttemptedAt:            now,
		Metadata:               result.Metadata,
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if method != nil {
		attempt.PaymentMethodID = method.ID
	}
	if result.Status == PaymentAttemptStatusFailed || result.Status == PaymentAttemptStatusPending {
		attempt.NextRetryAt = bm.nextRetryAt(invoice.AttemptCount + 1)
	}
	if result.HostedInvoiceURL != "" {
		invoice.HostedInvoiceURL = result.HostedInvoiceURL
	}
	return attempt, nil
}

func (bm *BillingManager) nextRetryAt(attemptCount int) time.Time {
	if attemptCount < 1 {
		attemptCount = 1
	}
	hours := []time.Duration{24, 72, 168}
	idx := attemptCount - 1
	if idx >= len(hours) {
		idx = len(hours) - 1
	}
	return bm.now().Add(hours[idx] * time.Hour)
}

func (bm *BillingManager) markSubscriptionPastDue(ctx context.Context, subscriptionID string) error {
	sub, err := bm.storage.GetSubscription(ctx, subscriptionID)
	if err != nil {
		return err
	}
	sub.Status = SubscriptionStatusPastDue
	sub.FailureCount++
	if sub.GracePeriodDays >= 0 && bm.now().After(sub.EndDate.AddDate(0, 0, sub.GracePeriodDays)) {
		sub.Status = SubscriptionStatusExpired
		if sub.LicenseID != "" {
			if license, err := bm.storage.GetLicense(ctx, sub.LicenseID); err == nil {
				license.IsRevoked = true
				license.RevokedAt = bm.now()
				license.RevokeReason = "subscription grace period expired"
				_ = bm.storage.UpdateLicense(ctx, license)
			}
		}
	}
	return bm.storage.UpdateSubscription(ctx, sub)
}

func addBillingCycle(start time.Time, cycle string) time.Time {
	switch cycle {
	case "monthly":
		return start.AddDate(0, 1, 0)
	case "yearly", "annual":
		return start.AddDate(1, 0, 0)
	case "weekly":
		return start.AddDate(0, 0, 7)
	case "daily":
		return start.AddDate(0, 0, 1)
	default:
		return start.AddDate(0, 1, 0)
	}
}
