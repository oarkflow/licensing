package licensing

import (
	"context"
	"path/filepath"
	"testing"
	"time"
)

func TestSQLiteBillingPersistence(t *testing.T) {
	storage, err := NewSQLiteStorage(filepath.Join(t.TempDir(), "licensing.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	defer storage.db.Close()

	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)
	client := &Client{ID: "client-billing", Email: "billing@example.com", Status: ClientStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveClient(ctx, client); err != nil {
		t.Fatalf("SaveClient failed: %v", err)
	}
	product := &Product{ID: "product-billing", Name: "Billing App", Slug: "billing-app", CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveProduct(ctx, product); err != nil {
		t.Fatalf("SaveProduct failed: %v", err)
	}
	plan := &Plan{
		ID:             "plan-pro",
		ProductID:      product.ID,
		Name:           "Pro",
		Slug:           "pro",
		Price:          2900,
		Currency:       "USD",
		BillingCycle:   "monthly",
		PricePerDevice: 2900,
		MinDevices:     1,
		MaxDevices:     10,
		IsActive:       true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := storage.SavePlan(ctx, plan); err != nil {
		t.Fatalf("SavePlan failed: %v", err)
	}
	sub := &Subscription{
		ID:              "sub-pro",
		ClientID:        client.ID,
		ProductID:       product.ID,
		PlanID:          plan.ID,
		Status:          SubscriptionStatusActive,
		StartDate:       now,
		EndDate:         now.AddDate(0, 1, 0),
		BillingCycle:    "monthly",
		NextBillingDate: now.AddDate(0, 1, 0),
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := storage.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("SaveSubscription failed: %v", err)
	}

	gateway := &PaymentGatewayConfig{
		ID:                "gateway-stripe",
		Name:              "Stripe US",
		Provider:          BillingGatewayStripe,
		Environment:       "test",
		Enabled:           true,
		IsDefault:         true,
		SupportsRecurring: true,
		RequiresApproval:  false,
		Config:            map[string]string{"account_id": "acct_123"},
		Metadata:          map[string]string{"region": "us"},
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := storage.SavePaymentGateway(ctx, gateway); err != nil {
		t.Fatalf("SavePaymentGateway failed: %v", err)
	}
	storedGateway, err := storage.GetPaymentGateway(ctx, gateway.ID)
	if err != nil {
		t.Fatalf("GetPaymentGateway failed: %v", err)
	}
	if !storedGateway.IsDefault || storedGateway.Config["account_id"] != "acct_123" {
		t.Fatalf("gateway did not round-trip: %+v", storedGateway)
	}

	method := &PaymentMethod{
		ID:                     "pm-card",
		ClientID:               client.ID,
		GatewayID:              gateway.ID,
		Type:                   "card",
		Status:                 PaymentMethodStatusPendingApproval,
		DisplayName:            "Visa ending 4242",
		GatewayCustomerID:      "cus_123",
		GatewayPaymentMethodID: "pm_123",
		IsDefault:              true,
		RequiresApproval:       true,
		Metadata:               map[string]string{"brand": "visa"},
		CreatedAt:              now,
		UpdatedAt:              now,
	}
	if err := storage.SavePaymentMethod(ctx, method); err != nil {
		t.Fatalf("SavePaymentMethod failed: %v", err)
	}
	methods, err := storage.ListPaymentMethodsByClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("ListPaymentMethodsByClient failed: %v", err)
	}
	if len(methods) != 1 || methods[0].Metadata["brand"] != "visa" || !methods[0].RequiresApproval {
		t.Fatalf("payment method did not round-trip: %+v", methods)
	}

	invoice := &BillingInvoice{
		ID:                   "inv-1",
		SubscriptionID:       sub.ID,
		ClientID:             client.ID,
		ProductID:            product.ID,
		PlanID:               plan.ID,
		Status:               InvoiceStatusPaymentFailed,
		Currency:             "USD",
		SubtotalAmount:       2900,
		TotalAmount:          2900,
		PeriodStart:          now,
		PeriodEnd:            now.AddDate(0, 1, 0),
		DueAt:                now.Add(24 * time.Hour),
		GatewayID:            gateway.ID,
		GatewayInvoiceID:     "in_123",
		AttemptCount:         1,
		NextPaymentAttemptAt: now.Add(48 * time.Hour),
		Metadata:             map[string]string{"reminder": "scheduled"},
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	if err := storage.SaveBillingInvoice(ctx, invoice); err != nil {
		t.Fatalf("SaveBillingInvoice failed: %v", err)
	}
	invoices, err := storage.ListBillingInvoicesBySubscription(ctx, sub.ID)
	if err != nil {
		t.Fatalf("ListBillingInvoicesBySubscription failed: %v", err)
	}
	if len(invoices) != 1 || invoices[0].Status != InvoiceStatusPaymentFailed || invoices[0].NextPaymentAttemptAt.IsZero() {
		t.Fatalf("invoice did not round-trip: %+v", invoices)
	}

	attempt := &PaymentAttempt{
		ID:              "attempt-1",
		InvoiceID:       invoice.ID,
		SubscriptionID:  sub.ID,
		GatewayID:       gateway.ID,
		PaymentMethodID: method.ID,
		Status:          PaymentAttemptStatusRetrying,
		Amount:          2900,
		Currency:        "USD",
		ErrorCode:       "card_declined",
		ErrorMessage:    "card was declined",
		AttemptedAt:     now,
		NextRetryAt:     now.Add(48 * time.Hour),
		Metadata:        map[string]string{"retry": "1"},
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := storage.SavePaymentAttempt(ctx, attempt); err != nil {
		t.Fatalf("SavePaymentAttempt failed: %v", err)
	}
	attempts, err := storage.ListPaymentAttemptsByInvoice(ctx, invoice.ID)
	if err != nil {
		t.Fatalf("ListPaymentAttemptsByInvoice failed: %v", err)
	}
	if len(attempts) != 1 || attempts[0].ErrorCode != "card_declined" || attempts[0].Metadata["retry"] != "1" {
		t.Fatalf("payment attempt did not round-trip: %+v", attempts)
	}

	approval := &BillingApprovalRequest{
		ID:          "approval-1",
		SubjectType: "payment_method",
		SubjectID:   method.ID,
		ClientID:    client.ID,
		Status:      ApprovalStatusPending,
		Reason:      "Client requires finance approval before recurring charges.",
		RequestedBy: "admin",
		RequestedAt: now,
		ExpiresAt:   now.Add(7 * 24 * time.Hour),
		Metadata:    map[string]string{"department": "finance"},
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	if err := storage.SaveBillingApprovalRequest(ctx, approval); err != nil {
		t.Fatalf("SaveBillingApprovalRequest failed: %v", err)
	}
	storedApproval, err := storage.GetBillingApprovalRequest(ctx, approval.ID)
	if err != nil {
		t.Fatalf("GetBillingApprovalRequest failed: %v", err)
	}
	if storedApproval.Status != ApprovalStatusPending || storedApproval.Metadata["department"] != "finance" {
		t.Fatalf("approval did not round-trip: %+v", storedApproval)
	}
}
