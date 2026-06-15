package licensing

import (
	"context"
	"testing"
	"time"
)

func TestBillingManagerGeneratesAndPaysRenewalInvoice(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemoryStorage()
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	client := &Client{ID: "client-1", Email: "billing@example.com", Status: ClientStatusActive, CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveClient(ctx, client); err != nil {
		t.Fatalf("SaveClient failed: %v", err)
	}
	product := &Product{ID: "product-1", Name: "App", Slug: "app", CreatedAt: now, UpdatedAt: now}
	if err := storage.SaveProduct(ctx, product); err != nil {
		t.Fatalf("SaveProduct failed: %v", err)
	}
	plan := &Plan{
		ID:             "plan-1",
		ProductID:      product.ID,
		Name:           "Pro",
		Slug:           "pro",
		PricePerDevice: 2000,
		Currency:       "USD",
		BillingCycle:   "monthly",
		MinDevices:     1,
		IsActive:       true,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := storage.SavePlan(ctx, plan); err != nil {
		t.Fatalf("SavePlan failed: %v", err)
	}
	license := &License{
		ID:         "license-1",
		ClientID:   client.ID,
		Email:      client.Email,
		ProductID:  product.ID,
		PlanID:     plan.ID,
		PlanSlug:   plan.Slug,
		LicenseKey: "LIC-TEST",
		IssuedAt:   now.AddDate(0, -1, 0),
		ExpiresAt:  now,
		MaxDevices: 2,
		Devices:    map[string]*LicenseDevice{},
	}
	if err := storage.SaveLicense(ctx, license); err != nil {
		t.Fatalf("SaveLicense failed: %v", err)
	}
	gateway := &PaymentGatewayConfig{
		ID:                "manual",
		Name:              "Manual",
		Provider:          BillingGatewayManual,
		Environment:       "test",
		Enabled:           true,
		SupportsRecurring: true,
		CreatedAt:         now,
		UpdatedAt:         now,
	}
	if err := storage.SavePaymentGateway(ctx, gateway); err != nil {
		t.Fatalf("SavePaymentGateway failed: %v", err)
	}
	sub := &Subscription{
		ID:               "sub-1",
		ClientID:         client.ID,
		ProductID:        product.ID,
		PlanID:           plan.ID,
		LicenseID:        license.ID,
		Status:           SubscriptionStatusActive,
		StartDate:        now.AddDate(0, -1, 0),
		EndDate:          now,
		BillingCycle:     "monthly",
		NextBillingDate:  now,
		AutoRenew:        true,
		CollectionMethod: CollectionMethodManual,
		GatewayID:        gateway.ID,
		Quantity:         2,
		GracePeriodDays:  7,
		ApprovalStatus:   ApprovalStatusApproved,
		CreatedAt:        now.AddDate(0, -1, 0),
		UpdatedAt:        now.AddDate(0, -1, 0),
	}
	if err := storage.SaveSubscription(ctx, sub); err != nil {
		t.Fatalf("SaveSubscription failed: %v", err)
	}

	manager := NewBillingManager(storage, nil)
	manager.now = func() time.Time { return now }
	generated, err := manager.GenerateRenewalInvoices(ctx, now)
	if err != nil {
		t.Fatalf("GenerateRenewalInvoices failed: %v", err)
	}
	if generated.InvoicesCreated != 1 {
		t.Fatalf("expected one invoice, got %+v", generated)
	}
	invoices, err := storage.ListBillingInvoicesBySubscription(ctx, sub.ID)
	if err != nil {
		t.Fatalf("ListBillingInvoicesBySubscription failed: %v", err)
	}
	if len(invoices) != 1 || invoices[0].TotalAmount != 4000 || invoices[0].Status != InvoiceStatusPendingPayment {
		t.Fatalf("unexpected generated invoice: %+v", invoices)
	}

	invoices[0].Metadata["manual_status"] = "paid"
	if err := storage.UpdateBillingInvoice(ctx, invoices[0]); err != nil {
		t.Fatalf("UpdateBillingInvoice failed: %v", err)
	}
	processed, err := manager.ProcessDueInvoices(ctx, now)
	if err != nil {
		t.Fatalf("ProcessDueInvoices failed: %v", err)
	}
	if processed.InvoicesPaid != 1 {
		t.Fatalf("expected one paid invoice, got %+v", processed)
	}
	renewedSub, err := storage.GetSubscription(ctx, sub.ID)
	if err != nil {
		t.Fatalf("GetSubscription failed: %v", err)
	}
	if renewedSub.Status != SubscriptionStatusActive || !renewedSub.EndDate.Equal(now.AddDate(0, 1, 0)) || renewedSub.FailureCount != 0 {
		t.Fatalf("subscription was not renewed: %+v", renewedSub)
	}
	renewedLicense, err := storage.GetLicense(ctx, license.ID)
	if err != nil {
		t.Fatalf("GetLicense failed: %v", err)
	}
	if !renewedLicense.ExpiresAt.Equal(now.AddDate(0, 1, 0)) || renewedLicense.IsRevoked {
		t.Fatalf("license was not extended: %+v", renewedLicense)
	}
}

func TestBillingManagerMarksPastDueAndExpiresAfterGrace(t *testing.T) {
	ctx := context.Background()
	storage := NewInMemoryStorage()
	now := time.Date(2026, 6, 15, 10, 0, 0, 0, time.UTC)

	client := &Client{ID: "client-2", Email: "pastdue@example.com", Status: ClientStatusActive, CreatedAt: now, UpdatedAt: now}
	_ = storage.SaveClient(ctx, client)
	product := &Product{ID: "product-2", Name: "App", Slug: "app-2", CreatedAt: now, UpdatedAt: now}
	_ = storage.SaveProduct(ctx, product)
	plan := &Plan{ID: "plan-2", ProductID: product.ID, Name: "Pro", Slug: "pro", Price: 1000, Currency: "USD", BillingCycle: "monthly", MinDevices: 1, IsActive: true, CreatedAt: now, UpdatedAt: now}
	_ = storage.SavePlan(ctx, plan)
	license := &License{ID: "license-2", ClientID: client.ID, Email: client.Email, ProductID: product.ID, PlanID: plan.ID, PlanSlug: plan.Slug, LicenseKey: "LIC-PAST", IssuedAt: now.AddDate(0, -1, 0), ExpiresAt: now.AddDate(0, 0, -10), Devices: map[string]*LicenseDevice{}}
	_ = storage.SaveLicense(ctx, license)
	sub := &Subscription{
		ID:               "sub-2",
		ClientID:         client.ID,
		ProductID:        product.ID,
		PlanID:           plan.ID,
		LicenseID:        license.ID,
		Status:           SubscriptionStatusActive,
		StartDate:        now.AddDate(0, -1, 0),
		EndDate:          now.AddDate(0, 0, -10),
		BillingCycle:     "monthly",
		NextBillingDate:  now.AddDate(0, 0, -10),
		AutoRenew:        true,
		CollectionMethod: CollectionMethodManual,
		Quantity:         1,
		GracePeriodDays:  3,
		ApprovalStatus:   ApprovalStatusApproved,
		CreatedAt:        now.AddDate(0, -1, 0),
		UpdatedAt:        now.AddDate(0, -1, 0),
	}
	_ = storage.SaveSubscription(ctx, sub)
	invoice := &BillingInvoice{
		ID:             "invoice-2",
		SubscriptionID: sub.ID,
		ClientID:       client.ID,
		ProductID:      product.ID,
		PlanID:         plan.ID,
		Status:         InvoiceStatusOpen,
		Currency:       "USD",
		TotalAmount:    1000,
		PeriodStart:    sub.NextBillingDate,
		PeriodEnd:      sub.NextBillingDate.AddDate(0, 1, 0),
		DueAt:          sub.NextBillingDate,
		Metadata:       map[string]string{"manual_status": "failed"},
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	_ = storage.SaveBillingInvoice(ctx, invoice)

	manager := NewBillingManager(storage, nil)
	manager.now = func() time.Time { return now }
	processed, err := manager.ProcessDueInvoices(ctx, now)
	if err != nil {
		t.Fatalf("ProcessDueInvoices failed: %v", err)
	}
	if processed.InvoicesFailed != 1 {
		t.Fatalf("expected one failed invoice, got %+v", processed)
	}
	expiredSub, _ := storage.GetSubscription(ctx, sub.ID)
	if expiredSub.Status != SubscriptionStatusExpired {
		t.Fatalf("expected expired subscription, got %+v", expiredSub)
	}
	revokedLicense, _ := storage.GetLicense(ctx, license.ID)
	if !revokedLicense.IsRevoked || revokedLicense.RevokeReason == "" {
		t.Fatalf("expected revoked license, got %+v", revokedLicense)
	}
}
