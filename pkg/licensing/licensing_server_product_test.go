package licensing

import (
	"context"
	"testing"
)

func TestBootstrapLicensingServerProductGrantsDistributionFeature(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	storage := NewInMemoryStorage()
	catalog, err := BootstrapLicensingServerProduct(ctx, storage)
	if err != nil {
		t.Fatalf("BootstrapLicensingServerProduct failed: %v", err)
	}
	if catalog.Product.Slug != licensingServerProductSlug {
		t.Fatalf("unexpected product slug: %s", catalog.Product.Slug)
	}

	plan := catalog.Plans["distribution-pro"]
	if plan == nil {
		t.Fatalf("distribution-pro plan missing")
	}
	entitlements, err := storage.ComputeLicenseEntitlements(ctx, catalog.Product.ID, plan.ID)
	if err != nil {
		t.Fatalf("ComputeLicenseEntitlements failed: %v", err)
	}
	feature, ok := entitlements.Features["distribution"]
	if !ok {
		t.Fatalf("distribution feature missing from entitlements")
	}
	if !feature.Enabled {
		t.Fatalf("distribution feature should be enabled")
	}
	scope, ok := feature.Scopes["server.start"]
	if !ok {
		t.Fatalf("server.start scope missing from distribution feature")
	}
	if scope.Permission != ScopePermissionAllow {
		t.Fatalf("server.start scope permission = %q, want %q", scope.Permission, ScopePermissionAllow)
	}
}
