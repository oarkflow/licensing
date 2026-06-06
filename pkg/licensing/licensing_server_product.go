package licensing

import (
	"context"
	"fmt"
	"time"
)

const (
	licensingServerProductID   = "licensing-server"
	licensingServerProductSlug = "licensing-server"
)

// LicensingServerCatalogSnapshot captures the distribution product metadata
// synchronized into storage.
type LicensingServerCatalogSnapshot struct {
	Product  *Product
	Plans    map[string]*Plan
	Features map[string]*Feature
}

type licensingServerPlanDefinition struct {
	ID           string
	Name         string
	Slug         string
	Description  string
	Price        int64
	MinDevices   int
	DurationDays int
	BillingCycle string
	TrialDays    int
	IsTrial      bool
	DisplayOrder int
	IsActive     bool
	Metadata     map[string]string
}

var licensingServerPlanDefinitions = []licensingServerPlanDefinition{
	{
		ID:           "plan_licensing_server_distribution_trial",
		Name:         "Distribution Trial",
		Slug:         "distribution-trial",
		Description:  "Trial license for evaluating distributed Licensing Server deployments",
		MinDevices:   1,
		DurationDays: 14,
		BillingCycle: "trial",
		TrialDays:    14,
		IsTrial:      true,
		DisplayOrder: 0,
		IsActive:     true,
		Metadata: map[string]string{
			"price_model": "trial",
		},
	},
	{
		ID:           "plan_licensing_server_distribution_pro",
		Name:         "Distribution Pro",
		Slug:         "distribution-pro",
		Description:  "Licensed distribution for production Licensing Server deployments",
		Price:        99900,
		MinDevices:   1,
		DurationDays: 365,
		BillingCycle: "yearly",
		DisplayOrder: 1,
		IsActive:     true,
		Metadata: map[string]string{
			"price_model": "yearly",
		},
	},
	{
		ID:           "plan_licensing_server_distribution_enterprise",
		Name:         "Distribution Enterprise",
		Slug:         "distribution-enterprise",
		Description:  "Enterprise distribution with custom support and deployment terms",
		MinDevices:   1,
		DurationDays: 365,
		BillingCycle: "yearly",
		DisplayOrder: 2,
		IsActive:     true,
		Metadata: map[string]string{
			"price_model": "custom",
			"price_notes": "Contact sales",
		},
	},
}

var licensingServerDistributionFeature = Feature{
	ID:          "feat_licensing_server_distribution",
	Name:        "Distribution",
	Slug:        "distribution",
	Description: "Allows running distribution-tagged Licensing Server builds",
	Type:        FeatureTypeScoped,
	Category:    "runtime",
	Metadata: map[string]string{
		"description": "Required by distribution builds at server startup",
	},
}

var licensingServerDistributionScope = FeatureScope{
	ID:         "licensing_server_distribution_server_start",
	Name:       "Start Server",
	Slug:       "server.start",
	Permission: ScopePermissionAllow,
	Metadata: map[string]string{
		"description": "Allows starting the distributed Licensing Server runtime",
	},
}

// BootstrapLicensingServerProduct ensures the Licensing Server distribution
// product, plans, feature, scope, and plan-feature mappings exist.
func BootstrapLicensingServerProduct(ctx context.Context, storage Storage) (*LicensingServerCatalogSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()

	product := &Product{
		ID:          licensingServerProductID,
		Name:        "Licensing Server",
		Slug:        licensingServerProductSlug,
		Description: "Distribution licensing for packaged Licensing Server deployments.",
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	persistedProduct, err := upsertProduct(ctx, storage, product)
	if err != nil {
		return nil, fmt.Errorf("bootstrap licensing server product: %w", err)
	}

	feature := licensingServerDistributionFeature
	feature.ProductID = persistedProduct.ID
	feature.CreatedAt = now
	feature.UpdatedAt = now
	persistedFeature, err := upsertFeature(ctx, storage, &feature)
	if err != nil {
		return nil, fmt.Errorf("upsert distribution feature: %w", err)
	}

	scope := licensingServerDistributionScope
	scope.FeatureID = persistedFeature.ID
	scope.CreatedAt = now
	scope.UpdatedAt = now
	if err := upsertFeatureScope(ctx, storage, &scope); err != nil {
		return nil, fmt.Errorf("upsert distribution scope: %w", err)
	}

	planMap := make(map[string]*Plan, len(licensingServerPlanDefinitions))
	for _, def := range licensingServerPlanDefinitions {
		plan := &Plan{
			ID:             def.ID,
			ProductID:      persistedProduct.ID,
			Name:           def.Name,
			Slug:           def.Slug,
			Description:    def.Description,
			Price:          def.Price,
			PricePerDevice: def.Price,
			MinDevices:     def.MinDevices,
			DurationDays:   def.DurationDays,
			Currency:       "USD",
			BillingCycle:   def.BillingCycle,
			TrialDays:      def.TrialDays,
			IsTrial:        def.IsTrial,
			IsActive:       def.IsActive,
			DisplayOrder:   def.DisplayOrder,
			Metadata:       cloneStringMap(def.Metadata),
			CreatedAt:      now,
			UpdatedAt:      now,
		}
		persistedPlan, err := upsertPlan(ctx, storage, plan)
		if err != nil {
			return nil, fmt.Errorf("upsert licensing server plan %s: %w", def.Slug, err)
		}
		planMap[persistedPlan.Slug] = persistedPlan

		planFeature := &PlanFeature{
			ID:        fmt.Sprintf("pf_%s_%s", persistedPlan.ID, persistedFeature.ID),
			PlanID:    persistedPlan.ID,
			FeatureID: persistedFeature.ID,
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := upsertPlanFeature(ctx, storage, planFeature); err != nil {
			return nil, fmt.Errorf("upsert licensing server plan feature %s: %w", def.Slug, err)
		}
	}

	return &LicensingServerCatalogSnapshot{
		Product: cloneProduct(persistedProduct),
		Plans: map[string]*Plan{
			"distribution-trial":      clonePlan(planMap["distribution-trial"]),
			"distribution-pro":        clonePlan(planMap["distribution-pro"]),
			"distribution-enterprise": clonePlan(planMap["distribution-enterprise"]),
		},
		Features: map[string]*Feature{
			"distribution": cloneFeature(persistedFeature),
		},
	}, nil
}
