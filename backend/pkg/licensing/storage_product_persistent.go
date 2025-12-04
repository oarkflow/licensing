package licensing

import (
	"context"
)

// ==================== PersistentStorage Product Methods ====================

func (ps *PersistentStorage) SaveProduct(ctx context.Context, product *Product) error {
	if err := ps.backend.SaveProduct(ctx, product); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateProduct(ctx context.Context, product *Product) error {
	if err := ps.backend.UpdateProduct(ctx, product); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetProduct(ctx context.Context, productID string) (*Product, error) {
	return ps.backend.GetProduct(ctx, productID)
}

func (ps *PersistentStorage) GetProductBySlug(ctx context.Context, slug string) (*Product, error) {
	return ps.backend.GetProductBySlug(ctx, slug)
}

func (ps *PersistentStorage) ListProducts(ctx context.Context) ([]*Product, error) {
	return ps.backend.ListProducts(ctx)
}

func (ps *PersistentStorage) DeleteProduct(ctx context.Context, productID string) error {
	if err := ps.backend.DeleteProduct(ctx, productID); err != nil {
		return err
	}
	return ps.persist()
}

// ==================== PersistentStorage Plan Methods ====================

func (ps *PersistentStorage) SavePlan(ctx context.Context, plan *Plan) error {
	if err := ps.backend.SavePlan(ctx, plan); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdatePlan(ctx context.Context, plan *Plan) error {
	if err := ps.backend.UpdatePlan(ctx, plan); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	return ps.backend.GetPlan(ctx, planID)
}

func (ps *PersistentStorage) GetPlanBySlug(ctx context.Context, productID, slug string) (*Plan, error) {
	return ps.backend.GetPlanBySlug(ctx, productID, slug)
}

func (ps *PersistentStorage) FindPlanBySlug(ctx context.Context, slug string) (*Plan, error) {
	return ps.backend.FindPlanBySlug(ctx, slug)
}

func (ps *PersistentStorage) ListPlansByProduct(ctx context.Context, productID string) ([]*Plan, error) {
	return ps.backend.ListPlansByProduct(ctx, productID)
}

func (ps *PersistentStorage) GetTrialPlanForProduct(ctx context.Context, productID string) (*Plan, error) {
	return ps.backend.GetTrialPlanForProduct(ctx, productID)
}

func (ps *PersistentStorage) DeletePlan(ctx context.Context, planID string) error {
	if err := ps.backend.DeletePlan(ctx, planID); err != nil {
		return err
	}
	return ps.persist()
}

// ==================== PersistentStorage Feature Methods ====================

func (ps *PersistentStorage) SaveFeature(ctx context.Context, feature *Feature) error {
	if err := ps.backend.SaveFeature(ctx, feature); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateFeature(ctx context.Context, feature *Feature) error {
	if err := ps.backend.UpdateFeature(ctx, feature); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetFeature(ctx context.Context, featureID string) (*Feature, error) {
	return ps.backend.GetFeature(ctx, featureID)
}

func (ps *PersistentStorage) GetFeatureBySlug(ctx context.Context, productID, slug string) (*Feature, error) {
	return ps.backend.GetFeatureBySlug(ctx, productID, slug)
}

func (ps *PersistentStorage) ListFeaturesByProduct(ctx context.Context, productID string) ([]*Feature, error) {
	return ps.backend.ListFeaturesByProduct(ctx, productID)
}

func (ps *PersistentStorage) DeleteFeature(ctx context.Context, featureID string) error {
	if err := ps.backend.DeleteFeature(ctx, featureID); err != nil {
		return err
	}
	return ps.persist()
}

// ==================== PersistentStorage Feature Scope Methods ====================

func (ps *PersistentStorage) SaveFeatureScope(ctx context.Context, scope *FeatureScope) error {
	if err := ps.backend.SaveFeatureScope(ctx, scope); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateFeatureScope(ctx context.Context, scope *FeatureScope) error {
	if err := ps.backend.UpdateFeatureScope(ctx, scope); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetFeatureScope(ctx context.Context, scopeID string) (*FeatureScope, error) {
	return ps.backend.GetFeatureScope(ctx, scopeID)
}

func (ps *PersistentStorage) ListFeatureScopes(ctx context.Context, featureID string) ([]*FeatureScope, error) {
	return ps.backend.ListFeatureScopes(ctx, featureID)
}

func (ps *PersistentStorage) DeleteFeatureScope(ctx context.Context, scopeID string) error {
	if err := ps.backend.DeleteFeatureScope(ctx, scopeID); err != nil {
		return err
	}
	return ps.persist()
}

// ==================== PersistentStorage Plan Feature Methods ====================

func (ps *PersistentStorage) SavePlanFeature(ctx context.Context, pf *PlanFeature) error {
	if err := ps.backend.SavePlanFeature(ctx, pf); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdatePlanFeature(ctx context.Context, pf *PlanFeature) error {
	if err := ps.backend.UpdatePlanFeature(ctx, pf); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetPlanFeature(ctx context.Context, planID, featureID string) (*PlanFeature, error) {
	return ps.backend.GetPlanFeature(ctx, planID, featureID)
}

func (ps *PersistentStorage) ListPlanFeatures(ctx context.Context, planID string) ([]*PlanFeature, error) {
	return ps.backend.ListPlanFeatures(ctx, planID)
}

func (ps *PersistentStorage) DeletePlanFeature(ctx context.Context, planID, featureID string) error {
	if err := ps.backend.DeletePlanFeature(ctx, planID, featureID); err != nil {
		return err
	}
	return ps.persist()
}

// ==================== PersistentStorage Entitlement Computation ====================

func (ps *PersistentStorage) ComputeLicenseEntitlements(ctx context.Context, productID, planID string) (*LicenseEntitlements, error) {
	return ps.backend.ComputeLicenseEntitlements(ctx, productID, planID)
}
