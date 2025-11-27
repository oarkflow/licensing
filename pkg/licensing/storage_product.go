package licensing

import (
	"context"
	"fmt"
	"strings"
)

// ==================== Product Storage Methods ====================

func (s *InMemoryStorage) SaveProduct(_ context.Context, product *Product) error {
	if product == nil {
		return fmt.Errorf("product is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.products[product.ID]; exists {
		return errProductExists
	}
	slugKey := strings.ToLower(product.Slug)
	if slugKey != "" {
		if _, exists := s.productsBySlug[slugKey]; exists {
			return errProductExists
		}
		s.productsBySlug[slugKey] = product.ID
	}
	s.products[product.ID] = cloneProduct(product)
	return nil
}

func (s *InMemoryStorage) UpdateProduct(_ context.Context, product *Product) error {
	if product == nil {
		return fmt.Errorf("product is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.products[product.ID]
	if !exists {
		return errProductMissing
	}
	oldSlug := strings.ToLower(current.Slug)
	newSlug := strings.ToLower(product.Slug)
	if oldSlug != newSlug {
		if mappedID, taken := s.productsBySlug[newSlug]; taken && mappedID != product.ID {
			return errProductExists
		}
		delete(s.productsBySlug, oldSlug)
	}
	s.products[product.ID] = cloneProduct(product)
	s.productsBySlug[newSlug] = product.ID
	return nil
}

func (s *InMemoryStorage) GetProduct(_ context.Context, productID string) (*Product, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	product, exists := s.products[productID]
	if !exists {
		return nil, errProductMissing
	}
	return cloneProduct(product), nil
}

func (s *InMemoryStorage) GetProductBySlug(_ context.Context, slug string) (*Product, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	productID, exists := s.productsBySlug[strings.ToLower(slug)]
	if !exists {
		return nil, errProductMissing
	}
	return cloneProduct(s.products[productID]), nil
}

func (s *InMemoryStorage) ListProducts(_ context.Context) ([]*Product, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	products := make([]*Product, 0, len(s.products))
	for _, p := range s.products {
		products = append(products, cloneProduct(p))
	}
	return products, nil
}

func (s *InMemoryStorage) DeleteProduct(_ context.Context, productID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	product, exists := s.products[productID]
	if !exists {
		return errProductMissing
	}
	delete(s.productsBySlug, strings.ToLower(product.Slug))
	delete(s.products, productID)
	return nil
}

// ==================== Plan Storage Methods ====================

func planSlugKey(productID, slug string) string {
	return productID + ":" + strings.ToLower(slug)
}

func (s *InMemoryStorage) SavePlan(_ context.Context, plan *Plan) error {
	if plan == nil {
		return fmt.Errorf("plan is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.plans[plan.ID]; exists {
		return errPlanExists
	}
	slugKey := planSlugKey(plan.ProductID, plan.Slug)
	if slugKey != "" {
		if _, exists := s.plansBySlug[slugKey]; exists {
			return errPlanExists
		}
		s.plansBySlug[slugKey] = plan.ID
	}
	s.plans[plan.ID] = clonePlan(plan)
	return nil
}

func (s *InMemoryStorage) UpdatePlan(_ context.Context, plan *Plan) error {
	if plan == nil {
		return fmt.Errorf("plan is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.plans[plan.ID]
	if !exists {
		return errPlanMissing
	}
	oldSlugKey := planSlugKey(current.ProductID, current.Slug)
	newSlugKey := planSlugKey(plan.ProductID, plan.Slug)
	if oldSlugKey != newSlugKey {
		if mappedID, taken := s.plansBySlug[newSlugKey]; taken && mappedID != plan.ID {
			return errPlanExists
		}
		delete(s.plansBySlug, oldSlugKey)
	}
	s.plans[plan.ID] = clonePlan(plan)
	s.plansBySlug[newSlugKey] = plan.ID
	return nil
}

func (s *InMemoryStorage) GetPlan(_ context.Context, planID string) (*Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plan, exists := s.plans[planID]
	if !exists {
		return nil, errPlanMissing
	}
	return clonePlan(plan), nil
}

func (s *InMemoryStorage) GetPlanBySlug(_ context.Context, productID, slug string) (*Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	planID, exists := s.plansBySlug[planSlugKey(productID, slug)]
	if !exists {
		return nil, errPlanMissing
	}
	return clonePlan(s.plans[planID]), nil
}

func (s *InMemoryStorage) FindPlanBySlug(_ context.Context, slug string) (*Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	slugLower := strings.ToLower(slug)
	for _, p := range s.plans {
		if strings.ToLower(p.Slug) == slugLower {
			return clonePlan(p), nil
		}
	}
	return nil, errPlanMissing
}

func (s *InMemoryStorage) ListPlansByProduct(_ context.Context, productID string) ([]*Plan, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	plans := make([]*Plan, 0)
	for _, p := range s.plans {
		if p.ProductID == productID {
			plans = append(plans, clonePlan(p))
		}
	}
	return plans, nil
}

func (s *InMemoryStorage) DeletePlan(_ context.Context, planID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	plan, exists := s.plans[planID]
	if !exists {
		return errPlanMissing
	}
	delete(s.plansBySlug, planSlugKey(plan.ProductID, plan.Slug))
	delete(s.plans, planID)
	// Also delete associated plan features
	for key, pf := range s.planFeatures {
		if pf.PlanID == planID {
			delete(s.planFeatures, key)
		}
	}
	return nil
}

// ==================== Feature Storage Methods ====================

func featureSlugKey(productID, slug string) string {
	return productID + ":" + strings.ToLower(slug)
}

func (s *InMemoryStorage) SaveFeature(_ context.Context, feature *Feature) error {
	if feature == nil {
		return fmt.Errorf("feature is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.features[feature.ID]; exists {
		return errFeatureExists
	}
	slugKey := featureSlugKey(feature.ProductID, feature.Slug)
	if slugKey != "" {
		if _, exists := s.featuresBySlug[slugKey]; exists {
			return errFeatureExists
		}
		s.featuresBySlug[slugKey] = feature.ID
	}
	s.features[feature.ID] = cloneFeature(feature)
	return nil
}

func (s *InMemoryStorage) UpdateFeature(_ context.Context, feature *Feature) error {
	if feature == nil {
		return fmt.Errorf("feature is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.features[feature.ID]
	if !exists {
		return errFeatureMissing
	}
	oldSlugKey := featureSlugKey(current.ProductID, current.Slug)
	newSlugKey := featureSlugKey(feature.ProductID, feature.Slug)
	if oldSlugKey != newSlugKey {
		if mappedID, taken := s.featuresBySlug[newSlugKey]; taken && mappedID != feature.ID {
			return errFeatureExists
		}
		delete(s.featuresBySlug, oldSlugKey)
	}
	s.features[feature.ID] = cloneFeature(feature)
	s.featuresBySlug[newSlugKey] = feature.ID
	return nil
}

func (s *InMemoryStorage) GetFeature(_ context.Context, featureID string) (*Feature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	feature, exists := s.features[featureID]
	if !exists {
		return nil, errFeatureMissing
	}
	return cloneFeature(feature), nil
}

func (s *InMemoryStorage) GetFeatureBySlug(_ context.Context, productID, slug string) (*Feature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	featureID, exists := s.featuresBySlug[featureSlugKey(productID, slug)]
	if !exists {
		return nil, errFeatureMissing
	}
	return cloneFeature(s.features[featureID]), nil
}

func (s *InMemoryStorage) ListFeaturesByProduct(_ context.Context, productID string) ([]*Feature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	features := make([]*Feature, 0)
	for _, f := range s.features {
		if f.ProductID == productID {
			features = append(features, cloneFeature(f))
		}
	}
	return features, nil
}

func (s *InMemoryStorage) DeleteFeature(_ context.Context, featureID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	feature, exists := s.features[featureID]
	if !exists {
		return errFeatureMissing
	}
	delete(s.featuresBySlug, featureSlugKey(feature.ProductID, feature.Slug))
	delete(s.features, featureID)
	// Also delete associated scopes
	for id, scope := range s.featureScopes {
		if scope.FeatureID == featureID {
			delete(s.featureScopes, id)
		}
	}
	// Also delete associated plan features
	for key, pf := range s.planFeatures {
		if pf.FeatureID == featureID {
			delete(s.planFeatures, key)
		}
	}
	return nil
}

// ==================== Feature Scope Storage Methods ====================

func (s *InMemoryStorage) SaveFeatureScope(_ context.Context, scope *FeatureScope) error {
	if scope == nil {
		return fmt.Errorf("feature scope is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.featureScopes[scope.ID]; exists {
		return errFeatureScopeExists
	}
	s.featureScopes[scope.ID] = cloneFeatureScope(scope)
	return nil
}

func (s *InMemoryStorage) UpdateFeatureScope(_ context.Context, scope *FeatureScope) error {
	if scope == nil {
		return fmt.Errorf("feature scope is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.featureScopes[scope.ID]; !exists {
		return errFeatureScopeMissing
	}
	s.featureScopes[scope.ID] = cloneFeatureScope(scope)
	return nil
}

func (s *InMemoryStorage) GetFeatureScope(_ context.Context, scopeID string) (*FeatureScope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scope, exists := s.featureScopes[scopeID]
	if !exists {
		return nil, errFeatureScopeMissing
	}
	return cloneFeatureScope(scope), nil
}

func (s *InMemoryStorage) ListFeatureScopes(_ context.Context, featureID string) ([]*FeatureScope, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	scopes := make([]*FeatureScope, 0)
	for _, scope := range s.featureScopes {
		if scope.FeatureID == featureID {
			scopes = append(scopes, cloneFeatureScope(scope))
		}
	}
	return scopes, nil
}

func (s *InMemoryStorage) DeleteFeatureScope(_ context.Context, scopeID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.featureScopes[scopeID]; !exists {
		return errFeatureScopeMissing
	}
	delete(s.featureScopes, scopeID)
	return nil
}

// ==================== Plan Feature Storage Methods ====================

func planFeatureKey(planID, featureID string) string {
	return planID + ":" + featureID
}

func (s *InMemoryStorage) SavePlanFeature(_ context.Context, pf *PlanFeature) error {
	if pf == nil {
		return fmt.Errorf("plan feature is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := planFeatureKey(pf.PlanID, pf.FeatureID)
	if _, exists := s.planFeatures[key]; exists {
		return errPlanFeatureExists
	}
	s.planFeatures[key] = clonePlanFeature(pf)
	return nil
}

func (s *InMemoryStorage) UpdatePlanFeature(_ context.Context, pf *PlanFeature) error {
	if pf == nil {
		return fmt.Errorf("plan feature is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := planFeatureKey(pf.PlanID, pf.FeatureID)
	if _, exists := s.planFeatures[key]; !exists {
		return errPlanFeatureMissing
	}
	s.planFeatures[key] = clonePlanFeature(pf)
	return nil
}

func (s *InMemoryStorage) GetPlanFeature(_ context.Context, planID, featureID string) (*PlanFeature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pf, exists := s.planFeatures[planFeatureKey(planID, featureID)]
	if !exists {
		return nil, errPlanFeatureMissing
	}
	return clonePlanFeature(pf), nil
}

func (s *InMemoryStorage) ListPlanFeatures(_ context.Context, planID string) ([]*PlanFeature, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	pfs := make([]*PlanFeature, 0)
	for _, pf := range s.planFeatures {
		if pf.PlanID == planID {
			pfs = append(pfs, clonePlanFeature(pf))
		}
	}
	return pfs, nil
}

func (s *InMemoryStorage) DeletePlanFeature(_ context.Context, planID, featureID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := planFeatureKey(planID, featureID)
	if _, exists := s.planFeatures[key]; !exists {
		return errPlanFeatureMissing
	}
	delete(s.planFeatures, key)
	return nil
}

// ==================== Entitlement Computation ====================

func (s *InMemoryStorage) ComputeLicenseEntitlements(_ context.Context, productID, planID string) (*LicenseEntitlements, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	product, exists := s.products[productID]
	if !exists {
		return nil, errProductMissing
	}

	plan, exists := s.plans[planID]
	if !exists {
		return nil, errPlanMissing
	}

	if plan.ProductID != productID {
		return nil, fmt.Errorf("plan does not belong to the specified product")
	}

	entitlements := &LicenseEntitlements{
		ProductID:   product.ID,
		ProductSlug: product.Slug,
		PlanID:      plan.ID,
		PlanSlug:    plan.Slug,
		Features:    make(map[string]FeatureGrant),
	}

	// Collect all plan features
	for _, pf := range s.planFeatures {
		if pf.PlanID != planID || !pf.Enabled {
			continue
		}

		feature, exists := s.features[pf.FeatureID]
		if !exists {
			continue
		}

		featureGrant := FeatureGrant{
			FeatureID:   feature.ID,
			FeatureSlug: feature.Slug,
			Category:    feature.Category,
			Enabled:     true,
			Scopes:      make(map[string]ScopeGrant),
		}

		// Collect all scopes for this feature
		for _, scope := range s.featureScopes {
			if scope.FeatureID != feature.ID {
				continue
			}

			// Check for scope override in plan feature
			scopeGrant := ScopeGrant{
				ScopeID:    scope.ID,
				ScopeSlug:  scope.Slug,
				Permission: scope.Permission,
				Limit:      scope.Limit,
				Metadata:   scope.Metadata,
			}

			// Apply override if exists
			if override, hasOverride := pf.ScopeOverrides[scope.ID]; hasOverride {
				scopeGrant.Permission = override.Permission
				scopeGrant.Limit = override.Limit
				if override.Metadata != nil {
					scopeGrant.Metadata = override.Metadata
				}
			}

			featureGrant.Scopes[scope.Slug] = scopeGrant
		}

		entitlements.Features[feature.Slug] = featureGrant
	}

	return entitlements, nil
}
