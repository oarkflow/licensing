package licensing

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ==================== Request Types ====================

type createProductRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	LogoURL     string `json:"logo_url,omitempty"`
}

type updateProductRequest struct {
	Name        string `json:"name,omitempty"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	LogoURL     string `json:"logo_url,omitempty"`
}

type createPlanRequest struct {
	Name         string            `json:"name"`
	Slug         string            `json:"slug"`
	Description  string            `json:"description,omitempty"`
	Price        int64             `json:"price"`
	Currency     string            `json:"currency"`
	BillingCycle string            `json:"billing_cycle"`
	TrialDays    int               `json:"trial_days,omitempty"`
	IsActive     bool              `json:"is_active"`
	DisplayOrder int               `json:"display_order,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type updatePlanRequest struct {
	Name         string            `json:"name,omitempty"`
	Slug         string            `json:"slug,omitempty"`
	Description  string            `json:"description,omitempty"`
	Price        *int64            `json:"price,omitempty"`
	Currency     string            `json:"currency,omitempty"`
	BillingCycle string            `json:"billing_cycle,omitempty"`
	TrialDays    *int              `json:"trial_days,omitempty"`
	IsActive     *bool             `json:"is_active,omitempty"`
	DisplayOrder *int              `json:"display_order,omitempty"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type createFeatureRequest struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
}

type updateFeatureRequest struct {
	Name        string `json:"name,omitempty"`
	Slug        string `json:"slug,omitempty"`
	Description string `json:"description,omitempty"`
	Category    string `json:"category,omitempty"`
}

type createFeatureScopeRequest struct {
	Name       string            `json:"name"`
	Slug       string            `json:"slug"`
	Permission string            `json:"permission"`
	Limit      int               `json:"limit,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type updateFeatureScopeRequest struct {
	Name       string            `json:"name,omitempty"`
	Slug       string            `json:"slug,omitempty"`
	Permission string            `json:"permission,omitempty"`
	Limit      *int              `json:"limit,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

type createPlanFeatureRequest struct {
	FeatureID      string                   `json:"feature_id"`
	Enabled        bool                     `json:"enabled"`
	ScopeOverrides map[string]ScopeOverride `json:"scope_overrides,omitempty"`
}

type updatePlanFeatureRequest struct {
	Enabled        *bool                    `json:"enabled,omitempty"`
	ScopeOverrides map[string]ScopeOverride `json:"scope_overrides,omitempty"`
}

// ==================== Product Handlers ====================

func (s *Server) handleProducts(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	switch r.Method {
	case http.MethodGet:
		products, err := s.lm.storage.ListProducts(r.Context())
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if products == nil {
			products = []*Product{}
		}
		s.respondJSON(w, http.StatusOK, products)

	case http.MethodPost:
		var req createProductRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		name := strings.TrimSpace(req.Name)
		slug := strings.TrimSpace(req.Slug)
		if name == "" || slug == "" {
			s.respondError(w, http.StatusBadRequest, "name and slug are required")
			return
		}
		now := time.Now()
		product := &Product{
			ID:          uuid.New().String(),
			Name:        name,
			Slug:        slug,
			Description: strings.TrimSpace(req.Description),
			LogoURL:     strings.TrimSpace(req.LogoURL),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := s.lm.storage.SaveProduct(r.Context(), product); err != nil {
			if strings.Contains(err.Error(), "already exists") {
				s.respondError(w, http.StatusConflict, "product already exists")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusCreated, product)

	default:
		http.NotFound(w, r)
	}
}

func (s *Server) handleProductActions(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	// Parse URL: /api/products/{id}[/plans|/features]
	path := strings.TrimPrefix(r.URL.Path, "/api/products/")
	parts := strings.SplitN(path, "/", 2)
	productID := parts[0]

	if productID == "" {
		s.respondError(w, http.StatusBadRequest, "product ID required")
		return
	}

	// Check if there's a sub-resource
	if len(parts) > 1 {
		subResource := parts[1]
		switch {
		case strings.HasPrefix(subResource, "plans"):
			s.handleProductPlans(w, r, productID, strings.TrimPrefix(subResource, "plans"))
			return
		case strings.HasPrefix(subResource, "features"):
			s.handleProductFeatures(w, r, productID, strings.TrimPrefix(subResource, "features"))
			return
		}
	}

	// Direct product operations
	switch r.Method {
	case http.MethodGet:
		product, err := s.lm.storage.GetProduct(r.Context(), productID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "product not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, product)

	case http.MethodPut:
		var req updateProductRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		product, err := s.lm.storage.GetProduct(r.Context(), productID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "product not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if name := strings.TrimSpace(req.Name); name != "" {
			product.Name = name
		}
		if slug := strings.TrimSpace(req.Slug); slug != "" {
			product.Slug = slug
		}
		if req.Description != "" {
			product.Description = strings.TrimSpace(req.Description)
		}
		if req.LogoURL != "" {
			product.LogoURL = strings.TrimSpace(req.LogoURL)
		}
		product.UpdatedAt = time.Now()
		if err := s.lm.storage.UpdateProduct(r.Context(), product); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, product)

	case http.MethodDelete:
		if err := s.lm.storage.DeleteProduct(r.Context(), productID); err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "product not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "product deleted"})

	default:
		http.NotFound(w, r)
	}
}

// ==================== Plan Handlers ====================

func (s *Server) handleProductPlans(w http.ResponseWriter, r *http.Request, productID, subPath string) {
	// subPath could be "", "/{planID}", "/{planID}/features", "/{planID}/features/{featureID}"
	subPath = strings.TrimPrefix(subPath, "/")
	parts := strings.SplitN(subPath, "/", 2)
	planID := parts[0]

	if planID == "" {
		// /api/products/{productID}/plans
		switch r.Method {
		case http.MethodGet:
			plans, err := s.lm.storage.ListPlansByProduct(r.Context(), productID)
			if err != nil {
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if plans == nil {
				plans = []*Plan{}
			}
			s.respondJSON(w, http.StatusOK, plans)

		case http.MethodPost:
			var req createPlanRequest
			if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
				return
			}
			name := strings.TrimSpace(req.Name)
			slug := strings.TrimSpace(req.Slug)
			if name == "" || slug == "" {
				s.respondError(w, http.StatusBadRequest, "name and slug are required")
				return
			}
			currency := strings.TrimSpace(req.Currency)
			if currency == "" {
				currency = "USD"
			}
			billingCycle := strings.TrimSpace(req.BillingCycle)
			if billingCycle == "" {
				billingCycle = "monthly"
			}
			now := time.Now()
			plan := &Plan{
				ID:           uuid.New().String(),
				ProductID:    productID,
				Name:         name,
				Slug:         slug,
				Description:  strings.TrimSpace(req.Description),
				Price:        req.Price,
				Currency:     currency,
				BillingCycle: billingCycle,
				TrialDays:    req.TrialDays,
				IsActive:     req.IsActive,
				DisplayOrder: req.DisplayOrder,
				Metadata:     req.Metadata,
				CreatedAt:    now,
				UpdatedAt:    now,
			}
			if err := s.lm.storage.SavePlan(r.Context(), plan); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					s.respondError(w, http.StatusConflict, "plan already exists")
					return
				}
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.respondJSON(w, http.StatusCreated, plan)

		default:
			http.NotFound(w, r)
		}
		return
	}

	// Check for plan features sub-resource
	if len(parts) > 1 && strings.HasPrefix(parts[1], "features") {
		s.handlePlanFeatures(w, r, planID, strings.TrimPrefix(parts[1], "features"))
		return
	}

	// /api/products/{productID}/plans/{planID}
	switch r.Method {
	case http.MethodGet:
		plan, err := s.lm.storage.GetPlan(r.Context(), planID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "plan not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, plan)

	case http.MethodPut:
		var req updatePlanRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		plan, err := s.lm.storage.GetPlan(r.Context(), planID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "plan not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if name := strings.TrimSpace(req.Name); name != "" {
			plan.Name = name
		}
		if slug := strings.TrimSpace(req.Slug); slug != "" {
			plan.Slug = slug
		}
		if req.Description != "" {
			plan.Description = strings.TrimSpace(req.Description)
		}
		if req.Price != nil {
			plan.Price = *req.Price
		}
		if currency := strings.TrimSpace(req.Currency); currency != "" {
			plan.Currency = currency
		}
		if billingCycle := strings.TrimSpace(req.BillingCycle); billingCycle != "" {
			plan.BillingCycle = billingCycle
		}
		if req.TrialDays != nil {
			plan.TrialDays = *req.TrialDays
		}
		if req.IsActive != nil {
			plan.IsActive = *req.IsActive
		}
		if req.DisplayOrder != nil {
			plan.DisplayOrder = *req.DisplayOrder
		}
		if req.Metadata != nil {
			plan.Metadata = req.Metadata
		}
		plan.UpdatedAt = time.Now()
		if err := s.lm.storage.UpdatePlan(r.Context(), plan); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, plan)

	case http.MethodDelete:
		if err := s.lm.storage.DeletePlan(r.Context(), planID); err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "plan not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "plan deleted"})

	default:
		http.NotFound(w, r)
	}
}

// ==================== Feature Handlers ====================

func (s *Server) handleProductFeatures(w http.ResponseWriter, r *http.Request, productID, subPath string) {
	subPath = strings.TrimPrefix(subPath, "/")
	parts := strings.SplitN(subPath, "/", 2)
	featureID := parts[0]

	if featureID == "" {
		// /api/products/{productID}/features
		switch r.Method {
		case http.MethodGet:
			features, err := s.lm.storage.ListFeaturesByProduct(r.Context(), productID)
			if err != nil {
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if features == nil {
				features = []*Feature{}
			}
			s.respondJSON(w, http.StatusOK, features)

		case http.MethodPost:
			var req createFeatureRequest
			if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
				return
			}
			name := strings.TrimSpace(req.Name)
			slug := strings.TrimSpace(req.Slug)
			if name == "" || slug == "" {
				s.respondError(w, http.StatusBadRequest, "name and slug are required")
				return
			}
			now := time.Now()
			feature := &Feature{
				ID:          uuid.New().String(),
				ProductID:   productID,
				Name:        name,
				Slug:        slug,
				Description: strings.TrimSpace(req.Description),
				Category:    strings.TrimSpace(req.Category),
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if err := s.lm.storage.SaveFeature(r.Context(), feature); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					s.respondError(w, http.StatusConflict, "feature already exists")
					return
				}
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.respondJSON(w, http.StatusCreated, feature)

		default:
			http.NotFound(w, r)
		}
		return
	}

	// Check for scopes sub-resource
	if len(parts) > 1 && strings.HasPrefix(parts[1], "scopes") {
		s.handleFeatureScopes(w, r, featureID, strings.TrimPrefix(parts[1], "scopes"))
		return
	}

	// /api/products/{productID}/features/{featureID}
	switch r.Method {
	case http.MethodGet:
		feature, err := s.lm.storage.GetFeature(r.Context(), featureID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "feature not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, feature)

	case http.MethodPut:
		var req updateFeatureRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		feature, err := s.lm.storage.GetFeature(r.Context(), featureID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "feature not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if name := strings.TrimSpace(req.Name); name != "" {
			feature.Name = name
		}
		if slug := strings.TrimSpace(req.Slug); slug != "" {
			feature.Slug = slug
		}
		if req.Description != "" {
			feature.Description = strings.TrimSpace(req.Description)
		}
		if req.Category != "" {
			feature.Category = strings.TrimSpace(req.Category)
		}
		feature.UpdatedAt = time.Now()
		if err := s.lm.storage.UpdateFeature(r.Context(), feature); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, feature)

	case http.MethodDelete:
		if err := s.lm.storage.DeleteFeature(r.Context(), featureID); err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "feature not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "feature deleted"})

	default:
		http.NotFound(w, r)
	}
}

// ==================== Feature Scope Handlers ====================

func (s *Server) handleFeatureScopes(w http.ResponseWriter, r *http.Request, featureID, subPath string) {
	subPath = strings.TrimPrefix(subPath, "/")
	scopeID := subPath

	if scopeID == "" {
		// /api/products/{productID}/features/{featureID}/scopes
		switch r.Method {
		case http.MethodGet:
			scopes, err := s.lm.storage.ListFeatureScopes(r.Context(), featureID)
			if err != nil {
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if scopes == nil {
				scopes = []*FeatureScope{}
			}
			s.respondJSON(w, http.StatusOK, scopes)

		case http.MethodPost:
			var req createFeatureScopeRequest
			if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
				return
			}
			name := strings.TrimSpace(req.Name)
			slug := strings.TrimSpace(req.Slug)
			permission := strings.TrimSpace(req.Permission)
			if name == "" || slug == "" {
				s.respondError(w, http.StatusBadRequest, "name and slug are required")
				return
			}
			if permission == "" {
				permission = string(ScopePermissionAllow)
			}
			now := time.Now()
			scope := &FeatureScope{
				ID:         uuid.New().String(),
				FeatureID:  featureID,
				Name:       name,
				Slug:       slug,
				Permission: ScopePermission(permission),
				Limit:      req.Limit,
				Metadata:   req.Metadata,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if err := s.lm.storage.SaveFeatureScope(r.Context(), scope); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					s.respondError(w, http.StatusConflict, "scope already exists")
					return
				}
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.respondJSON(w, http.StatusCreated, scope)

		default:
			http.NotFound(w, r)
		}
		return
	}

	// /api/products/{productID}/features/{featureID}/scopes/{scopeID}
	switch r.Method {
	case http.MethodGet:
		scope, err := s.lm.storage.GetFeatureScope(r.Context(), scopeID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "scope not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, scope)

	case http.MethodPut:
		var req updateFeatureScopeRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		scope, err := s.lm.storage.GetFeatureScope(r.Context(), scopeID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "scope not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if name := strings.TrimSpace(req.Name); name != "" {
			scope.Name = name
		}
		if slug := strings.TrimSpace(req.Slug); slug != "" {
			scope.Slug = slug
		}
		if permission := strings.TrimSpace(req.Permission); permission != "" {
			scope.Permission = ScopePermission(permission)
		}
		if req.Limit != nil {
			scope.Limit = *req.Limit
		}
		if req.Metadata != nil {
			scope.Metadata = req.Metadata
		}
		scope.UpdatedAt = time.Now()
		if err := s.lm.storage.UpdateFeatureScope(r.Context(), scope); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, scope)

	case http.MethodDelete:
		if err := s.lm.storage.DeleteFeatureScope(r.Context(), scopeID); err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "scope not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "scope deleted"})

	default:
		http.NotFound(w, r)
	}
}

// ==================== Plan Feature Handlers ====================

func (s *Server) handlePlanFeatures(w http.ResponseWriter, r *http.Request, planID, subPath string) {
	subPath = strings.TrimPrefix(subPath, "/")
	featureID := subPath

	if featureID == "" {
		// /api/products/{productID}/plans/{planID}/features
		switch r.Method {
		case http.MethodGet:
			planFeatures, err := s.lm.storage.ListPlanFeatures(r.Context(), planID)
			if err != nil {
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			if planFeatures == nil {
				planFeatures = []*PlanFeature{}
			}
			s.respondJSON(w, http.StatusOK, planFeatures)

		case http.MethodPost:
			var req createPlanFeatureRequest
			if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
				return
			}
			featureID := strings.TrimSpace(req.FeatureID)
			if featureID == "" {
				s.respondError(w, http.StatusBadRequest, "feature_id is required")
				return
			}
			now := time.Now()
			planFeature := &PlanFeature{
				ID:             uuid.New().String(),
				PlanID:         planID,
				FeatureID:      featureID,
				Enabled:        req.Enabled,
				ScopeOverrides: req.ScopeOverrides,
				CreatedAt:      now,
				UpdatedAt:      now,
			}
			if err := s.lm.storage.SavePlanFeature(r.Context(), planFeature); err != nil {
				if strings.Contains(err.Error(), "already exists") {
					s.respondError(w, http.StatusConflict, "plan feature already exists")
					return
				}
				s.respondError(w, http.StatusInternalServerError, err.Error())
				return
			}
			s.respondJSON(w, http.StatusCreated, planFeature)

		default:
			http.NotFound(w, r)
		}
		return
	}

	// /api/products/{productID}/plans/{planID}/features/{featureID}
	switch r.Method {
	case http.MethodGet:
		planFeature, err := s.lm.storage.GetPlanFeature(r.Context(), planID, featureID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "plan feature not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, planFeature)

	case http.MethodPut:
		var req updatePlanFeatureRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		planFeature, err := s.lm.storage.GetPlanFeature(r.Context(), planID, featureID)
		if err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "plan feature not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if req.Enabled != nil {
			planFeature.Enabled = *req.Enabled
		}
		if req.ScopeOverrides != nil {
			planFeature.ScopeOverrides = req.ScopeOverrides
		}
		planFeature.UpdatedAt = time.Now()
		if err := s.lm.storage.UpdatePlanFeature(r.Context(), planFeature); err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, planFeature)

	case http.MethodDelete:
		if err := s.lm.storage.DeletePlanFeature(r.Context(), planID, featureID); err != nil {
			if strings.Contains(err.Error(), "not found") {
				s.respondError(w, http.StatusNotFound, "plan feature not found")
				return
			}
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, map[string]string{"message": "plan feature deleted"})

	default:
		http.NotFound(w, r)
	}
}

// ==================== Entitlements Handler ====================

func (s *Server) handleEntitlements(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}

	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}

	productID := r.URL.Query().Get("product_id")
	planID := r.URL.Query().Get("plan_id")

	if productID == "" || planID == "" {
		s.respondError(w, http.StatusBadRequest, "product_id and plan_id are required")
		return
	}

	entitlements, err := s.lm.storage.ComputeLicenseEntitlements(r.Context(), productID, planID)
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	s.respondJSON(w, http.StatusOK, entitlements)
}
