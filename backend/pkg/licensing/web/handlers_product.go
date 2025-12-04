package web

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/licensing/pkg/licensing"
)

func (ws *WebServer) handleAPIProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	switch r.Method {
	case http.MethodGet:
		products, err := ws.lm.Storage().ListProducts(ctx)
		if err != nil {
			ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
			return
		}
		sort.Slice(products, func(i, j int) bool {
			return products[i].CreatedAt.After(products[j].CreatedAt)
		})
		ws.respondJSON(w, http.StatusOK, products)
	case http.MethodPost:
		var req struct {
			Name        string `json:"name"`
			Slug        string `json:"slug"`
			Description string `json:"description"`
			LogoURL     string `json:"logo_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Slug) == "" {
			ws.respondAPIError(w, http.StatusBadRequest, "name and slug are required")
			return
		}
		now := time.Now()
		product := &licensing.Product{
			ID:          uuid.New().String(),
			Name:        strings.TrimSpace(req.Name),
			Slug:        strings.TrimSpace(req.Slug),
			Description: strings.TrimSpace(req.Description),
			LogoURL:     strings.TrimSpace(req.LogoURL),
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := ws.lm.Storage().SaveProduct(ctx, product); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusCreated, product)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIProductRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/products/")
	if path == "" || path == r.URL.Path {
		ws.respondAPIError(w, http.StatusNotFound, "Product ID is required")
		return
	}
	segments := strings.Split(path, "/")
	productID := strings.TrimSpace(segments[0])
	if productID == "" {
		ws.respondAPIError(w, http.StatusNotFound, "Product ID is required")
		return
	}

	if len(segments) == 1 {
		ws.handleAPIProductDetail(w, r, productID)
		return
	}

	switch segments[1] {
	case "stats":
		ws.handleAPIProductStats(w, r, productID)
	case "plans":
		ws.handleAPIProductPlans(w, r, productID, segments[2:])
	case "features":
		ws.handleAPIProductFeatures(w, r, productID, segments[2:])
	default:
		ws.respondAPIError(w, http.StatusNotFound, "Invalid product endpoint")
	}
}

func (ws *WebServer) handleAPIProductDetail(w http.ResponseWriter, r *http.Request, productID string) {
	ctx := r.Context()
	product, err := ws.lm.Storage().GetProduct(ctx, productID)
	if err != nil {
		ws.respondAPIError(w, http.StatusNotFound, "Product not found")
		return
	}

	switch r.Method {
	case http.MethodGet:
		ws.respondJSON(w, http.StatusOK, product)
	case http.MethodPut:
		var req struct {
			Name        string `json:"name"`
			Slug        string `json:"slug"`
			Description string `json:"description"`
			LogoURL     string `json:"logo_url"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.TrimSpace(req.Name) != "" {
			product.Name = strings.TrimSpace(req.Name)
		}
		if strings.TrimSpace(req.Slug) != "" {
			product.Slug = strings.TrimSpace(req.Slug)
		}
		product.Description = strings.TrimSpace(req.Description)
		product.LogoURL = strings.TrimSpace(req.LogoURL)
		product.UpdatedAt = time.Now()
		if err := ws.lm.Storage().UpdateProduct(ctx, product); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, product)
	case http.MethodDelete:
		if err := ws.lm.Storage().DeleteProduct(ctx, productID); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIProductStats(w http.ResponseWriter, r *http.Request, productID string) {
	if r.Method != http.MethodGet {
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		return
	}
	ctx := r.Context()
	plans, _ := ws.lm.Storage().ListPlansByProduct(ctx, productID)
	features, _ := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)
	stats := map[string]int{
		"plans":    len(plans),
		"features": len(features),
	}
	ws.respondJSON(w, http.StatusOK, stats)
}

func (ws *WebServer) handleAPIProductPlans(w http.ResponseWriter, r *http.Request, productID string, segments []string) {
	ctx := r.Context()
	if len(segments) == 0 || segments[0] == "" {
		switch r.Method {
		case http.MethodGet:
			plans, err := ws.lm.Storage().ListPlansByProduct(ctx, productID)
			if err != nil {
				ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			sort.Slice(plans, func(i, j int) bool {
				if plans[i].DisplayOrder == plans[j].DisplayOrder {
					return plans[i].CreatedAt.After(plans[j].CreatedAt)
				}
				return plans[i].DisplayOrder < plans[j].DisplayOrder
			})
			ws.respondJSON(w, http.StatusOK, plans)
		case http.MethodPost:
			ws.createPlan(w, r, ctx, productID)
		default:
			ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}
	planID := segments[0]
	ws.handleAPIPlanDetail(w, r, productID, planID, segments[1:])
}

func (ws *WebServer) createPlan(w http.ResponseWriter, r *http.Request, ctx context.Context, productID string) {
	var req struct {
		Name           string            `json:"name"`
		Slug           string            `json:"slug"`
		Description    string            `json:"description"`
		Price          int64             `json:"price"`
		MinDevices     int               `json:"min_devices"`
		MaxDevices     int               `json:"max_devices"`
		DurationDays   int               `json:"duration_days"`
		PricePerDevice int64             `json:"price_per_device"`
		Currency       string            `json:"currency"`
		BillingCycle   string            `json:"billing_cycle"`
		TrialDays      int               `json:"trial_days"`
		IsTrial        bool              `json:"is_trial"`
		IsActive       bool              `json:"is_active"`
		DisplayOrder   int               `json:"display_order"`
		Metadata       map[string]string `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Slug) == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "name and slug are required")
		return
	}
	if req.Currency == "" {
		req.Currency = "USD"
	}
	if req.BillingCycle == "" {
		req.BillingCycle = "monthly"
	}
	if req.MinDevices < 0 {
		req.MinDevices = 0
	}
	if req.MaxDevices < 0 {
		req.MaxDevices = 0
	}
	if req.IsTrial {
		if existing, _ := ws.lm.Storage().GetTrialPlanForProduct(ctx, productID); existing != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "A trial plan already exists for this product")
			return
		}
	}
	now := time.Now()
	plan := &licensing.Plan{
		ID:             uuid.New().String(),
		ProductID:      productID,
		Name:           strings.TrimSpace(req.Name),
		Slug:           strings.TrimSpace(req.Slug),
		Description:    strings.TrimSpace(req.Description),
		Price:          req.Price,
		MinDevices:     req.MinDevices,
		MaxDevices:     req.MaxDevices,
		DurationDays:   req.DurationDays,
		PricePerDevice: req.PricePerDevice,
		Currency:       strings.ToUpper(req.Currency),
		BillingCycle:   strings.TrimSpace(req.BillingCycle),
		TrialDays:      req.TrialDays,
		IsTrial:        req.IsTrial,
		IsActive:       req.IsActive,
		DisplayOrder:   req.DisplayOrder,
		Metadata:       req.Metadata,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := ws.lm.Storage().SavePlan(ctx, plan); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	if plan.IsTrial {
		ws.seedTrialPlanFeatures(ctx, plan)
	}
	ws.respondJSON(w, http.StatusCreated, plan)
}

func (ws *WebServer) handleAPIPlanDetail(w http.ResponseWriter, r *http.Request, productID, planID string, segments []string) {
	ctx := r.Context()
	plan, err := ws.lm.Storage().GetPlan(ctx, planID)
	if err != nil || plan.ProductID != productID {
		ws.respondAPIError(w, http.StatusNotFound, "Plan not found")
		return
	}
	if len(segments) > 0 && segments[0] != "" {
		switch segments[0] {
		case "features":
			ws.handleAPIPlanFeatures(w, r, productID, planID, segments[1:])
		default:
			ws.respondAPIError(w, http.StatusNotFound, "Invalid plan endpoint")
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		ws.respondJSON(w, http.StatusOK, plan)
	case http.MethodPut:
		var req struct {
			Name           string            `json:"name"`
			Slug           string            `json:"slug"`
			Description    string            `json:"description"`
			Price          *int64            `json:"price"`
			MinDevices     *int              `json:"min_devices"`
			MaxDevices     *int              `json:"max_devices"`
			DurationDays   *int              `json:"duration_days"`
			PricePerDevice *int64            `json:"price_per_device"`
			Currency       string            `json:"currency"`
			BillingCycle   string            `json:"billing_cycle"`
			TrialDays      *int              `json:"trial_days"`
			IsTrial        *bool             `json:"is_trial"`
			IsActive       *bool             `json:"is_active"`
			DisplayOrder   *int              `json:"display_order"`
			Metadata       map[string]string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.TrimSpace(req.Name) != "" {
			plan.Name = strings.TrimSpace(req.Name)
		}
		if strings.TrimSpace(req.Slug) != "" {
			plan.Slug = strings.TrimSpace(req.Slug)
		}
		if req.Price != nil {
			plan.Price = *req.Price
		}
		if req.MinDevices != nil {
			plan.MinDevices = *req.MinDevices
		}
		if req.MaxDevices != nil {
			plan.MaxDevices = *req.MaxDevices
		}
		if req.DurationDays != nil {
			plan.DurationDays = *req.DurationDays
		}
		if req.PricePerDevice != nil {
			plan.PricePerDevice = *req.PricePerDevice
		}
		if strings.TrimSpace(req.Currency) != "" {
			plan.Currency = strings.ToUpper(strings.TrimSpace(req.Currency))
		}
		if strings.TrimSpace(req.BillingCycle) != "" {
			plan.BillingCycle = strings.TrimSpace(req.BillingCycle)
		}
		if req.TrialDays != nil {
			plan.TrialDays = *req.TrialDays
		}
		if req.IsTrial != nil {
			plan.IsTrial = *req.IsTrial
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
		plan.Description = strings.TrimSpace(req.Description)
		plan.UpdatedAt = time.Now()
		if err := ws.lm.Storage().UpdatePlan(ctx, plan); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, plan)
	case http.MethodDelete:
		if err := ws.lm.Storage().DeletePlan(ctx, planID); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIPlanFeatures(w http.ResponseWriter, r *http.Request, productID, planID string, segments []string) {
	ctx := r.Context()
	if len(segments) == 0 || segments[0] == "" {
		switch r.Method {
		case http.MethodGet:
			ws.listPlanFeatures(w, ctx, productID, planID)
		case http.MethodPost:
			ws.addPlanFeature(w, r, ctx, productID, planID)
		default:
			ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}
	featureID := segments[0]
	ws.handleAPIPlanFeatureDetail(w, r, ctx, planID, featureID)
}

type planFeatureResponse struct {
	*licensing.PlanFeature
	Feature *licensing.Feature        `json:"feature,omitempty"`
	Scopes  []*licensing.FeatureScope `json:"scopes,omitempty"`
}

func (ws *WebServer) listPlanFeatures(w http.ResponseWriter, ctx context.Context, productID, planID string) {
	features, err := ws.lm.Storage().ListPlanFeatures(ctx, planID)
	if err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	productFeatures, err := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)
	if err != nil {
		ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
		return
	}
	featureMap := make(map[string]*licensing.Feature)
	for _, f := range productFeatures {
		featureMap[f.ID] = f
	}
	resp := make([]planFeatureResponse, 0, len(features))
	for _, pf := range features {
		item := planFeatureResponse{PlanFeature: pf}
		if feature, ok := featureMap[pf.FeatureID]; ok {
			item.Feature = feature
		}
		scopes, err := ws.lm.Storage().ListFeatureScopes(ctx, pf.FeatureID)
		if err == nil {
			item.Scopes = scopes
		}
		resp = append(resp, item)
	}
	ws.respondJSON(w, http.StatusOK, resp)
}

func (ws *WebServer) addPlanFeature(w http.ResponseWriter, r *http.Request, ctx context.Context, productID, planID string) {
	var req struct {
		FeatureID      string                             `json:"feature_id"`
		Enabled        bool                               `json:"enabled"`
		ScopeOverrides map[string]licensing.ScopeOverride `json:"scope_overrides"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if strings.TrimSpace(req.FeatureID) == "" {
		ws.respondAPIError(w, http.StatusBadRequest, "feature_id is required")
		return
	}
	feature, err := ws.lm.Storage().GetFeature(ctx, req.FeatureID)
	if err != nil || feature.ProductID != productID {
		ws.respondAPIError(w, http.StatusBadRequest, "Feature not found for product")
		return
	}
	now := time.Now()
	pf := &licensing.PlanFeature{
		ID:             uuid.New().String(),
		PlanID:         planID,
		FeatureID:      req.FeatureID,
		Enabled:        req.Enabled,
		ScopeOverrides: req.ScopeOverrides,
		CreatedAt:      now,
		UpdatedAt:      now,
	}
	if err := ws.lm.Storage().SavePlanFeature(ctx, pf); err != nil {
		ws.respondAPIError(w, http.StatusBadRequest, err.Error())
		return
	}
	ws.respondJSON(w, http.StatusCreated, pf)
}

func (ws *WebServer) handleAPIPlanFeatureDetail(w http.ResponseWriter, r *http.Request, ctx context.Context, planID, featureID string) {
	switch r.Method {
	case http.MethodGet:
		pf, err := ws.lm.Storage().GetPlanFeature(ctx, planID, featureID)
		if err != nil {
			ws.respondAPIError(w, http.StatusNotFound, "Plan feature not found")
			return
		}
		ws.respondJSON(w, http.StatusOK, pf)
	case http.MethodPut:
		pf, err := ws.lm.Storage().GetPlanFeature(ctx, planID, featureID)
		if err != nil {
			ws.respondAPIError(w, http.StatusNotFound, "Plan feature not found")
			return
		}
		var req struct {
			Enabled        *bool                              `json:"enabled"`
			ScopeOverrides map[string]licensing.ScopeOverride `json:"scope_overrides"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if req.Enabled != nil {
			pf.Enabled = *req.Enabled
		}
		if req.ScopeOverrides != nil {
			pf.ScopeOverrides = req.ScopeOverrides
		}
		pf.UpdatedAt = time.Now()
		if err := ws.lm.Storage().UpdatePlanFeature(ctx, pf); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, pf)
	case http.MethodDelete:
		if err := ws.lm.Storage().DeletePlanFeature(ctx, planID, featureID); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIProductFeatures(w http.ResponseWriter, r *http.Request, productID string, segments []string) {
	ctx := r.Context()
	if len(segments) == 0 || segments[0] == "" {
		switch r.Method {
		case http.MethodGet:
			features, err := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)
			if err != nil {
				ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			sort.Slice(features, func(i, j int) bool {
				return features[i].CreatedAt.After(features[j].CreatedAt)
			})
			ws.respondJSON(w, http.StatusOK, features)
		case http.MethodPost:
			var req struct {
				Name        string `json:"name"`
				Slug        string `json:"slug"`
				Description string `json:"description"`
				Category    string `json:"category"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
				return
			}
			if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Slug) == "" {
				ws.respondAPIError(w, http.StatusBadRequest, "name and slug are required")
				return
			}
			now := time.Now()
			feature := &licensing.Feature{
				ID:          uuid.New().String(),
				ProductID:   productID,
				Name:        strings.TrimSpace(req.Name),
				Slug:        strings.TrimSpace(req.Slug),
				Description: strings.TrimSpace(req.Description),
				Category:    strings.TrimSpace(req.Category),
				CreatedAt:   now,
				UpdatedAt:   now,
			}
			if err := ws.lm.Storage().SaveFeature(ctx, feature); err != nil {
				ws.respondAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			ws.respondJSON(w, http.StatusCreated, feature)
		default:
			ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}
	featureID := segments[0]
	ws.handleAPIProductFeatureDetail(w, r, productID, featureID, segments[1:])
}

func (ws *WebServer) handleAPIProductFeatureDetail(w http.ResponseWriter, r *http.Request, productID, featureID string, segments []string) {
	ctx := r.Context()
	feature, err := ws.lm.Storage().GetFeature(ctx, featureID)
	if err != nil || feature.ProductID != productID {
		ws.respondAPIError(w, http.StatusNotFound, "Feature not found")
		return
	}
	if len(segments) > 0 && segments[0] != "" {
		switch segments[0] {
		case "scopes":
			ws.handleAPIProductFeatureScopes(w, r, featureID, segments[1:])
		default:
			ws.respondAPIError(w, http.StatusNotFound, "Invalid feature endpoint")
		}
		return
	}
	switch r.Method {
	case http.MethodGet:
		ws.respondJSON(w, http.StatusOK, feature)
	case http.MethodPut:
		var req struct {
			Name        string `json:"name"`
			Slug        string `json:"slug"`
			Description string `json:"description"`
			Category    string `json:"category"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.TrimSpace(req.Name) != "" {
			feature.Name = strings.TrimSpace(req.Name)
		}
		if strings.TrimSpace(req.Slug) != "" {
			feature.Slug = strings.TrimSpace(req.Slug)
		}
		feature.Description = strings.TrimSpace(req.Description)
		feature.Category = strings.TrimSpace(req.Category)
		feature.UpdatedAt = time.Now()
		if err := ws.lm.Storage().UpdateFeature(ctx, feature); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, feature)
	case http.MethodDelete:
		if err := ws.lm.Storage().DeleteFeature(ctx, featureID); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) handleAPIProductFeatureScopes(w http.ResponseWriter, r *http.Request, featureID string, segments []string) {
	ctx := r.Context()
	if len(segments) == 0 || segments[0] == "" {
		switch r.Method {
		case http.MethodGet:
			scopes, err := ws.lm.Storage().ListFeatureScopes(ctx, featureID)
			if err != nil {
				ws.respondAPIError(w, http.StatusInternalServerError, err.Error())
				return
			}
			ws.respondJSON(w, http.StatusOK, scopes)
		case http.MethodPost:
			var req struct {
				Name       string            `json:"name"`
				Slug       string            `json:"slug"`
				Permission string            `json:"permission"`
				Limit      int               `json:"limit"`
				Metadata   map[string]string `json:"metadata"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
				return
			}
			if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Slug) == "" {
				ws.respondAPIError(w, http.StatusBadRequest, "name and slug are required")
				return
			}
			now := time.Now()
			scope := &licensing.FeatureScope{
				ID:         uuid.New().String(),
				FeatureID:  featureID,
				Name:       strings.TrimSpace(req.Name),
				Slug:       strings.TrimSpace(req.Slug),
				Permission: licensing.ScopePermission(strings.TrimSpace(req.Permission)),
				Limit:      req.Limit,
				Metadata:   req.Metadata,
				CreatedAt:  now,
				UpdatedAt:  now,
			}
			if scope.Permission == "" {
				scope.Permission = licensing.ScopePermissionAllow
			}
			if err := ws.lm.Storage().SaveFeatureScope(ctx, scope); err != nil {
				ws.respondAPIError(w, http.StatusBadRequest, err.Error())
				return
			}
			ws.respondJSON(w, http.StatusCreated, scope)
		default:
			ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
		}
		return
	}
	scopeID := segments[0]
	ws.handleAPIProductFeatureScopeDetail(w, r, featureID, scopeID)
}

func (ws *WebServer) handleAPIProductFeatureScopeDetail(w http.ResponseWriter, r *http.Request, featureID, scopeID string) {
	ctx := r.Context()
	scope, err := ws.lm.Storage().GetFeatureScope(ctx, scopeID)
	if err != nil || scope.FeatureID != featureID {
		ws.respondAPIError(w, http.StatusNotFound, "Scope not found")
		return
	}
	switch r.Method {
	case http.MethodGet:
		ws.respondJSON(w, http.StatusOK, scope)
	case http.MethodPut:
		var req struct {
			Name       string            `json:"name"`
			Slug       string            `json:"slug"`
			Permission string            `json:"permission"`
			Limit      *int              `json:"limit"`
			Metadata   map[string]string `json:"metadata"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, "Invalid request body")
			return
		}
		if strings.TrimSpace(req.Name) != "" {
			scope.Name = strings.TrimSpace(req.Name)
		}
		if strings.TrimSpace(req.Slug) != "" {
			scope.Slug = strings.TrimSpace(req.Slug)
		}
		if strings.TrimSpace(req.Permission) != "" {
			scope.Permission = licensing.ScopePermission(strings.TrimSpace(req.Permission))
		}
		if req.Limit != nil {
			scope.Limit = *req.Limit
		}
		if req.Metadata != nil {
			scope.Metadata = req.Metadata
		}
		scope.UpdatedAt = time.Now()
		if err := ws.lm.Storage().UpdateFeatureScope(ctx, scope); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		ws.respondJSON(w, http.StatusOK, scope)
	case http.MethodDelete:
		if err := ws.lm.Storage().DeleteFeatureScope(ctx, scopeID); err != nil {
			ws.respondAPIError(w, http.StatusBadRequest, err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		ws.respondAPIError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (ws *WebServer) seedTrialPlanFeatures(ctx context.Context, plan *licensing.Plan) {
	features, err := ws.lm.Storage().ListFeaturesByProduct(ctx, plan.ProductID)
	if err != nil {
		log.Printf("failed to list features for trial plan: %v", err)
		return
	}
	now := time.Now()
	for _, feature := range features {
		pf := &licensing.PlanFeature{
			ID:        uuid.New().String(),
			PlanID:    plan.ID,
			FeatureID: feature.ID,
			Enabled:   true,
			CreatedAt: now,
			UpdatedAt: now,
		}
		scopes, err := ws.lm.Storage().ListFeatureScopes(ctx, feature.ID)
		if err == nil && len(scopes) > 0 {
			overrides := make(map[string]licensing.ScopeOverride, len(scopes))
			for _, scope := range scopes {
				overrides[scope.Slug] = licensing.ScopeOverride{
					Permission: licensing.ScopePermissionAllow,
					Limit:      scope.Limit,
				}
			}
			pf.ScopeOverrides = overrides
		}
		if err := ws.lm.Storage().SavePlanFeature(ctx, pf); err != nil {
			log.Printf("failed to seed trial plan feature %s: %v", feature.ID, err)
		}
	}
}
