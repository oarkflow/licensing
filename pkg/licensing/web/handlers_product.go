package web

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/oarkflow/licensing/pkg/licensing"
)

// Product handlers

func (ws *WebServer) handleProducts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		action := r.FormValue("action")
		productID := r.FormValue("product_id")

		if action == "delete" {
			err := ws.lm.Storage().DeleteProduct(ctx, productID)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		http.Redirect(w, r, "/products", http.StatusSeeOther)
		return
	}

	products, err := ws.lm.Storage().ListProducts(ctx)
	if err != nil {
		ws.renderError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Sort by created date descending
	sort.Slice(products, func(i, j int) bool {
		return products[i].CreatedAt.After(products[j].CreatedAt)
	})

	// Get plan counts for each product
	productStats := make(map[string]map[string]int)
	for _, prod := range products {
		plans, _ := ws.lm.Storage().ListPlansByProduct(ctx, prod.ID)
		features, _ := ws.lm.Storage().ListFeaturesByProduct(ctx, prod.ID)
		productStats[prod.ID] = map[string]int{
			"plans":    len(plans),
			"features": len(features),
		}
	}

	data := map[string]interface{}{
		"Products":     products,
		"ProductStats": productStats,
	}

	ws.render(w, "products.html", TemplateData{
		Title:       "Products",
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleNewProduct(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		slug := strings.TrimSpace(r.FormValue("slug"))
		description := strings.TrimSpace(r.FormValue("description"))
		logoURL := strings.TrimSpace(r.FormValue("logo_url"))

		if name == "" || slug == "" {
			ws.render(w, "product_new.html", TemplateData{
				Title:       "New Product",
				CurrentPath: "/products",
				User:        ws.getSessionFromContext(r),
				Error:       "Name and slug are required",
			})
			return
		}

		now := time.Now()
		product := &licensing.Product{
			ID:          uuid.New().String(),
			Name:        name,
			Slug:        slug,
			Description: description,
			LogoURL:     logoURL,
			CreatedAt:   now,
			UpdatedAt:   now,
		}

		if err := ws.lm.Storage().SaveProduct(ctx, product); err != nil {
			ws.render(w, "product_new.html", TemplateData{
				Title:       "New Product",
				CurrentPath: "/products",
				User:        ws.getSessionFromContext(r),
				Error:       err.Error(),
			})
			return
		}

		http.Redirect(w, r, "/products/"+product.ID, http.StatusSeeOther)
		return
	}

	ws.render(w, "product_new.html", TemplateData{
		Title:       "New Product",
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
	})
}

func (ws *WebServer) handleProductDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	path := strings.TrimPrefix(r.URL.Path, "/products/")
	parts := strings.Split(path, "/")
	productID := parts[0]

	if productID == "" {
		http.NotFound(w, r)
		return
	}

	// Handle sub-resources
	if len(parts) > 1 {
		switch parts[1] {
		case "plans":
			ws.handleProductPlans(w, r, productID, parts[2:])
			return
		case "features":
			ws.handleProductFeatures(w, r, productID, parts[2:])
			return
		case "edit":
			ws.handleProductEdit(w, r, productID)
			return
		case "delete":
			if r.Method == http.MethodPost && ws.validateCSRF(r) {
				err := ws.lm.Storage().DeleteProduct(ctx, productID)
				if err != nil {
					ws.renderError(w, http.StatusBadRequest, err.Error())
					return
				}
				http.Redirect(w, r, "/products", http.StatusSeeOther)
				return
			}
		}
	}

	product, err := ws.lm.Storage().GetProduct(ctx, productID)
	if err != nil || product == nil {
		ws.renderError(w, http.StatusNotFound, "Product not found")
		return
	}

	plans, _ := ws.lm.Storage().ListPlansByProduct(ctx, productID)
	features, _ := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)

	data := map[string]interface{}{
		"Product":  product,
		"Plans":    plans,
		"Features": features,
	}

	ws.render(w, "product_detail.html", TemplateData{
		Title:       product.Name,
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleProductEdit(w http.ResponseWriter, r *http.Request, productID string) {
	ctx := r.Context()

	product, err := ws.lm.Storage().GetProduct(ctx, productID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Product not found")
		return
	}

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		slug := strings.TrimSpace(r.FormValue("slug"))
		description := strings.TrimSpace(r.FormValue("description"))
		logoURL := strings.TrimSpace(r.FormValue("logo_url"))

		if name != "" {
			product.Name = name
		}
		if slug != "" {
			product.Slug = slug
		}
		product.Description = description
		product.LogoURL = logoURL
		product.UpdatedAt = time.Now()

		if err := ws.lm.Storage().UpdateProduct(ctx, product); err != nil {
			ws.render(w, "product_edit.html", TemplateData{
				Title:       "Edit Product",
				CurrentPath: "/products",
				User:        ws.getSessionFromContext(r),
				Data:        map[string]interface{}{"Product": product},
				Error:       err.Error(),
			})
			return
		}

		http.Redirect(w, r, "/products/"+productID, http.StatusSeeOther)
		return
	}

	ws.render(w, "product_edit.html", TemplateData{
		Title:       "Edit Product",
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        map[string]interface{}{"Product": product},
	})
}

func (ws *WebServer) handleProductPlans(w http.ResponseWriter, r *http.Request, productID string, pathParts []string) {
	ctx := r.Context()

	product, err := ws.lm.Storage().GetProduct(ctx, productID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Product not found")
		return
	}

	// New plan
	if len(pathParts) == 0 || (len(pathParts) == 1 && pathParts[0] == "new") {
		if r.Method == http.MethodPost {
			if !ws.validateCSRF(r) {
				ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
				return
			}

			name := strings.TrimSpace(r.FormValue("name"))
			slug := strings.TrimSpace(r.FormValue("slug"))
			description := strings.TrimSpace(r.FormValue("description"))
			price := int64(parseInt(r.FormValue("price"), 0) * 100) // Convert dollars to cents
			currency := strings.TrimSpace(r.FormValue("currency"))
			billingCycle := strings.TrimSpace(r.FormValue("billing_cycle"))
			trialDays := parseInt(r.FormValue("trial_days"), 0)
			displayOrder := parseInt(r.FormValue("display_order"), 0)
			isActive := r.FormValue("is_active") == "on"
			isTrial := r.FormValue("is_trial") == "on"

			if name == "" || slug == "" {
				ws.renderError(w, http.StatusBadRequest, "Name and slug are required")
				return
			}

			// If this is a trial plan, check if product already has one
			if isTrial {
				existingTrialPlan, _ := ws.lm.Storage().GetTrialPlanForProduct(ctx, productID)
				if existingTrialPlan != nil {
					ws.renderError(w, http.StatusBadRequest, "This product already has a trial plan: "+existingTrialPlan.Name)
					return
				}
				// Trial plans must have price of 0 and trial days > 0
				price = 0
				if trialDays <= 0 {
					trialDays = 14 // Default to 14 days
				}
			}

			if currency == "" {
				currency = "USD"
			}
			if billingCycle == "" {
				billingCycle = "monthly"
			}

			now := time.Now()
			plan := &licensing.Plan{
				ID:           uuid.New().String(),
				ProductID:    productID,
				Name:         name,
				Slug:         slug,
				Description:  description,
				Price:        price,
				Currency:     currency,
				BillingCycle: billingCycle,
				TrialDays:    trialDays,
				IsTrial:      isTrial,
				DisplayOrder: displayOrder,
				IsActive:     isActive,
				CreatedAt:    now,
				UpdatedAt:    now,
			}

			if err := ws.lm.Storage().SavePlan(ctx, plan); err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}

			// If this is a trial plan, automatically assign all product features with all scopes
			if isTrial {
				allFeatures, _ := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)
				for _, feature := range allFeatures {
					// Create plan feature with all scopes enabled
					pf := &licensing.PlanFeature{
						ID:        uuid.New().String(),
						PlanID:    plan.ID,
						FeatureID: feature.ID,
						Enabled:   true,
						CreatedAt: now,
						UpdatedAt: now,
					}

					// Get all scopes for this feature and add them as overrides with "allow" permission
					scopes, _ := ws.lm.Storage().ListFeatureScopes(ctx, feature.ID)
					if len(scopes) > 0 {
						scopeOverrides := make(map[string]licensing.ScopeOverride)
						for _, scope := range scopes {
							scopeOverrides[scope.Slug] = licensing.ScopeOverride{
								Permission: licensing.ScopePermissionAllow,
								Limit:      scope.Limit,
							}
						}
						pf.ScopeOverrides = scopeOverrides
					}

					ws.lm.Storage().SavePlanFeature(ctx, pf)
				}
			}

			http.Redirect(w, r, "/products/"+productID, http.StatusSeeOther)
			return
		}

		ws.render(w, "plan_new.html", TemplateData{
			Title:       "New Plan",
			CurrentPath: "/products",
			User:        ws.getSessionFromContext(r),
			Data:        map[string]interface{}{"Product": product},
		})
		return
	}

	planID := pathParts[0]
	if planID == "" {
		http.NotFound(w, r)
		return
	}

	plan, err := ws.lm.Storage().GetPlan(ctx, planID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Plan not found")
		return
	}

	// Handle plan sub-actions
	if len(pathParts) > 1 {
		switch pathParts[1] {
		case "edit":
			ws.handlePlanEdit(w, r, productID, plan)
			return
		case "delete":
			if r.Method == http.MethodPost && ws.validateCSRF(r) {
				err := ws.lm.Storage().DeletePlan(ctx, planID)
				if err != nil {
					ws.renderError(w, http.StatusBadRequest, err.Error())
					return
				}
				http.Redirect(w, r, "/products/"+productID, http.StatusSeeOther)
				return
			}
		case "features":
			ws.handlePlanFeatures(w, r, productID, planID, pathParts[2:])
			return
		}
	}

	// Show plan detail
	planFeatures, _ := ws.lm.Storage().ListPlanFeatures(ctx, planID)
	allFeatures, _ := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)

	// Map features for easy lookup
	featureMap := make(map[string]*licensing.Feature)
	for _, f := range allFeatures {
		featureMap[f.ID] = f
	}

	featureScopes := make(map[string][]*licensing.FeatureScope)
	for _, pf := range planFeatures {
		if _, ok := featureScopes[pf.FeatureID]; ok {
			continue
		}
		scopes, err := ws.lm.Storage().ListFeatureScopes(ctx, pf.FeatureID)
		if err != nil {
			continue
		}
		featureScopes[pf.FeatureID] = scopes
	}

	data := map[string]interface{}{
		"Product":       product,
		"Plan":          plan,
		"PlanFeatures":  planFeatures,
		"AllFeatures":   allFeatures,
		"FeatureMap":    featureMap,
		"FeatureScopes": featureScopes,
	}

	ws.render(w, "plan_detail.html", TemplateData{
		Title:       plan.Name,
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handlePlanEdit(w http.ResponseWriter, r *http.Request, productID string, plan *licensing.Plan) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		slug := strings.TrimSpace(r.FormValue("slug"))
		description := strings.TrimSpace(r.FormValue("description"))
		price := int64(parseInt(r.FormValue("price"), 0) * 100)
		currency := strings.TrimSpace(r.FormValue("currency"))
		billingCycle := strings.TrimSpace(r.FormValue("billing_cycle"))
		trialDays := parseInt(r.FormValue("trial_days"), 0)
		displayOrder := parseInt(r.FormValue("display_order"), 0)
		isActive := r.FormValue("is_active") == "on"
		isTrial := r.FormValue("is_trial") == "on"

		// If enabling trial on this plan, check if product already has a different trial plan
		if isTrial && !plan.IsTrial {
			existingTrialPlan, _ := ws.lm.Storage().GetTrialPlanForProduct(ctx, productID)
			if existingTrialPlan != nil && existingTrialPlan.ID != plan.ID {
				ws.renderError(w, http.StatusBadRequest, "This product already has a trial plan: "+existingTrialPlan.Name)
				return
			}
		}

		// If this is a trial plan, enforce price of 0 and trial days > 0
		if isTrial {
			price = 0
			if trialDays <= 0 {
				trialDays = 14
			}
		}

		if name != "" {
			plan.Name = name
		}
		if slug != "" {
			plan.Slug = slug
		}
		plan.Description = description
		plan.Price = price
		if currency != "" {
			plan.Currency = currency
		}
		if billingCycle != "" {
			plan.BillingCycle = billingCycle
		}
		// Track if we're newly enabling trial mode (before updating the plan)
		wasTrialBefore := plan.IsTrial
		becomingTrial := isTrial && !wasTrialBefore

		plan.TrialDays = trialDays
		plan.IsTrial = isTrial
		plan.DisplayOrder = displayOrder
		plan.IsActive = isActive
		plan.UpdatedAt = time.Now()

		if err := ws.lm.Storage().UpdatePlan(ctx, plan); err != nil {
			ws.renderError(w, http.StatusBadRequest, err.Error())
			return
		}

		// If plan is becoming a trial plan, assign all features with all scopes
		if becomingTrial {
			allFeatures, _ := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)
			existingPlanFeatures, _ := ws.lm.Storage().ListPlanFeatures(ctx, plan.ID)

			// Map existing plan features
			existingFeatureMap := make(map[string]*licensing.PlanFeature)
			for _, pf := range existingPlanFeatures {
				existingFeatureMap[pf.FeatureID] = pf
			}

			now := time.Now()
			for _, feature := range allFeatures {
				// Get all scopes for this feature
				scopes, _ := ws.lm.Storage().ListFeatureScopes(ctx, feature.ID)
				scopeOverrides := make(map[string]licensing.ScopeOverride)
				for _, scope := range scopes {
					scopeOverrides[scope.Slug] = licensing.ScopeOverride{
						Permission: licensing.ScopePermissionAllow,
						Limit:      scope.Limit,
					}
				}

				if existingPF, exists := existingFeatureMap[feature.ID]; exists {
					// Update existing plan feature to enable all scopes
					existingPF.Enabled = true
					existingPF.ScopeOverrides = scopeOverrides
					existingPF.UpdatedAt = now
					ws.lm.Storage().UpdatePlanFeature(ctx, existingPF)
				} else {
					// Create new plan feature
					pf := &licensing.PlanFeature{
						ID:             uuid.New().String(),
						PlanID:         plan.ID,
						FeatureID:      feature.ID,
						Enabled:        true,
						ScopeOverrides: scopeOverrides,
						CreatedAt:      now,
						UpdatedAt:      now,
					}
					ws.lm.Storage().SavePlanFeature(ctx, pf)
				}
			}
		}

		http.Redirect(w, r, "/products/"+productID+"/plans/"+plan.ID, http.StatusSeeOther)
		return
	}

	product, _ := ws.lm.Storage().GetProduct(ctx, productID)

	ws.render(w, "plan_edit.html", TemplateData{
		Title:       "Edit Plan",
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        map[string]interface{}{"Product": product, "Plan": plan},
	})
}

func (ws *WebServer) handlePlanFeatures(w http.ResponseWriter, r *http.Request, productID, planID string, pathParts []string) {
	ctx := r.Context()

	plan, err := ws.lm.Storage().GetPlan(ctx, planID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Plan not found")
		return
	}

	// Add feature to plan
	if r.Method == http.MethodPost && ws.validateCSRF(r) {
		action := r.FormValue("action")
		featureID := r.FormValue("feature_id")

		switch action {
		case "add":
			enabled := r.FormValue("enabled") == "on"
			now := time.Now()
			pf := &licensing.PlanFeature{
				ID:        uuid.New().String(),
				PlanID:    planID,
				FeatureID: featureID,
				Enabled:   enabled,
				CreatedAt: now,
				UpdatedAt: now,
			}
			if err := ws.lm.Storage().SavePlanFeature(ctx, pf); err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		case "remove":
			if err := ws.lm.Storage().DeletePlanFeature(ctx, planID, featureID); err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		case "toggle":
			pf, err := ws.lm.Storage().GetPlanFeature(ctx, planID, featureID)
			if err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
			pf.Enabled = !pf.Enabled
			pf.UpdatedAt = time.Now()
			if err := ws.lm.Storage().UpdatePlanFeature(ctx, pf); err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}
		}

		http.Redirect(w, r, "/products/"+productID+"/plans/"+planID, http.StatusSeeOther)
		return
	}

	product, _ := ws.lm.Storage().GetProduct(ctx, productID)
	allFeatures, _ := ws.lm.Storage().ListFeaturesByProduct(ctx, productID)
	planFeatures, _ := ws.lm.Storage().ListPlanFeatures(ctx, planID)

	// Find features not yet assigned to plan
	assignedFeatures := make(map[string]bool)
	for _, pf := range planFeatures {
		assignedFeatures[pf.FeatureID] = true
	}

	var availableFeatures []*licensing.Feature
	for _, f := range allFeatures {
		if !assignedFeatures[f.ID] {
			availableFeatures = append(availableFeatures, f)
		}
	}

	data := map[string]interface{}{
		"Product":           product,
		"Plan":              plan,
		"AvailableFeatures": availableFeatures,
		"PlanFeatures":      planFeatures,
	}

	ws.render(w, "plan_features.html", TemplateData{
		Title:       "Plan Features",
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleProductFeatures(w http.ResponseWriter, r *http.Request, productID string, pathParts []string) {
	ctx := r.Context()

	product, err := ws.lm.Storage().GetProduct(ctx, productID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Product not found")
		return
	}

	// New feature
	if len(pathParts) == 0 || (len(pathParts) == 1 && pathParts[0] == "new") {
		if r.Method == http.MethodPost {
			if !ws.validateCSRF(r) {
				ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
				return
			}

			name := strings.TrimSpace(r.FormValue("name"))
			slug := strings.TrimSpace(r.FormValue("slug"))
			description := strings.TrimSpace(r.FormValue("description"))
			category := strings.TrimSpace(r.FormValue("category"))

			if name == "" || slug == "" {
				ws.renderError(w, http.StatusBadRequest, "Name and slug are required")
				return
			}

			now := time.Now()
			feature := &licensing.Feature{
				ID:          uuid.New().String(),
				ProductID:   productID,
				Name:        name,
				Slug:        slug,
				Description: description,
				Category:    category,
				CreatedAt:   now,
				UpdatedAt:   now,
			}

			if err := ws.lm.Storage().SaveFeature(ctx, feature); err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}

			http.Redirect(w, r, "/products/"+productID, http.StatusSeeOther)
			return
		}

		ws.render(w, "feature_new.html", TemplateData{
			Title:       "New Feature",
			CurrentPath: "/products",
			User:        ws.getSessionFromContext(r),
			Data:        map[string]interface{}{"Product": product},
		})
		return
	}

	featureID := pathParts[0]
	if featureID == "" {
		http.NotFound(w, r)
		return
	}

	feature, err := ws.lm.Storage().GetFeature(ctx, featureID)
	if err != nil || feature == nil {
		ws.renderError(w, http.StatusNotFound, "Feature not found")
		return
	}

	// Handle feature sub-actions
	if len(pathParts) > 1 {
		switch pathParts[1] {
		case "edit":
			ws.handleFeatureEdit(w, r, productID, feature)
			return
		case "delete":
			if r.Method == http.MethodPost && ws.validateCSRF(r) {
				err := ws.lm.Storage().DeleteFeature(ctx, featureID)
				if err != nil {
					ws.renderError(w, http.StatusBadRequest, err.Error())
					return
				}
				http.Redirect(w, r, "/products/"+productID, http.StatusSeeOther)
				return
			}
		case "scopes":
			ws.handleFeatureScopes(w, r, productID, featureID, pathParts[2:])
			return
		}
	}

	// Show feature detail
	scopes, _ := ws.lm.Storage().ListFeatureScopes(ctx, featureID)

	data := map[string]interface{}{
		"Product": product,
		"Feature": feature,
		"Scopes":  scopes,
	}

	ws.render(w, "feature_detail.html", TemplateData{
		Title:       feature.Name,
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        data,
	})
}

func (ws *WebServer) handleFeatureEdit(w http.ResponseWriter, r *http.Request, productID string, feature *licensing.Feature) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		slug := strings.TrimSpace(r.FormValue("slug"))
		description := strings.TrimSpace(r.FormValue("description"))
		category := strings.TrimSpace(r.FormValue("category"))

		if name != "" {
			feature.Name = name
		}
		if slug != "" {
			feature.Slug = slug
		}
		feature.Description = description
		feature.Category = category
		feature.UpdatedAt = time.Now()

		if err := ws.lm.Storage().UpdateFeature(ctx, feature); err != nil {
			ws.renderError(w, http.StatusBadRequest, err.Error())
			return
		}

		http.Redirect(w, r, "/products/"+productID+"/features/"+feature.ID, http.StatusSeeOther)
		return
	}

	product, err := ws.lm.Storage().GetProduct(ctx, productID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Product not found")
		return
	}

	ws.render(w, "feature_edit.html", TemplateData{
		Title:       "Edit Feature",
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        map[string]interface{}{"Product": product, "Feature": feature},
	})
}

func (ws *WebServer) handleFeatureScopes(w http.ResponseWriter, r *http.Request, productID, featureID string, pathParts []string) {
	ctx := r.Context()

	feature, err := ws.lm.Storage().GetFeature(ctx, featureID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Feature not found")
		return
	}

	// Handle empty path - redirect to feature detail
	if len(pathParts) == 0 {
		http.Redirect(w, r, "/products/"+productID+"/features/"+featureID, http.StatusSeeOther)
		return
	}

	// New scope
	if len(pathParts) == 1 && pathParts[0] == "new" {
		if r.Method == http.MethodPost {
			if !ws.validateCSRF(r) {
				ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
				return
			}

			name := strings.TrimSpace(r.FormValue("name"))
			slug := strings.TrimSpace(r.FormValue("slug"))
			permission := strings.TrimSpace(r.FormValue("permission"))
			limit := parseInt(r.FormValue("limit"), 0)
			description := strings.TrimSpace(r.FormValue("description"))

			if name == "" || slug == "" {
				ws.renderError(w, http.StatusBadRequest, "Name and slug are required")
				return
			}

			now := time.Now()
			scope := &licensing.FeatureScope{
				ID:         uuid.New().String(),
				FeatureID:  featureID,
				Name:       name,
				Slug:       slug,
				Permission: licensing.ScopePermission(permission),
				Limit:      limit,
				CreatedAt:  now,
				UpdatedAt:  now,
			}

			if description != "" {
				scope.Metadata = map[string]string{"description": description}
			}

			if err := ws.lm.Storage().SaveFeatureScope(ctx, scope); err != nil {
				ws.renderError(w, http.StatusBadRequest, err.Error())
				return
			}

			http.Redirect(w, r, "/products/"+productID+"/features/"+featureID, http.StatusSeeOther)
			return
		}

		product, err := ws.lm.Storage().GetProduct(ctx, productID)
		if err != nil || product == nil {
			ws.renderError(w, http.StatusNotFound, "Product not found")
			return
		}

		ws.render(w, "scope_new.html", TemplateData{
			Title:       "New Scope",
			CurrentPath: "/products",
			User:        ws.getSessionFromContext(r),
			Data:        map[string]interface{}{"Product": product, "Feature": feature},
		})
		return
	}

	scopeID := pathParts[0]
	if scopeID == "" {
		http.NotFound(w, r)
		return
	}

	// Handle scope actions
	if len(pathParts) > 1 {
		switch pathParts[1] {
		case "edit":
			scope, err := ws.lm.Storage().GetFeatureScope(ctx, scopeID)
			if err != nil {
				ws.renderError(w, http.StatusNotFound, "Scope not found")
				return
			}
			ws.handleScopeEdit(w, r, productID, featureID, scope)
			return
		case "delete":
			if r.Method == http.MethodPost && ws.validateCSRF(r) {
				err := ws.lm.Storage().DeleteFeatureScope(ctx, scopeID)
				if err != nil {
					ws.renderError(w, http.StatusBadRequest, err.Error())
					return
				}
				http.Redirect(w, r, "/products/"+productID+"/features/"+featureID, http.StatusSeeOther)
				return
			}
		}
	}

	http.NotFound(w, r)
}

func (ws *WebServer) handleScopeEdit(w http.ResponseWriter, r *http.Request, productID, featureID string, scope *licensing.FeatureScope) {
	ctx := r.Context()

	if r.Method == http.MethodPost {
		if !ws.validateCSRF(r) {
			ws.renderError(w, http.StatusForbidden, "Invalid CSRF token")
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		slug := strings.TrimSpace(r.FormValue("slug"))
		permission := strings.TrimSpace(r.FormValue("permission"))
		limit := parseInt(r.FormValue("limit"), 0)
		description := strings.TrimSpace(r.FormValue("description"))

		if name != "" {
			scope.Name = name
		}
		if slug != "" {
			scope.Slug = slug
		}
		scope.Permission = licensing.ScopePermission(permission)
		scope.Limit = limit
		if scope.Metadata == nil && description != "" {
			scope.Metadata = make(map[string]string)
		}
		if scope.Metadata != nil {
			if description != "" {
				scope.Metadata["description"] = description
			} else {
				delete(scope.Metadata, "description")
				if len(scope.Metadata) == 0 {
					scope.Metadata = nil
				}
			}
		}
		scope.UpdatedAt = time.Now()

		if err := ws.lm.Storage().UpdateFeatureScope(ctx, scope); err != nil {
			ws.renderError(w, http.StatusBadRequest, err.Error())
			return
		}

		http.Redirect(w, r, "/products/"+productID+"/features/"+featureID, http.StatusSeeOther)
		return
	}

	product, err := ws.lm.Storage().GetProduct(ctx, productID)
	if err != nil || product == nil {
		ws.renderError(w, http.StatusNotFound, "Product not found")
		return
	}
	feature, err := ws.lm.Storage().GetFeature(ctx, featureID)
	if err != nil || feature == nil {
		ws.renderError(w, http.StatusNotFound, "Feature not found")
		return
	}

	ws.render(w, "scope_edit.html", TemplateData{
		Title:       "Edit Scope",
		CurrentPath: "/products",
		User:        ws.getSessionFromContext(r),
		Data:        map[string]interface{}{"Product": product, "Feature": feature, "Scope": scope},
	})
}

// handlePlanDetail handles /plans/{id} routes
func (ws *WebServer) handlePlanDetail(w http.ResponseWriter, r *http.Request) {
	// This is just a redirect to the proper product/plan path
	ctx := r.Context()
	planID := strings.TrimPrefix(r.URL.Path, "/plans/")
	planID = strings.Split(planID, "/")[0]

	plan, err := ws.lm.Storage().GetPlan(ctx, planID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Plan not found")
		return
	}

	http.Redirect(w, r, "/products/"+plan.ProductID+"/plans/"+planID, http.StatusSeeOther)
}

// handleFeatureDetail handles /features/{id} routes
func (ws *WebServer) handleFeatureDetail(w http.ResponseWriter, r *http.Request) {
	// This is just a redirect to the proper product/feature path
	ctx := r.Context()
	featureID := strings.TrimPrefix(r.URL.Path, "/features/")
	featureID = strings.Split(featureID, "/")[0]

	feature, err := ws.lm.Storage().GetFeature(ctx, featureID)
	if err != nil {
		ws.renderError(w, http.StatusNotFound, "Feature not found")
		return
	}

	http.Redirect(w, r, "/products/"+feature.ProductID+"/features/"+featureID, http.StatusSeeOther)
}
