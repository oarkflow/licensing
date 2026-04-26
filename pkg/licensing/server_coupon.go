package licensing

import (
	"net/http"
	"strings"
	"time"
)

type saveCouponRequest struct {
	Code                    string               `json:"code"`
	Name                    string               `json:"name"`
	Description             string               `json:"description,omitempty"`
	ProductID               string               `json:"product_id,omitempty"`
	AllowedClientIDs        []string             `json:"allowed_client_ids,omitempty"`
	MaxRedemptions          int                  `json:"max_redemptions,omitempty"`
	MaxRedemptionsPerClient int                  `json:"max_redemptions_per_client,omitempty"`
	IsActive                *bool                `json:"is_active,omitempty"`
	StartsAt                string               `json:"starts_at,omitempty"`
	ExpiresAt               string               `json:"expires_at,omitempty"`
	Metadata                map[string]string    `json:"metadata,omitempty"`
	Features                []CouponFeaturePatch `json:"features,omitempty"`
}

type redeemCouponRequest struct {
	Code       string            `json:"code"`
	RedeemedBy string            `json:"redeemed_by,omitempty"`
	Metadata   map[string]string `json:"metadata,omitempty"`
}

func (s *Server) handleCoupons(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	switch r.Method {
	case http.MethodGet:
		items, err := s.lm.ListCouponCodes(r.Context())
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, err.Error())
			return
		}
		if items == nil {
			items = []*CouponCode{}
		}
		s.respondJSON(w, http.StatusOK, items)
	case http.MethodPost:
		var req saveCouponRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		coupon, err := buildCouponFromRequest(req)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		created, err := s.lm.CreateCouponCode(r.Context(), coupon)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondJSON(w, http.StatusCreated, created)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func (s *Server) handleCouponActions(w http.ResponseWriter, r *http.Request) {
	if !s.enforceRateLimit(w, r) {
		return
	}
	if !s.authorizeAdmin(w, r) {
		return
	}
	couponID := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/coupons/"), "/")
	if couponID == "" {
		s.respondError(w, http.StatusBadRequest, "coupon id is required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		coupon, err := s.lm.storage.GetCouponCode(r.Context(), couponID)
		if err != nil {
			s.respondError(w, http.StatusNotFound, "coupon not found")
			return
		}
		s.respondJSON(w, http.StatusOK, coupon)
	case http.MethodPut:
		var req saveCouponRequest
		if !s.decodeJSONBody(w, r, &req, maxAdminPayloadBytes) {
			return
		}
		coupon, err := buildCouponFromRequest(req)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		coupon.ID = couponID
		updated, err := s.lm.UpdateCouponCode(r.Context(), coupon)
		if err != nil {
			s.respondError(w, http.StatusBadRequest, err.Error())
			return
		}
		s.respondJSON(w, http.StatusOK, updated)
	default:
		s.respondError(w, http.StatusMethodNotAllowed, "Method not allowed")
	}
}

func buildCouponFromRequest(req saveCouponRequest) (*CouponCode, error) {
	var startsAt, expiresAt time.Time
	var err error
	if strings.TrimSpace(req.StartsAt) != "" {
		startsAt, err = time.Parse(time.RFC3339, strings.TrimSpace(req.StartsAt))
		if err != nil {
			return nil, err
		}
	}
	if strings.TrimSpace(req.ExpiresAt) != "" {
		expiresAt, err = time.Parse(time.RFC3339, strings.TrimSpace(req.ExpiresAt))
		if err != nil {
			return nil, err
		}
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	return &CouponCode{
		Code:                    req.Code,
		Name:                    req.Name,
		Description:             req.Description,
		ProductID:               req.ProductID,
		AllowedClientIDs:        req.AllowedClientIDs,
		MaxRedemptions:          req.MaxRedemptions,
		MaxRedemptionsPerClient: req.MaxRedemptionsPerClient,
		IsActive:                isActive,
		StartsAt:                startsAt,
		ExpiresAt:               expiresAt,
		Metadata:                req.Metadata,
		Features:                req.Features,
	}, nil
}
