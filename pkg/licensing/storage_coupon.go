package licensing

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

func normalizeCouponCode(code string) string {
	return strings.ToUpper(strings.TrimSpace(code))
}

func (s *InMemoryStorage) SaveCouponCode(_ context.Context, coupon *CouponCode) error {
	if coupon == nil {
		return fmt.Errorf("coupon is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.coupons[coupon.ID]; exists {
		return errCouponExists
	}
	code := normalizeCouponCode(coupon.Code)
	if code == "" {
		return fmt.Errorf("coupon code is required")
	}
	if _, exists := s.couponsByCode[code]; exists {
		return errCouponExists
	}
	copy := cloneCouponCode(coupon)
	copy.Code = code
	s.coupons[copy.ID] = copy
	s.couponsByCode[code] = copy.ID
	return nil
}

func (s *InMemoryStorage) UpdateCouponCode(_ context.Context, coupon *CouponCode) error {
	if coupon == nil {
		return fmt.Errorf("coupon is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.coupons[coupon.ID]
	if !exists {
		return errCouponMissing
	}
	oldCode := normalizeCouponCode(current.Code)
	newCode := normalizeCouponCode(coupon.Code)
	if newCode == "" {
		return fmt.Errorf("coupon code is required")
	}
	if mapped, exists := s.couponsByCode[newCode]; exists && mapped != coupon.ID {
		return errCouponExists
	}
	delete(s.couponsByCode, oldCode)
	copy := cloneCouponCode(coupon)
	copy.Code = newCode
	s.coupons[coupon.ID] = copy
	s.couponsByCode[newCode] = coupon.ID
	return nil
}

func (s *InMemoryStorage) GetCouponCode(_ context.Context, couponID string) (*CouponCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	coupon, exists := s.coupons[couponID]
	if !exists {
		return nil, errCouponMissing
	}
	return cloneCouponCode(coupon), nil
}

func (s *InMemoryStorage) GetCouponCodeByCode(_ context.Context, code string) (*CouponCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, exists := s.couponsByCode[normalizeCouponCode(code)]
	if !exists {
		return nil, errCouponMissing
	}
	return cloneCouponCode(s.coupons[id]), nil
}

func (s *InMemoryStorage) ListCouponCodes(_ context.Context) ([]*CouponCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]*CouponCode, 0, len(s.coupons))
	for _, coupon := range s.coupons {
		items = append(items, cloneCouponCode(coupon))
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].CreatedAt.After(items[j].CreatedAt)
	})
	return items, nil
}

func (s *InMemoryStorage) SaveCouponRedemption(_ context.Context, redemption *CouponRedemption) error {
	if redemption == nil {
		return fmt.Errorf("coupon redemption is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.couponRedemptions[redemption.ID]; exists {
		return errCouponRedemptionExists
	}
	copy := cloneCouponRedemption(redemption)
	s.couponRedemptions[copy.ID] = copy
	s.couponRedemptionsByCoupon[copy.CouponID] = append(s.couponRedemptionsByCoupon[copy.CouponID], copy.ID)
	s.couponRedemptionsByLicense[copy.LicenseID] = append(s.couponRedemptionsByLicense[copy.LicenseID], copy.ID)
	s.couponRedemptionsByClient[copy.ClientID] = append(s.couponRedemptionsByClient[copy.ClientID], copy.ID)
	return nil
}

func (s *InMemoryStorage) ListCouponRedemptionsByCoupon(_ context.Context, couponID string) ([]*CouponRedemption, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCouponRedemptionsFromIDs(s.couponRedemptions, s.couponRedemptionsByCoupon[couponID]), nil
}

func (s *InMemoryStorage) ListCouponRedemptionsByLicense(_ context.Context, licenseID string) ([]*CouponRedemption, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCouponRedemptionsFromIDs(s.couponRedemptions, s.couponRedemptionsByLicense[licenseID]), nil
}

func (s *InMemoryStorage) ListCouponRedemptionsByClient(_ context.Context, clientID string) ([]*CouponRedemption, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCouponRedemptionsFromIDs(s.couponRedemptions, s.couponRedemptionsByClient[clientID]), nil
}

func cloneCouponRedemptionsFromIDs(source map[string]*CouponRedemption, ids []string) []*CouponRedemption {
	items := make([]*CouponRedemption, 0, len(ids))
	for _, id := range ids {
		if redemption, exists := source[id]; exists {
			items = append(items, cloneCouponRedemption(redemption))
		}
	}
	sort.Slice(items, func(i, j int) bool {
		return items[i].RedeemedAt.After(items[j].RedeemedAt)
	})
	return items
}
