package licensing

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func (s *SQLiteStorage) SaveCouponCode(ctx context.Context, coupon *CouponCode) error {
	if coupon == nil {
		return fmt.Errorf("coupon is nil")
	}
	coupon.Code = normalizeCouponCode(coupon.Code)
	if coupon.Code == "" {
		return fmt.Errorf("coupon code is required")
	}
	if coupon.CreatedAt.IsZero() {
		coupon.CreatedAt = time.Now()
	}
	coupon.UpdatedAt = time.Now()
	allowedJSON, _ := json.Marshal(coupon.AllowedClientIDs)
	metadataJSON, _ := json.Marshal(coupon.Metadata)
	featuresJSON, _ := json.Marshal(coupon.Features)
	_, err := s.db.ExecContext(ctx, `INSERT INTO coupons
		(id, code, code_upper, name, description, product_id, allowed_client_ids, max_redemptions, max_redemptions_per_client, is_active, starts_at, expires_at, metadata, features, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		coupon.ID, coupon.Code, coupon.Code, coupon.Name, coupon.Description, nullableCouponString(coupon.ProductID),
		string(allowedJSON), coupon.MaxRedemptions, coupon.MaxRedemptionsPerClient, boolToIntCoupon(coupon.IsActive),
		nullableCouponTime(coupon.StartsAt), nullableCouponTime(coupon.ExpiresAt), string(metadataJSON), string(featuresJSON), coupon.CreatedAt, coupon.UpdatedAt,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errCouponExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateCouponCode(ctx context.Context, coupon *CouponCode) error {
	if coupon == nil {
		return fmt.Errorf("coupon is nil")
	}
	coupon.Code = normalizeCouponCode(coupon.Code)
	coupon.UpdatedAt = time.Now()
	allowedJSON, _ := json.Marshal(coupon.AllowedClientIDs)
	metadataJSON, _ := json.Marshal(coupon.Metadata)
	featuresJSON, _ := json.Marshal(coupon.Features)
	result, err := s.db.ExecContext(ctx, `UPDATE coupons SET
		code=?, code_upper=?, name=?, description=?, product_id=?, allowed_client_ids=?, max_redemptions=?, max_redemptions_per_client=?, is_active=?, starts_at=?, expires_at=?, metadata=?, features=?, updated_at=?
		WHERE id=?`,
		coupon.Code, coupon.Code, coupon.Name, coupon.Description, nullableCouponString(coupon.ProductID),
		string(allowedJSON), coupon.MaxRedemptions, coupon.MaxRedemptionsPerClient, boolToIntCoupon(coupon.IsActive),
		nullableCouponTime(coupon.StartsAt), nullableCouponTime(coupon.ExpiresAt), string(metadataJSON), string(featuresJSON), coupon.UpdatedAt, coupon.ID,
	)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errCouponExists
		}
		return err
	}
	rows, _ := result.RowsAffected()
	if rows == 0 {
		return errCouponMissing
	}
	return nil
}

func (s *SQLiteStorage) GetCouponCode(ctx context.Context, couponID string) (*CouponCode, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, code, name, description, product_id, allowed_client_ids, max_redemptions, max_redemptions_per_client, is_active, starts_at, expires_at, metadata, features, created_at, updated_at FROM coupons WHERE id=?`, couponID)
	return scanCouponCode(row)
}

func (s *SQLiteStorage) GetCouponCodeByCode(ctx context.Context, code string) (*CouponCode, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, code, name, description, product_id, allowed_client_ids, max_redemptions, max_redemptions_per_client, is_active, starts_at, expires_at, metadata, features, created_at, updated_at FROM coupons WHERE code_upper=?`, normalizeCouponCode(code))
	return scanCouponCode(row)
}

func (s *SQLiteStorage) ListCouponCodes(ctx context.Context) ([]*CouponCode, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id, code, name, description, product_id, allowed_client_ids, max_redemptions, max_redemptions_per_client, is_active, starts_at, expires_at, metadata, features, created_at, updated_at FROM coupons ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]*CouponCode, 0)
	for rows.Next() {
		item, err := scanCouponCode(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *SQLiteStorage) SaveCouponRedemption(ctx context.Context, redemption *CouponRedemption) error {
	if redemption == nil {
		return fmt.Errorf("coupon redemption is nil")
	}
	metadataJSON, _ := json.Marshal(redemption.Metadata)
	_, err := s.db.ExecContext(ctx, `INSERT INTO coupon_redemptions
		(id, coupon_id, coupon_code, license_id, client_id, redeemed_by, redeemed_at, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		redemption.ID, redemption.CouponID, normalizeCouponCode(redemption.CouponCode), redemption.LicenseID, redemption.ClientID, nullableCouponString(redemption.RedeemedBy), redemption.RedeemedAt, string(metadataJSON),
	)
	return err
}

func (s *SQLiteStorage) ListCouponRedemptionsByCoupon(ctx context.Context, couponID string) ([]*CouponRedemption, error) {
	return s.listCouponRedemptions(ctx, `SELECT id, coupon_id, coupon_code, license_id, client_id, redeemed_by, redeemed_at, metadata FROM coupon_redemptions WHERE coupon_id=? ORDER BY redeemed_at DESC`, couponID)
}

func (s *SQLiteStorage) ListCouponRedemptionsByLicense(ctx context.Context, licenseID string) ([]*CouponRedemption, error) {
	return s.listCouponRedemptions(ctx, `SELECT id, coupon_id, coupon_code, license_id, client_id, redeemed_by, redeemed_at, metadata FROM coupon_redemptions WHERE license_id=? ORDER BY redeemed_at DESC`, licenseID)
}

func (s *SQLiteStorage) ListCouponRedemptionsByClient(ctx context.Context, clientID string) ([]*CouponRedemption, error) {
	return s.listCouponRedemptions(ctx, `SELECT id, coupon_id, coupon_code, license_id, client_id, redeemed_by, redeemed_at, metadata FROM coupon_redemptions WHERE client_id=? ORDER BY redeemed_at DESC`, clientID)
}

func (s *SQLiteStorage) listCouponRedemptions(ctx context.Context, query string, arg string) ([]*CouponRedemption, error) {
	rows, err := s.db.QueryContext(ctx, query, arg)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]*CouponRedemption, 0)
	for rows.Next() {
		item, err := scanCouponRedemption(rows)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func scanCouponCode(scanner interface{ Scan(dest ...any) error }) (*CouponCode, error) {
	var coupon CouponCode
	var description, productID, allowedJSON, metadataJSON, featuresJSON sql.NullString
	var startsAt, expiresAt, createdAt, updatedAt sqliteTimeValue
	var isActive int
	err := scanner.Scan(&coupon.ID, &coupon.Code, &coupon.Name, &description, &productID, &allowedJSON, &coupon.MaxRedemptions, &coupon.MaxRedemptionsPerClient, &isActive, &startsAt, &expiresAt, &metadataJSON, &featuresJSON, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errCouponMissing
	}
	if err != nil {
		return nil, err
	}
	coupon.Description = description.String
	coupon.ProductID = productID.String
	coupon.IsActive = isActive == 1
	coupon.StartsAt = startsAt.Time
	coupon.ExpiresAt = expiresAt.Time
	coupon.CreatedAt = createdAt.Time
	coupon.UpdatedAt = updatedAt.Time
	if allowedJSON.Valid && allowedJSON.String != "" {
		_ = json.Unmarshal([]byte(allowedJSON.String), &coupon.AllowedClientIDs)
	}
	if metadataJSON.Valid && metadataJSON.String != "" {
		_ = json.Unmarshal([]byte(metadataJSON.String), &coupon.Metadata)
	}
	if featuresJSON.Valid && featuresJSON.String != "" {
		_ = json.Unmarshal([]byte(featuresJSON.String), &coupon.Features)
	}
	return &coupon, nil
}

func scanCouponRedemption(scanner interface{ Scan(dest ...any) error }) (*CouponRedemption, error) {
	var redemption CouponRedemption
	var redeemedBy, metadataJSON sql.NullString
	var redeemedAt sqliteTimeValue
	if err := scanner.Scan(&redemption.ID, &redemption.CouponID, &redemption.CouponCode, &redemption.LicenseID, &redemption.ClientID, &redeemedBy, &redeemedAt, &metadataJSON); err != nil {
		return nil, err
	}
	redemption.RedeemedBy = redeemedBy.String
	redemption.RedeemedAt = redeemedAt.Time
	if metadataJSON.Valid && metadataJSON.String != "" {
		_ = json.Unmarshal([]byte(metadataJSON.String), &redemption.Metadata)
	}
	return &redemption, nil
}

func boolToIntCoupon(v bool) int {
	if v {
		return 1
	}
	return 0
}

func nullableCouponString(v string) any {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return v
}

func nullableCouponTime(v time.Time) any {
	if v.IsZero() {
		return nil
	}
	return v
}
