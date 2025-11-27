package licensing

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// productRowScanner is a common interface for sql.Row and sql.Rows
type productRowScanner interface {
	Scan(dest ...any) error
}

// ensureProductSchema creates the product-related tables in SQLite
func ensureProductSchema(db interface {
	Exec(string, ...interface{}) (sql.Result, error)
}) error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS products (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			slug TEXT NOT NULL,
			slug_lower TEXT NOT NULL UNIQUE,
			description TEXT,
			logo_url TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS plans (
			id TEXT PRIMARY KEY,
			product_id TEXT NOT NULL,
			name TEXT NOT NULL,
			slug TEXT NOT NULL,
			slug_key TEXT NOT NULL UNIQUE,
			description TEXT,
			price INTEGER NOT NULL DEFAULT 0,
			currency TEXT NOT NULL DEFAULT 'USD',
			billing_cycle TEXT NOT NULL DEFAULT 'monthly',
			trial_days INTEGER NOT NULL DEFAULT 0,
			is_active INTEGER NOT NULL DEFAULT 1,
			display_order INTEGER NOT NULL DEFAULT 0,
			metadata TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS features (
			id TEXT PRIMARY KEY,
			product_id TEXT NOT NULL,
			name TEXT NOT NULL,
			slug TEXT NOT NULL,
			slug_key TEXT NOT NULL UNIQUE,
			description TEXT,
			category TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			FOREIGN KEY(product_id) REFERENCES products(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS feature_scopes (
			id TEXT PRIMARY KEY,
			feature_id TEXT NOT NULL,
			name TEXT NOT NULL,
			slug TEXT NOT NULL,
			permission TEXT NOT NULL DEFAULT 'allow',
			scope_limit INTEGER NOT NULL DEFAULT 0,
			metadata TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			FOREIGN KEY(feature_id) REFERENCES features(id) ON DELETE CASCADE
		);`,
		`CREATE TABLE IF NOT EXISTS plan_features (
			id TEXT PRIMARY KEY,
			plan_id TEXT NOT NULL,
			feature_id TEXT NOT NULL,
			enabled INTEGER NOT NULL DEFAULT 1,
			scope_overrides TEXT,
			created_at TIMESTAMP NOT NULL,
			updated_at TIMESTAMP NOT NULL,
			UNIQUE(plan_id, feature_id),
			FOREIGN KEY(plan_id) REFERENCES plans(id) ON DELETE CASCADE,
			FOREIGN KEY(feature_id) REFERENCES features(id) ON DELETE CASCADE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_plans_product_id ON plans(product_id);`,
		`CREATE INDEX IF NOT EXISTS idx_features_product_id ON features(product_id);`,
		`CREATE INDEX IF NOT EXISTS idx_feature_scopes_feature_id ON feature_scopes(feature_id);`,
		`CREATE INDEX IF NOT EXISTS idx_plan_features_plan_id ON plan_features(plan_id);`,
		`CREATE INDEX IF NOT EXISTS idx_plan_features_feature_id ON plan_features(feature_id);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			return fmt.Errorf("product schema migration failed: %w", err)
		}
	}
	return nil
}

// ==================== Product Storage Methods ====================

func (s *SQLiteStorage) SaveProduct(ctx context.Context, product *Product) error {
	if product == nil {
		return fmt.Errorf("product is nil")
	}
	now := time.Now()
	if product.CreatedAt.IsZero() {
		product.CreatedAt = now
	}
	product.UpdatedAt = now
	slugLower := strings.ToLower(product.Slug)

	query := `INSERT INTO products (id, name, slug, slug_lower, description, logo_url, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		product.ID, product.Name, product.Slug, slugLower,
		product.Description, product.LogoURL,
		product.CreatedAt, product.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errProductExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateProduct(ctx context.Context, product *Product) error {
	if product == nil {
		return fmt.Errorf("product is nil")
	}
	product.UpdatedAt = time.Now()
	slugLower := strings.ToLower(product.Slug)

	query := `UPDATE products SET name=?, slug=?, slug_lower=?, description=?, logo_url=?, updated_at=? WHERE id=?`
	result, err := s.db.ExecContext(ctx, query,
		product.Name, product.Slug, slugLower,
		product.Description, product.LogoURL,
		product.UpdatedAt, product.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errProductExists
		}
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errProductMissing
	}
	return nil
}

func (s *SQLiteStorage) GetProduct(ctx context.Context, productID string) (*Product, error) {
	query := `SELECT id, name, slug, description, logo_url, created_at, updated_at FROM products WHERE id=?`
	row := s.db.QueryRowContext(ctx, query, productID)
	product := &Product{}
	var description, logoURL sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := row.Scan(&product.ID, &product.Name, &product.Slug, &description, &logoURL, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errProductMissing
	}
	if err != nil {
		return nil, err
	}
	product.Description = description.String
	product.LogoURL = logoURL.String
	product.CreatedAt = createdAt.Time
	product.UpdatedAt = updatedAt.Time
	return product, nil
}

func (s *SQLiteStorage) GetProductBySlug(ctx context.Context, slug string) (*Product, error) {
	query := `SELECT id, name, slug, description, logo_url, created_at, updated_at FROM products WHERE slug_lower=?`
	row := s.db.QueryRowContext(ctx, query, strings.ToLower(slug))
	product := &Product{}
	var description, logoURL sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := row.Scan(&product.ID, &product.Name, &product.Slug, &description, &logoURL, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errProductMissing
	}
	if err != nil {
		return nil, err
	}
	product.Description = description.String
	product.LogoURL = logoURL.String
	product.CreatedAt = createdAt.Time
	product.UpdatedAt = updatedAt.Time
	return product, nil
}

func (s *SQLiteStorage) ListProducts(ctx context.Context) ([]*Product, error) {
	query := `SELECT id, name, slug, description, logo_url, created_at, updated_at FROM products ORDER BY name`
	rows, err := s.db.QueryContext(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	products := make([]*Product, 0)
	for rows.Next() {
		product := &Product{}
		var description, logoURL sql.NullString
		var createdAt, updatedAt sqliteTimeValue
		if err := rows.Scan(&product.ID, &product.Name, &product.Slug, &description, &logoURL, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		product.Description = description.String
		product.LogoURL = logoURL.String
		product.CreatedAt = createdAt.Time
		product.UpdatedAt = updatedAt.Time
		products = append(products, product)
	}
	return products, rows.Err()
}

func (s *SQLiteStorage) DeleteProduct(ctx context.Context, productID string) error {
	query := `DELETE FROM products WHERE id=?`
	result, err := s.db.ExecContext(ctx, query, productID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errProductMissing
	}
	return nil
}

// ==================== Plan Storage Methods ====================

func (s *SQLiteStorage) SavePlan(ctx context.Context, plan *Plan) error {
	if plan == nil {
		return fmt.Errorf("plan is nil")
	}
	now := time.Now()
	if plan.CreatedAt.IsZero() {
		plan.CreatedAt = now
	}
	plan.UpdatedAt = now
	slugKey := plan.ProductID + ":" + strings.ToLower(plan.Slug)

	metadataJSON, err := json.Marshal(plan.Metadata)
	if err != nil {
		return err
	}

	query := `INSERT INTO plans (id, product_id, name, slug, slug_key, description, price, currency, billing_cycle, trial_days, is_active, display_order, metadata, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		plan.ID, plan.ProductID, plan.Name, plan.Slug, slugKey,
		plan.Description, plan.Price, plan.Currency, plan.BillingCycle,
		plan.TrialDays, plan.IsActive, plan.DisplayOrder, string(metadataJSON),
		plan.CreatedAt, plan.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errPlanExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdatePlan(ctx context.Context, plan *Plan) error {
	if plan == nil {
		return fmt.Errorf("plan is nil")
	}
	plan.UpdatedAt = time.Now()
	slugKey := plan.ProductID + ":" + strings.ToLower(plan.Slug)

	metadataJSON, err := json.Marshal(plan.Metadata)
	if err != nil {
		return err
	}

	query := `UPDATE plans SET product_id=?, name=?, slug=?, slug_key=?, description=?, price=?, currency=?, billing_cycle=?, trial_days=?, is_active=?, display_order=?, metadata=?, updated_at=? WHERE id=?`
	result, err := s.db.ExecContext(ctx, query,
		plan.ProductID, plan.Name, plan.Slug, slugKey,
		plan.Description, plan.Price, plan.Currency, plan.BillingCycle,
		plan.TrialDays, plan.IsActive, plan.DisplayOrder, string(metadataJSON),
		plan.UpdatedAt, plan.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errPlanExists
		}
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errPlanMissing
	}
	return nil
}

func (s *SQLiteStorage) GetPlan(ctx context.Context, planID string) (*Plan, error) {
	query := `SELECT id, product_id, name, slug, description, price, currency, billing_cycle, trial_days, is_active, display_order, metadata, created_at, updated_at FROM plans WHERE id=?`
	row := s.db.QueryRowContext(ctx, query, planID)
	return s.scanPlan(row)
}

func (s *SQLiteStorage) GetPlanBySlug(ctx context.Context, productID, slug string) (*Plan, error) {
	slugKey := productID + ":" + strings.ToLower(slug)
	query := `SELECT id, product_id, name, slug, description, price, currency, billing_cycle, trial_days, is_active, display_order, metadata, created_at, updated_at FROM plans WHERE slug_key=?`
	row := s.db.QueryRowContext(ctx, query, slugKey)
	return s.scanPlan(row)
}

func (s *SQLiteStorage) FindPlanBySlug(ctx context.Context, slug string) (*Plan, error) {
	query := `SELECT id, product_id, name, slug, description, price, currency, billing_cycle, trial_days, is_active, display_order, metadata, created_at, updated_at FROM plans WHERE LOWER(slug)=LOWER(?) LIMIT 1`
	row := s.db.QueryRowContext(ctx, query, slug)
	return s.scanPlan(row)
}

func (s *SQLiteStorage) ListPlansByProduct(ctx context.Context, productID string) ([]*Plan, error) {
	query := `SELECT id, product_id, name, slug, description, price, currency, billing_cycle, trial_days, is_active, display_order, metadata, created_at, updated_at FROM plans WHERE product_id=? ORDER BY display_order, name`
	rows, err := s.db.QueryContext(ctx, query, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	plans := make([]*Plan, 0)
	for rows.Next() {
		plan, err := s.scanPlanRow(rows)
		if err != nil {
			return nil, err
		}
		plans = append(plans, plan)
	}
	return plans, rows.Err()
}

func (s *SQLiteStorage) DeletePlan(ctx context.Context, planID string) error {
	query := `DELETE FROM plans WHERE id=?`
	result, err := s.db.ExecContext(ctx, query, planID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errPlanMissing
	}
	return nil
}

func (s *SQLiteStorage) scanPlan(scanner productRowScanner) (*Plan, error) {
	plan := &Plan{}
	var description sql.NullString
	var metadataJSON sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&plan.ID, &plan.ProductID, &plan.Name, &plan.Slug, &description,
		&plan.Price, &plan.Currency, &plan.BillingCycle, &plan.TrialDays,
		&plan.IsActive, &plan.DisplayOrder, &metadataJSON,
		&createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errPlanMissing
	}
	if err != nil {
		return nil, err
	}
	plan.Description = description.String
	plan.CreatedAt = createdAt.Time
	plan.UpdatedAt = updatedAt.Time
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &plan.Metadata)
	}
	return plan, nil
}

func (s *SQLiteStorage) scanPlanRow(scanner productRowScanner) (*Plan, error) {
	plan := &Plan{}
	var description sql.NullString
	var metadataJSON sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&plan.ID, &plan.ProductID, &plan.Name, &plan.Slug, &description,
		&plan.Price, &plan.Currency, &plan.BillingCycle, &plan.TrialDays,
		&plan.IsActive, &plan.DisplayOrder, &metadataJSON,
		&createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	plan.Description = description.String
	plan.CreatedAt = createdAt.Time
	plan.UpdatedAt = updatedAt.Time
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &plan.Metadata)
	}
	return plan, nil
}

// ==================== Feature Storage Methods ====================

func (s *SQLiteStorage) SaveFeature(ctx context.Context, feature *Feature) error {
	if feature == nil {
		return fmt.Errorf("feature is nil")
	}
	now := time.Now()
	if feature.CreatedAt.IsZero() {
		feature.CreatedAt = now
	}
	feature.UpdatedAt = now
	slugKey := feature.ProductID + ":" + strings.ToLower(feature.Slug)

	query := `INSERT INTO features (id, product_id, name, slug, slug_key, description, category, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err := s.db.ExecContext(ctx, query,
		feature.ID, feature.ProductID, feature.Name, feature.Slug, slugKey,
		feature.Description, feature.Category,
		feature.CreatedAt, feature.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errFeatureExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateFeature(ctx context.Context, feature *Feature) error {
	if feature == nil {
		return fmt.Errorf("feature is nil")
	}
	feature.UpdatedAt = time.Now()
	slugKey := feature.ProductID + ":" + strings.ToLower(feature.Slug)

	query := `UPDATE features SET product_id=?, name=?, slug=?, slug_key=?, description=?, category=?, updated_at=? WHERE id=?`
	result, err := s.db.ExecContext(ctx, query,
		feature.ProductID, feature.Name, feature.Slug, slugKey,
		feature.Description, feature.Category,
		feature.UpdatedAt, feature.ID)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errFeatureExists
		}
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errFeatureMissing
	}
	return nil
}

func (s *SQLiteStorage) GetFeature(ctx context.Context, featureID string) (*Feature, error) {
	query := `SELECT id, product_id, name, slug, description, category, created_at, updated_at FROM features WHERE id=?`
	row := s.db.QueryRowContext(ctx, query, featureID)
	feature := &Feature{}
	var description, category sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := row.Scan(&feature.ID, &feature.ProductID, &feature.Name, &feature.Slug, &description, &category, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errFeatureMissing
	}
	if err != nil {
		return nil, err
	}
	feature.Description = description.String
	feature.Category = category.String
	feature.CreatedAt = createdAt.Time
	feature.UpdatedAt = updatedAt.Time
	return feature, nil
}

func (s *SQLiteStorage) GetFeatureBySlug(ctx context.Context, productID, slug string) (*Feature, error) {
	slugKey := productID + ":" + strings.ToLower(slug)
	query := `SELECT id, product_id, name, slug, description, category, created_at, updated_at FROM features WHERE slug_key=?`
	row := s.db.QueryRowContext(ctx, query, slugKey)
	feature := &Feature{}
	var description, category sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := row.Scan(&feature.ID, &feature.ProductID, &feature.Name, &feature.Slug, &description, &category, &createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errFeatureMissing
	}
	if err != nil {
		return nil, err
	}
	feature.Description = description.String
	feature.Category = category.String
	feature.CreatedAt = createdAt.Time
	feature.UpdatedAt = updatedAt.Time
	return feature, nil
}

func (s *SQLiteStorage) ListFeaturesByProduct(ctx context.Context, productID string) ([]*Feature, error) {
	query := `SELECT id, product_id, name, slug, description, category, created_at, updated_at FROM features WHERE product_id=? ORDER BY category, name`
	rows, err := s.db.QueryContext(ctx, query, productID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	features := make([]*Feature, 0)
	for rows.Next() {
		feature := &Feature{}
		var description, category sql.NullString
		var createdAt, updatedAt sqliteTimeValue
		if err := rows.Scan(&feature.ID, &feature.ProductID, &feature.Name, &feature.Slug, &description, &category, &createdAt, &updatedAt); err != nil {
			return nil, err
		}
		feature.Description = description.String
		feature.Category = category.String
		feature.CreatedAt = createdAt.Time
		feature.UpdatedAt = updatedAt.Time
		features = append(features, feature)
	}
	return features, rows.Err()
}

func (s *SQLiteStorage) DeleteFeature(ctx context.Context, featureID string) error {
	query := `DELETE FROM features WHERE id=?`
	result, err := s.db.ExecContext(ctx, query, featureID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errFeatureMissing
	}
	return nil
}

// ==================== Feature Scope Storage Methods ====================

func (s *SQLiteStorage) SaveFeatureScope(ctx context.Context, scope *FeatureScope) error {
	if scope == nil {
		return fmt.Errorf("feature scope is nil")
	}
	now := time.Now()
	if scope.CreatedAt.IsZero() {
		scope.CreatedAt = now
	}
	scope.UpdatedAt = now

	metadataJSON, err := json.Marshal(scope.Metadata)
	if err != nil {
		return err
	}

	query := `INSERT INTO feature_scopes (id, feature_id, name, slug, permission, scope_limit, metadata, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		scope.ID, scope.FeatureID, scope.Name, scope.Slug,
		string(scope.Permission), scope.Limit, string(metadataJSON),
		scope.CreatedAt, scope.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errFeatureScopeExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdateFeatureScope(ctx context.Context, scope *FeatureScope) error {
	if scope == nil {
		return fmt.Errorf("feature scope is nil")
	}
	scope.UpdatedAt = time.Now()

	metadataJSON, err := json.Marshal(scope.Metadata)
	if err != nil {
		return err
	}

	query := `UPDATE feature_scopes SET feature_id=?, name=?, slug=?, permission=?, scope_limit=?, metadata=?, updated_at=? WHERE id=?`
	result, err := s.db.ExecContext(ctx, query,
		scope.FeatureID, scope.Name, scope.Slug,
		string(scope.Permission), scope.Limit, string(metadataJSON),
		scope.UpdatedAt, scope.ID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errFeatureScopeMissing
	}
	return nil
}

func (s *SQLiteStorage) GetFeatureScope(ctx context.Context, scopeID string) (*FeatureScope, error) {
	query := `SELECT id, feature_id, name, slug, permission, scope_limit, metadata, created_at, updated_at FROM feature_scopes WHERE id=?`
	row := s.db.QueryRowContext(ctx, query, scopeID)
	return s.scanFeatureScope(row)
}

func (s *SQLiteStorage) ListFeatureScopes(ctx context.Context, featureID string) ([]*FeatureScope, error) {
	query := `SELECT id, feature_id, name, slug, permission, scope_limit, metadata, created_at, updated_at FROM feature_scopes WHERE feature_id=? ORDER BY name`
	rows, err := s.db.QueryContext(ctx, query, featureID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	scopes := make([]*FeatureScope, 0)
	for rows.Next() {
		scope, err := s.scanFeatureScopeRow(rows)
		if err != nil {
			return nil, err
		}
		scopes = append(scopes, scope)
	}
	return scopes, rows.Err()
}

func (s *SQLiteStorage) DeleteFeatureScope(ctx context.Context, scopeID string) error {
	query := `DELETE FROM feature_scopes WHERE id=?`
	result, err := s.db.ExecContext(ctx, query, scopeID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errFeatureScopeMissing
	}
	return nil
}

func (s *SQLiteStorage) scanFeatureScope(scanner productRowScanner) (*FeatureScope, error) {
	scope := &FeatureScope{}
	var permission string
	var metadataJSON sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&scope.ID, &scope.FeatureID, &scope.Name, &scope.Slug,
		&permission, &scope.Limit, &metadataJSON,
		&createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errFeatureScopeMissing
	}
	if err != nil {
		return nil, err
	}
	scope.Permission = ScopePermission(permission)
	scope.CreatedAt = createdAt.Time
	scope.UpdatedAt = updatedAt.Time
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &scope.Metadata)
	}
	return scope, nil
}

func (s *SQLiteStorage) scanFeatureScopeRow(scanner productRowScanner) (*FeatureScope, error) {
	scope := &FeatureScope{}
	var permission string
	var metadataJSON sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&scope.ID, &scope.FeatureID, &scope.Name, &scope.Slug,
		&permission, &scope.Limit, &metadataJSON,
		&createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	scope.Permission = ScopePermission(permission)
	scope.CreatedAt = createdAt.Time
	scope.UpdatedAt = updatedAt.Time
	if metadataJSON.Valid && metadataJSON.String != "" {
		json.Unmarshal([]byte(metadataJSON.String), &scope.Metadata)
	}
	return scope, nil
}

// ==================== Plan Feature Storage Methods ====================

func (s *SQLiteStorage) SavePlanFeature(ctx context.Context, pf *PlanFeature) error {
	if pf == nil {
		return fmt.Errorf("plan feature is nil")
	}
	now := time.Now()
	if pf.CreatedAt.IsZero() {
		pf.CreatedAt = now
	}
	pf.UpdatedAt = now

	overridesJSON, err := json.Marshal(pf.ScopeOverrides)
	if err != nil {
		return err
	}

	query := `INSERT INTO plan_features (id, plan_id, feature_id, enabled, scope_overrides, created_at, updated_at)
			  VALUES (?, ?, ?, ?, ?, ?, ?)`
	_, err = s.db.ExecContext(ctx, query,
		pf.ID, pf.PlanID, pf.FeatureID, pf.Enabled, string(overridesJSON),
		pf.CreatedAt, pf.UpdatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "UNIQUE constraint failed") {
			return errPlanFeatureExists
		}
		return err
	}
	return nil
}

func (s *SQLiteStorage) UpdatePlanFeature(ctx context.Context, pf *PlanFeature) error {
	if pf == nil {
		return fmt.Errorf("plan feature is nil")
	}
	pf.UpdatedAt = time.Now()

	overridesJSON, err := json.Marshal(pf.ScopeOverrides)
	if err != nil {
		return err
	}

	query := `UPDATE plan_features SET enabled=?, scope_overrides=?, updated_at=? WHERE plan_id=? AND feature_id=?`
	result, err := s.db.ExecContext(ctx, query,
		pf.Enabled, string(overridesJSON), pf.UpdatedAt,
		pf.PlanID, pf.FeatureID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errPlanFeatureMissing
	}
	return nil
}

func (s *SQLiteStorage) GetPlanFeature(ctx context.Context, planID, featureID string) (*PlanFeature, error) {
	query := `SELECT id, plan_id, feature_id, enabled, scope_overrides, created_at, updated_at FROM plan_features WHERE plan_id=? AND feature_id=?`
	row := s.db.QueryRowContext(ctx, query, planID, featureID)
	return s.scanPlanFeature(row)
}

func (s *SQLiteStorage) ListPlanFeatures(ctx context.Context, planID string) ([]*PlanFeature, error) {
	query := `SELECT id, plan_id, feature_id, enabled, scope_overrides, created_at, updated_at FROM plan_features WHERE plan_id=?`
	rows, err := s.db.QueryContext(ctx, query, planID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	pfs := make([]*PlanFeature, 0)
	for rows.Next() {
		pf, err := s.scanPlanFeatureRow(rows)
		if err != nil {
			return nil, err
		}
		pfs = append(pfs, pf)
	}
	return pfs, rows.Err()
}

func (s *SQLiteStorage) DeletePlanFeature(ctx context.Context, planID, featureID string) error {
	query := `DELETE FROM plan_features WHERE plan_id=? AND feature_id=?`
	result, err := s.db.ExecContext(ctx, query, planID, featureID)
	if err != nil {
		return err
	}
	rowsAffected, _ := result.RowsAffected()
	if rowsAffected == 0 {
		return errPlanFeatureMissing
	}
	return nil
}

func (s *SQLiteStorage) scanPlanFeature(scanner productRowScanner) (*PlanFeature, error) {
	pf := &PlanFeature{}
	var overridesJSON sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&pf.ID, &pf.PlanID, &pf.FeatureID, &pf.Enabled, &overridesJSON,
		&createdAt, &updatedAt)
	if err == sql.ErrNoRows {
		return nil, errPlanFeatureMissing
	}
	if err != nil {
		return nil, err
	}
	pf.CreatedAt = createdAt.Time
	pf.UpdatedAt = updatedAt.Time
	if overridesJSON.Valid && overridesJSON.String != "" {
		json.Unmarshal([]byte(overridesJSON.String), &pf.ScopeOverrides)
	}
	return pf, nil
}

func (s *SQLiteStorage) scanPlanFeatureRow(scanner productRowScanner) (*PlanFeature, error) {
	pf := &PlanFeature{}
	var overridesJSON sql.NullString
	var createdAt, updatedAt sqliteTimeValue
	err := scanner.Scan(&pf.ID, &pf.PlanID, &pf.FeatureID, &pf.Enabled, &overridesJSON,
		&createdAt, &updatedAt)
	if err != nil {
		return nil, err
	}
	pf.CreatedAt = createdAt.Time
	pf.UpdatedAt = updatedAt.Time
	if overridesJSON.Valid && overridesJSON.String != "" {
		json.Unmarshal([]byte(overridesJSON.String), &pf.ScopeOverrides)
	}
	return pf, nil
}

// ==================== Entitlement Computation ====================

func (s *SQLiteStorage) ComputeLicenseEntitlements(ctx context.Context, productID, planID string) (*LicenseEntitlements, error) {
	// Get product
	product, err := s.GetProduct(ctx, productID)
	if err != nil {
		return nil, err
	}

	// Get plan
	plan, err := s.GetPlan(ctx, planID)
	if err != nil {
		return nil, err
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

	// Get all plan features
	planFeatures, err := s.ListPlanFeatures(ctx, planID)
	if err != nil {
		return nil, err
	}

	for _, pf := range planFeatures {
		if !pf.Enabled {
			continue
		}

		feature, err := s.GetFeature(ctx, pf.FeatureID)
		if err != nil {
			continue
		}

		featureGrant := FeatureGrant{
			FeatureID:   feature.ID,
			FeatureSlug: feature.Slug,
			Category:    feature.Category,
			Enabled:     true,
			Scopes:      make(map[string]ScopeGrant),
		}

		// Get all scopes for this feature
		scopes, err := s.ListFeatureScopes(ctx, feature.ID)
		if err != nil {
			continue
		}

		for _, scope := range scopes {
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
