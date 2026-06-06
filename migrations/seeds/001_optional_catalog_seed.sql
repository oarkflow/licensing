-- Optional catalog seed.
-- Run explicitly with:
--   migrator cli seed --include-raw=true --file=001_optional_catalog_seed.sql
--
-- Runtime startup does not execute this file. Product catalog data should be
-- created through Admin UI/API or explicit SQL seed execution.

INSERT OR IGNORE INTO products (
    id,
    name,
    slug,
    slug_lower,
    description,
    allow_trial,
    trial_interval,
    trial_interval_type,
    created_at,
    updated_at
) VALUES (
    'product_sample',
    'Sample Product',
    'sample-product',
    'sample-product',
    'Optional sample product for local catalog setup.',
    1,
    14,
    'days',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO plans (
    id,
    product_id,
    name,
    slug,
    slug_key,
    description,
    price,
    min_devices,
    max_devices,
    duration_days,
    price_per_device,
    currency,
    billing_cycle,
    trial_days,
    is_trial,
    is_active,
    display_order,
    metadata,
    created_at,
    updated_at
) VALUES
    (
        'plan_sample_trial',
        'product_sample',
        'Trial',
        'trial',
        'product_sample:trial',
        'Optional trial plan.',
        0,
        1,
        3,
        14,
        0,
        'USD',
        'one-time',
        14,
        1,
        1,
        0,
        '{}',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        'plan_sample_pro',
        'product_sample',
        'Pro',
        'pro',
        'product_sample:pro',
        'Optional paid plan.',
        9900,
        1,
        10,
        365,
        9900,
        'USD',
        'yearly',
        14,
        0,
        1,
        10,
        '{}',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    );

INSERT OR IGNORE INTO features (
    id,
    product_id,
    name,
    slug,
    slug_key,
    description,
    type,
    category,
    metadata,
    created_at,
    updated_at
) VALUES (
    'feature_sample_runtime',
    'product_sample',
    'Runtime',
    'runtime',
    'product_sample:runtime',
    'Optional runtime feature.',
    'scoped',
    'runtime',
    '{}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO feature_scopes (
    id,
    feature_id,
    name,
    slug,
    permission,
    scope_limit,
    metadata,
    created_at,
    updated_at
) VALUES (
    'scope_sample_runtime_start',
    'feature_sample_runtime',
    'Start',
    'start',
    'allow',
    0,
    '{"category":"Runtime"}',
    CURRENT_TIMESTAMP,
    CURRENT_TIMESTAMP
);

INSERT OR IGNORE INTO plan_features (
    id,
    plan_id,
    feature_id,
    enabled,
    scope_overrides,
    created_at,
    updated_at
) VALUES
    (
        'plan_feature_sample_trial_runtime',
        'plan_sample_trial',
        'feature_sample_runtime',
        1,
        '{"start":{"permission":"allow"}}',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    ),
    (
        'plan_feature_sample_pro_runtime',
        'plan_sample_pro',
        'feature_sample_runtime',
        1,
        '{"start":{"permission":"allow"}}',
        CURRENT_TIMESTAMP,
        CURRENT_TIMESTAMP
    );
