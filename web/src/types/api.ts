// API Types for Licensing Server

export interface User {
    id: string;
    username: string;
}

export interface Session {
    id: string;
    userId: string;
    username: string;
    createdAt: string;
    expiresAt: string;
}

export interface License {
    id: string;
    license_key: string;
    email: string;
    client_id: string;
    product_id?: string;
    plan_id?: string;
    plan_slug: string;
    check_mode?: string;
    check_interval_seconds?: number;
    issued_at: string;
    expires_at: string;
    is_revoked: boolean;
    revoked_at?: string;
    revoke_reason?: string;
    is_activated: boolean;
    last_activated_at?: string;
    current_activations: number;
    max_devices: number;
    device_count: number;
    devices: Record<string, LicenseDevice>;
    authorized_users?: Record<string, LicenseIdentity>;
    entitlements?: LicenseEntitlements;
    is_trial: boolean;
    trial_started_at?: string;
    trial_device_fingerprint?: string;
    // Populated by API for display
    client?: Client;
    product?: Product;
    plan?: Plan;
}

export interface LicenseDevice {
    fingerprint: string;
    activated_at: string;
    last_seen_at: string;
}

export interface LicenseIdentity {
    email: string;
    client_id?: string;
    provider_client_id?: string;
    granted_at: string;
}

export interface LicenseEntitlements {
    product_id?: string;
    product_slug?: string;
    plan_id?: string;
    plan_slug?: string;
    features?: Record<string, FeatureGrant>;
}

export interface FeatureGrant {
    feature_id?: string;
    feature_slug: string;
    category?: string;
    enabled: boolean;
    scopes?: Record<string, ScopeGrant>;
}

export interface ScopeGrant {
    scope_id?: string;
    scope_slug: string;
    permission: ScopePermissionValue;
    limit?: number;
    metadata?: Record<string, string>;
}

export type ScopePermissionValue = 'allow' | 'deny' | 'limit';

export interface ScopePermission {
    permission: ScopePermissionValue;
    limit?: number;
}

export interface Client {
    id: string;
    username?: string;
    email: string;
    status: 'active' | 'banned';
    created_at: string;
    updated_at: string;
    banned_at?: string;
    ban_reason?: string;
}

export interface Product {
    id: string;
    name: string;
    slug: string;
    description?: string;
    logo_url?: string;
    created_at: string;
    updated_at: string;
}

export interface Plan {
    id: string;
    product_id: string;
    name: string;
    slug: string;
    description?: string;
    price: number;
    currency: string;
    billing_cycle: 'monthly' | 'yearly' | 'weekly' | 'lifetime';
    is_trial: boolean;
    trial_days: number;
    is_active: boolean;
    price_unit?: string;
    created_at: string;
    updated_at: string;
}

export interface Feature {
    id: string;
    product_id: string;
    name: string;
    slug: string;
    description?: string;
    category?: string;
    type?: 'boolean' | 'metered' | 'scoped';
    created_at: string;
    updated_at: string;
}

export interface PlanFeature {
    id: string;
    plan_id: string;
    feature_id: string;
    enabled: boolean;
    limit?: number;
    scope_overrides?: Record<string, ScopePermission>;
    created_at: string;
    updated_at: string;
    feature?: Feature;
    scopes?: FeatureScope[];
}

export interface FeatureScope {
    id: string;
    feature_id: string;
    name: string;
    slug: string;
    permission: string;
    limit?: number;
    metadata?: Record<string, string>;
    created_at: string;
    updated_at: string;
}

export interface AdminUser {
    id: string;
    username: string;
    created_at: string;
    updated_at: string;
}

export interface APIKey {
    id: string;
    user_id: string;
    client_id?: string;
    prefix: string;
    created_at: string;
    last_used_at?: string;
}

export interface Activation {
    id: string;
    license_id: string;
    client_id: string;
    device_fingerprint: string;
    ip_address: string;
    user_agent: string;
    success: boolean;
    message: string;
    timestamp: string;
}

// Dashboard data
export interface DashboardStats {
    total_licenses: number;
    active_licenses: number;
    revoked_licenses: number;
    expired_licenses: number;
    total_clients: number;
    active_clients: number;
    banned_clients: number;
    total_products: number;
    total_admins: number;
    recent_licenses: License[];
}

// API Response types
export interface ApiResponse<T> {
    success: boolean;
    data?: T;
    error?: string;
    message?: string;
}

export interface LoginRequest {
    email?: string;
    username?: string;
    password: string;
}

export interface LoginResponse {
    success: boolean;
    user?: User;
    error?: string;
}

export interface CreateLicenseRequest {
    client_id: string;
    product_id?: string;
    plan_id?: string;
    plan_slug: string;
    duration_days?: number;
    max_devices?: number;
    check_mode?: string;
    check_interval_seconds?: number;
    is_trial?: boolean;
    feature_scopes?: FeatureScopeSelection[];
}

export interface FeatureScopeSelection {
    feature_id?: string;
    feature_slug: string;
    enabled: boolean;
    scopes?: ScopeSelection[];
}

export interface ScopeSelection {
    scope_id?: string;
    scope_slug: string;
    permission: ScopePermissionValue;
    limit?: number;
}

export interface CreateClientRequest {
    email: string;
    username?: string;
    password?: string;
}

export interface CreateProductRequest {
    name: string;
    slug: string;
    description?: string;
    logo_url?: string;
}

export interface CreatePlanRequest {
    product_id: string;
    name: string;
    slug?: string;
    description?: string;
    price?: number; // dollars (frontend)
    price_unit?: string; // none|feature|user|device|storage|<custom>
    custom_price_unit?: string; // none|feature|user|device|storage|<custom>
    currency?: string;
    billing_cycle?: string;
    is_trial?: boolean;
    trial_days?: number;
    is_active?: boolean;
}

export interface CreateFeatureRequest {
    product_id: string;
    name: string;
    slug: string;
    description?: string;
    category?: string;
    type?: 'boolean' | 'metered' | 'scoped';
}

export interface CreateScopeRequest {
    feature_id: string;
    name: string;
    slug: string;
    permission?: string;
    limit?: number;
    metadata?: Record<string, string>;
}

export interface CreateAdminUserRequest {
    username: string;
    password: string;
}

export interface ProductStats {
    plans: number;
    features: number;
}

// Messaging
export type EmailProviderType = 'smtp' | 'sendgrid' | 'ses' | 'custom';

export type EmailMessageStatus = 'queued' | 'sending' | 'retrying' | 'sent' | 'failed' | 'bounced';

export interface EmailProvider {
    id: string;
    name: string;
    slug: string;
    type: EmailProviderType;
    priority: number;
    max_retries: number;
    retry_base_ms: number;
    retry_max_ms: number;
    retry_jitter_pct: number;
    is_default: boolean;
    enabled: boolean;
    success_count: number;
    failure_count: number;
    config: Record<string, unknown>;
    metadata?: Record<string, string>;
    created_at: string;
    updated_at: string;
}

export interface SaveEmailProviderRequest {
    name: string;
    slug: string;
    type: EmailProviderType;
    priority?: number;
    max_retries?: number;
    retry_base_ms?: number;
    retry_max_ms?: number;
    retry_jitter_pct?: number;
    is_default?: boolean;
    enabled?: boolean;
    config: Record<string, unknown>;
    metadata?: Record<string, string>;
}

export interface EmailProviderTestRequest {
    provider: SaveEmailProviderRequest;
    test_email: string;
}

export interface EmailProviderTestResponse {
    success: boolean;
    message?: string;
}

export interface EmailTemplate {
    id: string;
    name: string;
    slug: string;
    category: string;
    subject: string;
    html_body: string;
    text_body: string;
    description?: string;
    metadata?: Record<string, unknown>;
    default_provider_id?: string;
    max_retries_override?: number;
    created_at: string;
    updated_at: string;
}

export interface SaveEmailTemplateRequest {
    name: string;
    slug: string;
    category: string;
    subject: string;
    html_body: string;
    text_body: string;
    description?: string;
    metadata?: Record<string, unknown>;
    default_provider_id?: string;
    max_retries_override?: number;
}

export interface EmailTemplateRoute {
    id: string;
    template_id?: string;
    category?: string;
    provider_id: string;
    priority: number;
    retry_limit_override?: number;
    enabled: boolean;
    created_at: string;
    updated_at: string;
}

export interface EmailMessage {
    id: string;
    template_id: string;
    provider_id?: string;
    to: string;
    cc?: string[];
    bcc?: string[];
    subject: string;
    rendered_html?: string;
    rendered_text?: string;
    variables?: Record<string, unknown>;
    metadata?: Record<string, string>;
    status: EmailMessageStatus;
    retry_count: number;
    max_retries: number;
    failover_count: number;
    last_error?: string;
    next_attempt_at: string;
    last_attempt_at: string;
    created_at: string;
    updated_at: string;
}

export interface EmailComposePreview {
    recipient: string;
    subject: string;
    html?: string;
    text?: string;
}

export interface EmailAttachment {
    filename: string;
    content_type: string;
    data_base64: string;
    size?: number;
}

export interface EmailComposeRequest {
    template_id: string;
    client_ids?: string[];
    additional_emails?: string[];
    variables?: Record<string, unknown>;
    attachments?: EmailAttachment[];
    preview?: boolean;
}

export interface EmailComposeResponse {
    preview?: EmailComposePreview;
    queued_count?: number;
    message_ids?: string[];
    attachments_count?: number;
}

export type LicenseCheckMode = 'none' | 'each-run' | 'monthly' | 'yearly' | 'custom';

// Offline tokens & signing keys
export interface OfflineValidationToken {
    token: string;
    license_key: string;
    client_id: string;
    device_fingerprint: string;
    signing_key_id?: string;
    valid_until: string;
    usage_count: number;
    max_uses: number;
    is_revoked: boolean;
    created_at: string;
    revoked_at?: string;
    revoked_by?: string;
    revoked_reason?: string;
}

export interface SignedBundleResponse {
    payload: Record<string, unknown>;
    signature: string;
}

export interface SigningKeyMeta {
    id: string;
    name?: string;
    public_key: string; // base64
    is_active: boolean;
    created_at: string;
}
