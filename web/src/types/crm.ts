export type CRMUserRole = 'owner' | 'admin' | 'member' | 'viewer';
export type CRMUserStatus = 'active' | 'invited' | 'disabled';
export type CRMTenantStatus = 'active' | 'suspended' | 'archived';

export interface CRMUserView {
    id: string;
    email: string;
    username: string;
    role: CRMUserRole;
    roles: string[];
    status: CRMUserStatus;
    last_login_at?: string;
}

export interface CRMTenantView {
    id: string;
    name: string;
    slug: string;
    status: CRMTenantStatus;
    industry?: string;
    region?: string;
    billing_email?: string;
    support_email?: string;
    metadata?: Record<string, string>;
    created_at: string;
    updated_at: string;
}

export interface CRMProductAccess {
    product_id: string;
    product_slug: string;
    plan_id: string;
    plan_slug: string;
    features: string[];
    status: string;
    expires_at: string;
    effective_at: string;
}

export interface CRMLoginRequest {
    identifier: string;
    password: string;
    scope?: string;
    device_id?: string;
}

export interface CRMLoginResponse {
    access_token: string;
    refresh_token: string;
    token_type: 'Bearer';
    expires_in: number;
    refresh_expires_in: number;
    scope: string;
    user: CRMUserView;
    tenant: CRMTenantView;
    products?: CRMProductAccess[];
}

export interface CRMSessionResponse {
    user: CRMUserView;
    tenant: CRMTenantView;
    products?: CRMProductAccess[];
    scope: string;
    issued_at: string;
    expires_at: string;
}

export interface CRMTenantProvisionRequest {
    name: string;
    slug: string;
    industry?: string;
    region?: string;
    billing_email?: string;
    support_email?: string;
    metadata?: Record<string, string>;
    admin_user: {
        email: string;
        username: string;
        password: string;
        role?: CRMUserRole;
    };
}

export interface CRMTenantProductsResponse {
    tenant_id: string;
    products: CRMProductAccess[];
}

export interface CRMScopeOverride {
    permission: string;
    limit?: number;
    metadata?: Record<string, string>;
}

export interface CRMFeatureOverride {
    enabled?: boolean;
    scopes?: Record<string, CRMScopeOverride>;
    metadata?: Record<string, string>;
}

export interface CRMEntitlementAssignmentPayload {
    tenant_id?: string;
    contact_id?: string;
    client_id?: string;
    product_id: string;
    plan_id?: string;
    plan_slug?: string;
    effective_at?: string;
    expires_at?: string;
    feature_overrides?: Record<string, CRMFeatureOverride>;
}

export interface CRMEntitlementResponse {
    binding_id: string;
    status: string;
    message: string;
}

export interface CRMDeviceLedgerRecord {
    tenant_id: string;
    client_id?: string;
    license_id?: string;
    device_fingerprint: string;
    last_seen_at: string;
    last_sync_at: string;
    pending_revocation: boolean;
    revocation_epoch: number;
    metadata?: Record<string, string>;
}

export interface CRMServiceAccountRequest {
    tenant_id?: string;
    name: string;
    description?: string;
    scopes: string[];
}

export interface CRMServiceAccountResponse {
    id: string;
    tenant_id: string;
    name: string;
    scopes: string[];
    secret: string;
}

export interface CRMOfflineBundle {
    license_id: string;
    version: string;
    issued_at: string;
    expires_at: string;
    revocation_epoch: number;
    bundle: string;
    signature: string;
}
