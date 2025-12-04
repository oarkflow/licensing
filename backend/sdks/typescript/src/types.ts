export interface LicensingClientOptions {
    serverUrl: string;
    allowInsecureHttp?: boolean;
    httpTimeoutMs?: number;
}

export interface ActivationPayload {
    email: string;
    clientId: string;
    licenseKey: string;
    deviceFingerprint: string;
}

/**
 * Represents a JSON file containing license activation credentials.
 * Expected file format:
 * {
 *   "email": "user@example.com",
 *   "client_id": "client-123",
 *   "license_key": "XXXX-XXXX-..."
 * }
 */
export interface CredentialsFile {
    email: string;
    client_id: string;
    license_key: string;
}

export interface LicenseDevice {
    fingerprint: string;
    activated_at: string;
    last_seen_at: string;
}

export type ScopePermission = 'allow' | 'deny' | 'limit';

export interface ScopeGrant {
    scope_id: string;
    scope_slug: string;
    permission: ScopePermission;
    limit?: number;
    metadata?: Record<string, unknown>;
}

export interface FeatureGrant {
    feature_id: string;
    feature_slug: string;
    category?: string;
    enabled: boolean;
    scopes?: Record<string, ScopeGrant>;
}

export interface LicenseEntitlements {
    product_id: string;
    product_slug: string;
    plan_id: string;
    plan_slug: string;
    features: Record<string, FeatureGrant>;
}

export interface LicenseData {
    id: string;
    client_id: string;
    subject_client_id: string;
    email: string;
    product_id?: string;
    plan_id?: string;
    plan_slug: string;
    relationship: string;
    granted_by?: string;
    license_key: string;
    issued_at: string;
    expires_at: string;
    last_activated_at: string;
    current_activations: number;
    max_devices: number;
    device_count: number;
    is_revoked: boolean;
    revoked_at?: string;
    revoke_reason?: string;
    devices: LicenseDevice[];
    device_fingerprint?: string;
    check_mode: string;
    check_interval_seconds: number;
    next_check_at: string;
    last_check_at: string;
    entitlements?: LicenseEntitlements;

    // Trial-related fields
    is_trial: boolean;
    trial_started_at?: string;
    trial_expires_at?: string;
}

/**
 * Represents the current status of a trial license.
 */
export enum TrialStatus {
    NotTrial = 'not_trial',
    Active = 'active',
    Expired = 'expired'
}

/**
 * Contains information about the trial status and expiration.
 */
export interface TrialInfo {
    status: TrialStatus;
    isTrial: boolean;
    isExpired: boolean;
    daysRemaining: number;
    expiresAt?: Date;
    message: string;
    subscriptionUrl?: string;
}

/**
 * Request payload for starting a trial.
 */
export interface TrialRequest {
    email: string;
    device_fingerprint: string;
    product_id?: string;
    plan_id?: string;
    trial_days?: number;
}

/**
 * Request payload for checking trial eligibility.
 */
export interface TrialCheckRequest {
    device_fingerprint: string;
    product_id?: string;
}

/**
 * Response when checking trial eligibility.
 */
export interface TrialCheckResponse {
    eligible: boolean;
    has_used_trial: boolean;
    trial_expires_at?: string;
    message: string;
    subscription_url?: string;
}
