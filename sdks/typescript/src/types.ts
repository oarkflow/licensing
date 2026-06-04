export interface LicensingClientOptions {
    serverUrl: string;
    allowInsecureHttp?: boolean;
    httpTimeoutMs?: number;
    appName?: string;
    appVersion?: string;
    configDir?: string;
    licenseFile?: string;
    deviceKeyFile?: string;
    productId?: string;
}

export interface ActivationPayload {
    email: string;
    clientId: string;
    licenseKey: string;
    deviceFingerprint: string;
    productId?: string;
    replacementToken?: string;
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
    status?: string;
    label?: string;
    hardware_fingerprint?: string;
    hardware_confidence?: string;
    last_ip?: string;
    last_user_agent?: string;
    app_version?: string;
    proof_version?: number;
    device_key_id?: string;
    public_key_algorithm?: string;
    key_provider?: string;
    attestation_type?: string;
    attestation_status?: string;
    last_proof_at?: string;
    revoked_at?: string;
    revoked_reason?: string;
    replaced_by_fingerprint?: string;
    replacement_token_id?: string;
}

export type DeviceProofPurpose = 'activate' | 'verify' | 'trial';

export interface DeviceChallenge {
    challenge_id: string;
    nonce: string;
    purpose: DeviceProofPurpose;
    expires_at: string;
}

export interface DeviceProof {
    version: 2;
    purpose: DeviceProofPurpose;
    challenge_id: string;
    nonce: string;
    fingerprint: string;
    key_id: string;
    key_provider: string;
    public_key_alg: 'ed25519';
    public_key: string;
    signature: string;
    attestation?: Record<string, string>;
}

export interface ActivationRequest {
    email: string;
    client_id: string;
    license_key: string;
    device_fingerprint: string;
    product_id?: string;
    replacement_token?: string;
    device_proof?: DeviceProof;
}

export interface ActivationResponse {
    success: boolean;
    message: string;
    encrypted_license?: string;
    nonce?: string;
    signature?: string;
    public_key?: string;
    expires_at?: string;
}

export type ScopePermission = 'allow' | 'deny' | 'limit';

export interface ScopeGrant {
    scope_id: string;
    scope_slug: string;
    permission: ScopePermission;
    limit?: number;
    metadata?: Record<string, unknown>;
    flags?: Record<string, boolean>;
    settings?: Record<string, string>;
    limits?: Record<string, number>;
    usage?: Record<string, UsageGrant>;
    // Optional usage restrictions emitted by the server
    restrictions?: ScopeRestriction[];
}

export interface UsageGrant {
    limit?: number;
    window_seconds?: number;
    current?: number;
    reset_at?: string;
    strategy?: string;
    metadata?: Record<string, unknown>;
}

export type UsageRestrictionType = 'storage' | 'user' | 'device';

export interface ScopeRestriction {
    type: UsageRestrictionType;
    limit?: number;
    window_seconds?: number;
    metadata?: Record<string, unknown>;
}

export type SubjectType = 'storage' | 'user' | 'device';

export interface UsageContext {
    subjectType?: SubjectType;
    subjectID?: string;
    amount?: number; // amount requested (1 means single unit)
}

export interface FeatureGrant {
    feature_id: string;
    feature_slug: string;
    type?: 'boolean' | 'metered' | 'scoped';
    category?: string;
    enabled: boolean;
    metadata?: Record<string, string>;
    flags?: Record<string, boolean>;
    settings?: Record<string, string>;
    limits?: Record<string, number>;
    usage?: Record<string, UsageGrant>;
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
    trial_duration_days?: number;
    subscription_url?: string;
    device_proof?: DeviceProof;
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
    eligible?: boolean;
    has_used_trial?: boolean;
    eligible_for_trial?: boolean;
    trial_used?: boolean;
    device_fingerprint?: string;
    trial_expires_at?: string;
    trial_started_at?: string;
    trial_expired?: boolean;
    message: string;
    subscription_url?: string;
}
