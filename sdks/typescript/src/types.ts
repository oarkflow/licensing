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

export interface LicenseDevice {
    fingerprint: string;
    activated_at: string;
    last_seen_at: string;
}

export interface LicenseData {
    id: string;
    client_id: string;
    subject_client_id: string;
    email: string;
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
}
