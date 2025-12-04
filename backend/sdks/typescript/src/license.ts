import { promises as fs } from "node:fs";
import { createPublicKey } from "node:crypto";
import { deriveTransportKey, decryptAesGcm, verifySignature } from "./crypto.js";
import { LicenseData, FeatureGrant, ScopeGrant, CredentialsFile, TrialStatus, TrialInfo } from "./types.js";

export interface StoredLicenseFile {
    encrypted_data: string;
    nonce: string;
    signature: string;
    public_key: string;
    device_fingerprint: string;
    expires_at: string;
}

export interface DecryptedLicense {
    sessionKey: Buffer;
    license: LicenseData;
}

/**
 * Load license activation credentials from a JSON file.
 *
 * @param path - Path to the credentials JSON file
 * @returns Promise resolving to the parsed credentials
 * @throws Error if the file cannot be read or parsed, or if required fields are missing
 *
 * @example
 * ```typescript
 * const creds = await loadCredentialsFile('./license-credentials.json');
 * // creds.email, creds.client_id, creds.license_key
 * ```
 */
export async function loadCredentialsFile(path: string): Promise<CredentialsFile> {
    const raw = await fs.readFile(path, "utf8");
    const parsed = JSON.parse(raw) as Partial<CredentialsFile>;

    if (!parsed.email) {
        throw new Error("credentials file missing 'email' field");
    }
    if (!parsed.client_id) {
        throw new Error("credentials file missing 'client_id' field");
    }
    if (!parsed.license_key) {
        throw new Error("credentials file missing 'license_key' field");
    }

    return parsed as CredentialsFile;
}

export async function loadLicenseFile(path: string): Promise<StoredLicenseFile> {
    const raw = await fs.readFile(path, "utf8");
    return JSON.parse(raw) as StoredLicenseFile;
}

export function decryptStoredLicense(stored: StoredLicenseFile): DecryptedLicense {
    const encrypted = Buffer.from(stored.encrypted_data, "base64");
    const nonce = Buffer.from(stored.nonce, "base64");
    const signature = Buffer.from(stored.signature, "base64");
    const publicKeyDer = Buffer.from(stored.public_key, "base64");
    const publicKey = createPublicKey({ key: publicKeyDer, format: "der", type: "spki" });

    if (!verifySignature(encrypted, signature, publicKey)) {
        throw new Error("stored license signature invalid");
    }

    const transportKey = deriveTransportKey(stored.device_fingerprint, nonce);
    const decrypted = decryptAesGcm(encrypted, nonce, transportKey);
    if (decrypted.length <= 32) {
        throw new Error("decrypted payload missing session key");
    }
    const sessionKey = decrypted.subarray(0, 32);
    const licensePayload = decrypted.subarray(32);
    const license = JSON.parse(licensePayload.toString("utf8")) as LicenseData;
    license.device_fingerprint = stored.device_fingerprint;
    return { sessionKey, license };
}

/**
 * Check if the license has access to a specific feature.
 * @param license - The license data to check.
 * @param featureSlug - The slug of the feature to check.
 * @returns true if the feature is enabled, false otherwise.
 */
export function hasFeature(license: LicenseData, featureSlug: string): boolean {
    if (!license.entitlements?.features) {
        return false;
    }
    const feature = license.entitlements.features[featureSlug];
    return feature?.enabled ?? false;
}

/**
 * Get a feature grant from the license.
 * @param license - The license data to check.
 * @param featureSlug - The slug of the feature to get.
 * @returns The feature grant if found and enabled, undefined otherwise.
 */
export function getFeature(license: LicenseData, featureSlug: string): FeatureGrant | undefined {
    if (!license.entitlements?.features) {
        return undefined;
    }
    const feature = license.entitlements.features[featureSlug];
    return feature?.enabled ? feature : undefined;
}

/**
 * Check if the license has access to a specific scope within a feature.
 * @param license - The license data to check.
 * @param featureSlug - The slug of the feature.
 * @param scopeSlug - The slug of the scope to check.
 * @returns true if the scope is allowed, false otherwise.
 */
export function hasScope(license: LicenseData, featureSlug: string, scopeSlug: string): boolean {
    const feature = getFeature(license, featureSlug);
    if (!feature?.scopes) {
        return false;
    }
    const scope = feature.scopes[scopeSlug];
    return scope != null && scope.permission !== "deny";
}

/**
 * Get a scope grant from the license.
 * @param license - The license data to check.
 * @param featureSlug - The slug of the feature.
 * @param scopeSlug - The slug of the scope to get.
 * @returns The scope grant if found and allowed, undefined otherwise.
 */
export function getScope(license: LicenseData, featureSlug: string, scopeSlug: string): ScopeGrant | undefined {
    const feature = getFeature(license, featureSlug);
    if (!feature?.scopes) {
        return undefined;
    }
    const scope = feature.scopes[scopeSlug];
    return scope != null && scope.permission !== "deny" ? scope : undefined;
}

/**
 * Check if the license allows performing an operation (scope) on a feature.
 * @param license - The license data to check.
 * @param featureSlug - The slug of the feature.
 * @param scopeSlug - The slug of the scope/operation.
 * @returns An object with allowed (boolean) and limit (number, 0 if no limit).
 */
export function canPerform(license: LicenseData, featureSlug: string, scopeSlug: string): { allowed: boolean; limit: number } {
    const scope = getScope(license, featureSlug, scopeSlug);
    if (!scope) {
        return { allowed: false, limit: 0 };
    }
    return { allowed: true, limit: scope.limit ?? 0 };
}

// Trial-related helper functions

/**
 * Get detailed information about the trial status of a license.
 * @param license - The license data to check.
 * @param subscriptionUrl - Optional URL to display when trial expires.
 * @returns TrialInfo object with status, expiration info, and messages.
 */
export function getTrialInfo(license: LicenseData, subscriptionUrl?: string): TrialInfo {
    const info: TrialInfo = {
        status: TrialStatus.NotTrial,
        isTrial: license.is_trial,
        isExpired: false,
        daysRemaining: 0,
        message: '',
        subscriptionUrl
    };

    if (!license.is_trial) {
        info.status = TrialStatus.NotTrial;
        info.message = 'This is a licensed version.';
        return info;
    }

    const now = new Date();
    const expiresAtStr = license.trial_expires_at ?? license.expires_at;
    const expiresAt = new Date(expiresAtStr);
    info.expiresAt = expiresAt;

    if (now > expiresAt) {
        info.status = TrialStatus.Expired;
        info.isExpired = true;
        info.daysRemaining = 0;
        info.message = 'Your trial has expired. Please subscribe to continue using the application.';
        return info;
    }

    const remainingMs = expiresAt.getTime() - now.getTime();
    info.daysRemaining = Math.floor(remainingMs / (1000 * 60 * 60 * 24));
    info.status = TrialStatus.Active;
    info.isExpired = false;

    if (info.daysRemaining <= 3) {
        info.message = `Your trial expires in ${info.daysRemaining} day(s). Please subscribe to continue using the application.`;
    } else {
        info.message = `Trial active: ${info.daysRemaining} days remaining.`;
    }

    return info;
}

/**
 * Check if the license is a trial that has expired.
 * @param license - The license data to check.
 * @returns true if this is an expired trial license.
 */
export function isTrialExpired(license: LicenseData): boolean {
    if (!license.is_trial) {
        return false;
    }
    const expiresAtStr = license.trial_expires_at ?? license.expires_at;
    const expiresAt = new Date(expiresAtStr);
    return new Date() > expiresAt;
}

/**
 * Check if the license is an active (non-expired) trial.
 * @param license - The license data to check.
 * @returns true if this is an active trial license.
 */
export function isTrialActive(license: LicenseData): boolean {
    if (!license.is_trial) {
        return false;
    }
    const expiresAtStr = license.trial_expires_at ?? license.expires_at;
    const expiresAt = new Date(expiresAtStr);
    return new Date() < expiresAt;
}

/**
 * Get the number of days remaining in the trial.
 * @param license - The license data to check.
 * @returns Number of days remaining, or 0 if not a trial or expired.
 */
export function trialDaysRemaining(license: LicenseData): number {
    if (!license.is_trial) {
        return 0;
    }
    const expiresAtStr = license.trial_expires_at ?? license.expires_at;
    const expiresAt = new Date(expiresAtStr);
    const remainingMs = expiresAt.getTime() - new Date().getTime();
    if (remainingMs <= 0) {
        return 0;
    }
    return Math.floor(remainingMs / (1000 * 60 * 60 * 24));
}
