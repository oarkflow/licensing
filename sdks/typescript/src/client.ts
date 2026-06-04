import fetch from "cross-fetch";
import { mkdirSync } from "node:fs";
import path from "node:path";
import { buildDeviceProof, loadOrCreateDeviceIdentity, type DeviceIdentity } from "./device.js";
import {
    loadLicenseFile,
    saveStoredLicense,
    storedLicenseFromActivationResponse,
    type StoredLicenseFile,
} from "./license.js";
import type {
    ActivationRequest,
    ActivationResponse,
    CredentialsFile,
    DeviceChallenge,
    DeviceProofPurpose,
    LicensingClientOptions,
    TrialCheckResponse,
    TrialRequest,
} from "./types.js";

export class LicensingClient {
    private readonly options: Required<Pick<LicensingClientOptions, "serverUrl">> & LicensingClientOptions;

    constructor(options: LicensingClientOptions) {
        if (!options.serverUrl) {
            throw new Error("serverUrl is required");
        }
        if (!options.allowInsecureHttp && options.serverUrl.trim().startsWith("http://")) {
            throw new Error("insecure HTTP requires allowInsecureHttp=true");
        }
        this.options = options as Required<Pick<LicensingClientOptions, "serverUrl">> & LicensingClientOptions;
    }

    serverUrl(): string {
        return this.options.serverUrl.replace(/\/$/, "");
    }

    configDir(): string {
        return this.options.configDir ?? path.join(process.env.HOME ?? process.cwd(), ".licensing");
    }

    licenseFile(): string {
        return this.options.licenseFile ?? path.join(this.configDir(), ".license.dat");
    }

    deviceKeyFile(): string {
        return this.options.deviceKeyFile ?? path.join(this.configDir(), "device_ed25519.pem");
    }

    deviceIdentity(): DeviceIdentity {
        mkdirSync(this.configDir(), { recursive: true, mode: 0o700 });
        return loadOrCreateDeviceIdentity(this.deviceKeyFile());
    }

    async requestDeviceChallenge(purpose: DeviceProofPurpose): Promise<DeviceChallenge> {
        return this.request<DeviceChallenge>("/api/device/challenge", {
            method: "POST",
            body: JSON.stringify({ purpose }),
        });
    }

    async activate(creds: CredentialsFile, opts: { productId?: string; replacementToken?: string; licenseFile?: string } = {}): Promise<{ response: ActivationResponse; stored: StoredLicenseFile }> {
        const identity = this.deviceIdentity();
        const request: ActivationRequest = {
            email: creds.email,
            client_id: creds.client_id,
            license_key: creds.license_key,
            device_fingerprint: identity.fingerprint,
            product_id: opts.productId ?? this.options.productId,
            replacement_token: opts.replacementToken,
        };
        request.device_proof = buildDeviceProof(identity, await this.requestDeviceChallenge("activate"), "activate", request);
        const response = await this.request<ActivationResponse>("/api/activate", {
            method: "POST",
            body: JSON.stringify(request),
        }, request);
        if (!response.success) {
            throw new Error(response.message || "activation failed");
        }
        const stored = storedLicenseFromActivationResponse(response, identity.fingerprint);
        await saveStoredLicense(opts.licenseFile ?? this.licenseFile(), stored);
        return { response, stored };
    }

    async verify(credsOrStored?: CredentialsFile | StoredLicenseFile, opts: { productId?: string; licenseFile?: string } = {}): Promise<{ response: ActivationResponse; stored: StoredLicenseFile }> {
        const identity = this.deviceIdentity();
        let creds: CredentialsFile;
        if (credsOrStored && "email" in credsOrStored) {
            creds = credsOrStored;
        } else {
            const stored = credsOrStored ?? await loadLicenseFile(opts.licenseFile ?? this.licenseFile());
            throw new Error(`verification from stored license requires credentials with email/client_id/license_key; loaded license for ${stored.device_fingerprint}`);
        }
        const request: ActivationRequest = {
            email: creds.email,
            client_id: creds.client_id,
            license_key: creds.license_key,
            device_fingerprint: identity.fingerprint,
            product_id: opts.productId ?? this.options.productId,
        };
        request.device_proof = buildDeviceProof(identity, await this.requestDeviceChallenge("verify"), "verify", request);
        const response = await this.request<ActivationResponse>("/api/verify", {
            method: "POST",
            body: JSON.stringify(request),
        }, request);
        if (!response.success) {
            throw new Error(response.message || "verification failed");
        }
        const stored = storedLicenseFromActivationResponse(response, identity.fingerprint);
        await saveStoredLicense(opts.licenseFile ?? this.licenseFile(), stored);
        return { response, stored };
    }

    async startTrial(req: Omit<TrialRequest, "device_fingerprint" | "device_proof">): Promise<unknown> {
        const identity = this.deviceIdentity();
        const body: TrialRequest = {
            ...req,
            product_id: req.product_id ?? this.options.productId,
            device_fingerprint: identity.fingerprint,
        };
        const proofRequest: ActivationRequest = {
            email: body.email,
            client_id: "",
            license_key: "",
            device_fingerprint: identity.fingerprint,
            product_id: body.product_id,
        };
        body.device_proof = buildDeviceProof(identity, await this.requestDeviceChallenge("trial"), "trial", proofRequest);
        return this.request<unknown>("/api/trial", { method: "POST", body: JSON.stringify(body) });
    }

    async checkTrial(deviceFingerprint?: string): Promise<TrialCheckResponse> {
        const fingerprint = deviceFingerprint ?? this.deviceIdentity().fingerprint;
        return this.request<TrialCheckResponse>(`/api/trial/check?device_fingerprint=${encodeURIComponent(fingerprint)}`, { method: "GET" });
    }

    private async request<T>(pathName: string, init: RequestInit, licenseHeaders?: Pick<ActivationRequest, "device_fingerprint" | "license_key">): Promise<T> {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), this.options.httpTimeoutMs ?? 15000);
        try {
            const headers: Record<string, string> = {
                "Content-Type": "application/json",
                "User-Agent": `${this.options.appName ?? "typescript-sdk"}/${this.options.appVersion ?? "0.1.0"}`,
            };
            if (this.options.appVersion) {
                headers["X-App-Version"] = this.options.appVersion;
            }
            if (licenseHeaders?.device_fingerprint) {
                headers["X-Device-Fingerprint"] = licenseHeaders.device_fingerprint;
            }
            if (licenseHeaders?.license_key) {
                headers["X-License-Key"] = licenseHeaders.license_key.toUpperCase().replace(/[- ]/g, "");
            }
            const res = await fetch(this.serverUrl() + pathName, { ...init, headers, signal: controller.signal });
            const text = await res.text();
            const json = text ? JSON.parse(text) : {};
            if (!res.ok) {
                throw new Error(json.error || json.message || `request failed with status ${res.status}`);
            }
            return json as T;
        } finally {
            clearTimeout(timeout);
        }
    }
}
