export {
    ActivationPayload,
    CredentialsFile,
    LicenseData,
    LicenseDevice,
    LicenseEntitlements,
    FeatureGrant,
    ScopeGrant,
    ScopePermission,
    LicensingClientOptions,
    TrialStatus,
    TrialInfo,
    TrialRequest,
    TrialCheckRequest,
    TrialCheckResponse
} from "./types.js";
export * from "./license.js";

import { LicensingClientOptions } from "./types.js";

export class LicensingClient {
    constructor(private readonly options: LicensingClientOptions) { }

    serverUrl(): string {
        return this.options.serverUrl.replace(/\/$/, "");
    }
}
