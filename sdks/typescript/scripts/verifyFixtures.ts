import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createPublicKey } from "node:crypto";
import {
    decryptAesGcm,
    deriveTransportKey,
    hexToBuffer,
    verifySignature,
} from "../src/crypto.js";
import { decryptStoredLicense, StoredLicenseFile } from "../src/license.js";
import { canPerformWithContext } from "../src/license.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..", "..", "..");
const fixtureDir = path.join(repoRoot, "docs", "fixtures", "v1");

interface ActivationRequestFixture {
    email: string;
    client_id: string;
    license_key: string;
    device_fingerprint: string;
}

interface ActivationResponseFixture {
    success: boolean;
    message: string;
    encrypted_license: string;
    nonce: string;
    signature: string;
    public_key: string;
    expires_at: string;
}

interface StoredLicenseFixture {
    encrypted_data: string;
    nonce: string;
    signature: string;
    public_key: string;
    device_fingerprint: string;
    expires_at: string;
}

interface LicenseDataFixture {
    device_fingerprint: string;
    [key: string]: unknown;
}

function loadJSON<T>(name: string): T {
    const fullPath = path.join(fixtureDir, name);
    const data = fs.readFileSync(fullPath, "utf8");
    return JSON.parse(data) as T;
}

function bufferFromBase64(input: string): Buffer {
    return Buffer.from(input, "base64");
}

const activationReq = loadJSON<ActivationRequestFixture>("activation_request.json");
const activationResp = loadJSON<ActivationResponseFixture>("activation_response.json");
const storedLicense = loadJSON<StoredLicenseFile>("stored_license.json");
const licenseData = loadJSON<LicenseDataFixture>("license_data.json");

const { sessionKey, license } = decryptStoredLicense(storedLicense);
assert.deepStrictEqual(license, licenseData, "license payload mismatch");

const storedEncrypted = bufferFromBase64(storedLicense.encrypted_data);
const storedNonce = bufferFromBase64(storedLicense.nonce);

const activationEncrypted = hexToBuffer(activationResp.encrypted_license);
const activationNonce = hexToBuffer(activationResp.nonce);
const activationSignature = hexToBuffer(activationResp.signature);
const activationKeyObject = createPublicKey(activationResp.public_key);
const activationCombined = Buffer.concat([activationEncrypted, Buffer.from(activationReq.device_fingerprint, "utf8")]);
assert.ok(
    verifySignature(activationCombined, activationSignature, activationKeyObject) || verifySignature(activationEncrypted, activationSignature, activationKeyObject),
    "activation response signature invalid",
);

const activationTransportKey = deriveTransportKey(activationReq.device_fingerprint, activationNonce);
const decryptedActivation = decryptAesGcm(activationEncrypted, activationNonce, activationTransportKey);
const activationSession = decryptedActivation.subarray(0, 32);
assert.strictEqual(activationSession.compare(sessionKey), 0, "session key mismatch between activation/stored payloads");
const activationPayload = JSON.parse(decryptedActivation.subarray(32).toString("utf8"));
activationPayload.device_fingerprint = storedLicense.device_fingerprint;
assert.deepStrictEqual(activationPayload, licenseData, "activation payload differs");

console.log("TypeScript SDK fixture verification passed ✅");

// Additional restriction checks
const testLicense: any = {
    entitlements: {
        features: {
            file: {
                enabled: true,
                scopes: {
                    basic_storage: {
                        scope_slug: 'basic_storage',
                        permission: 'limit',
                        limit: 0,
                        restrictions: [{ type: 'storage', limit: 10 }]
                    },
                    export: {
                        scope_slug: 'export',
                        permission: 'limit',
                        limit: 0,
                        restrictions: [
                            { type: 'device', limit: 2 },
                            { type: 'user', limit: 3 }
                        ]
                    }
                }
            }
        }
    }
};

const res1 = canPerformWithContext(testLicense, 'file', 'basic_storage', { subjectType: 'storage', amount: 5 });
if (!res1.allowed) throw new Error('expected allowed for storage amount 5');
const res2 = canPerformWithContext(testLicense, 'file', 'basic_storage', { subjectType: 'storage', amount: 15 });
if (res2.allowed) throw new Error('expected denied for storage amount 15');

const dev1 = canPerformWithContext(testLicense, 'file', 'export', { subjectType: 'device', subjectID: 'dev1', amount: 1 });
if (!dev1.allowed) throw new Error('device 1 should be allowed');
const dev2 = canPerformWithContext(testLicense, 'file', 'export', { subjectType: 'device', subjectID: 'dev1', amount: 3 });
if (dev2.allowed) throw new Error('device 3 should be denied');
const user1 = canPerformWithContext(testLicense, 'file', 'export', { subjectType: 'user', subjectID: 'u1', amount: 2 });
if (!user1.allowed) throw new Error('user 2 should be allowed');
const user2 = canPerformWithContext(testLicense, 'file', 'export', { subjectType: 'user', subjectID: 'u1', amount: 4 });
if (user2.allowed) throw new Error('user 4 should be denied');

console.log('TypeScript SDK restriction checks passed ✅');
