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
assert.ok(verifySignature(activationEncrypted, activationSignature, activationKeyObject), "activation response signature invalid");

const activationTransportKey = deriveTransportKey(activationReq.device_fingerprint, activationNonce);
const decryptedActivation = decryptAesGcm(activationEncrypted, activationNonce, activationTransportKey);
const activationSession = decryptedActivation.subarray(0, 32);
assert.strictEqual(activationSession.compare(sessionKey), 0, "session key mismatch between activation/stored payloads");
const activationPayload = JSON.parse(decryptedActivation.subarray(32).toString("utf8"));
activationPayload.device_fingerprint = storedLicense.device_fingerprint;
assert.deepStrictEqual(activationPayload, licenseData, "activation payload differs");

console.log("TypeScript SDK fixture verification passed ✅");
