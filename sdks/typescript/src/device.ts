import {
    createHash,
    createPrivateKey,
    createPublicKey,
    generateKeyPairSync,
    sign as signData,
} from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import type { ActivationRequest, DeviceChallenge, DeviceProof, DeviceProofPurpose } from "./types.js";

export interface DeviceIdentity {
    privateKeyPem: string;
    publicKeyRaw: Buffer;
    fingerprint: string;
    keyID: string;
    keyProvider: string;
}

export function loadOrCreateDeviceIdentity(deviceKeyFile: string): DeviceIdentity {
    mkdirSync(path.dirname(deviceKeyFile), { recursive: true, mode: 0o700 });
    let privateKeyPem: string;
    try {
        privateKeyPem = readFileSync(deviceKeyFile, "utf8");
    } catch {
        const pair = generateKeyPairSync("ed25519", {
            privateKeyEncoding: { type: "pkcs8", format: "pem" },
            publicKeyEncoding: { type: "spki", format: "pem" },
        });
        privateKeyPem = pair.privateKey;
        writeFileSync(deviceKeyFile, privateKeyPem, { encoding: "utf8", mode: 0o600 });
    }

    const privateKey = createPrivateKey(privateKeyPem);
    const publicKeyDer = createPublicKey(privateKey).export({ type: "spki", format: "der" }) as Buffer;
    const publicKeyRaw = publicKeyDer.subarray(publicKeyDer.length - 32);
    const keyID = createHash("sha256").update(publicKeyRaw).digest("hex");
    return {
        privateKeyPem,
        publicKeyRaw,
        keyID,
        fingerprint: `fp:v2:ed25519:${keyID}`,
        keyProvider: "software-file",
    };
}

export function base64UrlRaw(data: Buffer): string {
    return data.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function canonicalDeviceProofPayload(input: {
    purpose: DeviceProofPurpose;
    challengeID: string;
    nonce: string;
    licenseKey?: string;
    clientID?: string;
    email?: string;
    productID?: string;
    fingerprint: string;
    publicKey: Buffer;
}): Buffer {
    const normalizedLicense = (input.licenseKey ?? "").trim().toUpperCase().replace(/[- ]/g, "");
    const publicKeyHash = createHash("sha256").update(input.publicKey).digest("hex");
    return Buffer.from([
        "v=2",
        `purpose=${input.purpose.trim().toLowerCase()}`,
        `challenge_id=${input.challengeID.trim()}`,
        `nonce=${input.nonce.trim()}`,
        `license_key=${normalizedLicense}`,
        `client_id=${(input.clientID ?? "").trim()}`,
        `email=${(input.email ?? "").trim().toLowerCase()}`,
        `product_id=${(input.productID ?? "").trim()}`,
        `fingerprint=${input.fingerprint.trim()}`,
        `public_key_sha256=${publicKeyHash}`,
    ].join("\n"), "utf8");
}

export function buildDeviceProof(
    identity: DeviceIdentity,
    challenge: DeviceChallenge,
    purpose: DeviceProofPurpose,
    request: Pick<ActivationRequest, "email" | "client_id" | "license_key" | "product_id" | "device_fingerprint">,
): DeviceProof {
    const payload = canonicalDeviceProofPayload({
        purpose,
        challengeID: challenge.challenge_id,
        nonce: challenge.nonce,
        licenseKey: request.license_key,
        clientID: request.client_id,
        email: request.email,
        productID: request.product_id,
        fingerprint: request.device_fingerprint,
        publicKey: identity.publicKeyRaw,
    });
    const signature = signData(null, payload, identity.privateKeyPem);
    return {
        version: 2,
        purpose,
        challenge_id: challenge.challenge_id,
        nonce: challenge.nonce,
        fingerprint: request.device_fingerprint,
        key_id: identity.keyID,
        key_provider: identity.keyProvider,
        public_key_alg: "ed25519",
        public_key: base64UrlRaw(identity.publicKeyRaw),
        signature: base64UrlRaw(signature),
        attestation: {
            type: "software",
            status: "file",
        },
    };
}
