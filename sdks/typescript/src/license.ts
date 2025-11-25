import { promises as fs } from "node:fs";
import { createPublicKey } from "node:crypto";
import { deriveTransportKey, decryptAesGcm, verifySignature } from "./crypto.js";
import { LicenseData } from "./types.js";

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
