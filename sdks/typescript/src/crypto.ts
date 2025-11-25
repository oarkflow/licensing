import {
    KeyLike,
    constants,
    createDecipheriv,
    createHash,
    verify as verifyRSA,
} from "node:crypto";

export function hexToBuffer(hex: string): Buffer {
    if (hex.length % 2 !== 0) {
        throw new Error("hex payload must have an even length");
    }
    return Buffer.from(hex, "hex");
}

export function deriveTransportKey(fingerprint: string, nonce: Buffer): Buffer {
    const material = Buffer.from(fingerprint + nonce.toString("hex"), "utf8");
    return createHash("sha256").update(material).digest();
}

export function decryptAesGcm(encrypted: Buffer, nonce: Buffer, key: Buffer): Buffer {
    if (encrypted.length <= 16) {
        throw new Error("encrypted payload too small for GCM tag");
    }
    const tag = encrypted.subarray(encrypted.length - 16);
    const ciphertext = encrypted.subarray(0, encrypted.length - 16);
    const decipher = createDecipheriv("aes-256-gcm", key, nonce);
    decipher.setAuthTag(tag);
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}

export function verifySignature(payload: Buffer, signature: Buffer, publicKey: KeyLike): boolean {
    try {
        return verifyRSA("sha256", payload, {
            key: publicKey,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: constants.RSA_PSS_SALTLEN_AUTO,
            mgf1Hash: "sha256",
        }, signature);
    } catch {
        return false;
    }
}
