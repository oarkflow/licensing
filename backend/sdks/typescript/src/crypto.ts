import {
    KeyLike,
    constants,
    createCipheriv,
    createDecipheriv,
    createHash,
    generateKeyPairSync,
    randomBytes,
    sign as signData,
    verify as verifyRSA,
} from "node:crypto";
import { readFileSync, unlinkSync, writeFileSync } from "node:fs";

/**
 * Cryptographic utilities for licensing SDK
 *
 * Provides secure cryptographic operations including:
 * - AES-256-GCM encryption/decryption
 * - RSA-PSS signature verification
 * - Ed25519 key generation and signing (v2.0+)
 * - SHA-256 hashing
 * - Secure random bytes generation
 */

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

export function encryptAesGcm(plaintext: Buffer, nonce: Buffer, key: Buffer): Buffer {
    const cipher = createCipheriv("aes-256-gcm", key, nonce);
    const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    return Buffer.concat([encrypted, tag]);
}

export function verifySignature(payload: Buffer, signature: Buffer, publicKey: KeyLike): boolean {
    try {
        return verifyRSA("sha256", payload, {
            key: publicKey as Parameters<typeof verifyRSA>[2] extends { key: infer K } ? K : never,
            padding: constants.RSA_PKCS1_PSS_PADDING,
            saltLength: constants.RSA_PSS_SALTLEN_AUTO,
        } as Parameters<typeof verifyRSA>[2], signature);
    } catch {
        return false;
    }
}

/**
 * Generate Ed25519 key pair for SSH authentication
 *
 * @returns Object with privateKey and publicKey in PEM format
 */
export function generateEd25519KeyPair(): { privateKey: string; publicKey: string } {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519", {
        privateKeyEncoding: { type: "pkcs8", format: "pem" },
        publicKeyEncoding: { type: "spki", format: "pem" },
    });
    return { privateKey, publicKey };
}

/**
 * Sign data with Ed25519 private key
 *
 * @param privateKeyPem PEM-encoded Ed25519 private key
 * @param data Data to sign
 * @returns Base64-encoded signature
 */
export function signEd25519(privateKeyPem: string, data: Buffer): string {
    const signature = signData(null, data, {
        key: privateKeyPem,
        format: "pem",
    });
    return signature.toString("base64");
}

/**
 * Verify Ed25519 signature
 *
 * @param publicKeyPem PEM-encoded Ed25519 public key
 * @param data Original data
 * @param signatureBase64 Base64-encoded signature
 * @returns True if signature is valid
 */
export function verifyEd25519(publicKeyPem: string, data: Buffer, signatureBase64: string): boolean {
    try {
        const signature = Buffer.from(signatureBase64, "base64");
        return verifyRSA(null, data, {
            key: publicKeyPem,
            format: "pem",
        }, signature);
    } catch {
        return false;
    }
}

/**
 * Compute SHA-256 hash of data
 *
 * @param data Data to hash
 * @param encoding Output encoding (default: 'hex')
 * @returns Hash value
 */
export function computeSHA256(data: Buffer, encoding: "hex" | "base64" = "hex"): string {
    return createHash("sha256").update(data).digest(encoding);
}

/**
 * Compute SHA-256 hash of file
 *
 * @param filepath Path to file
 * @param encoding Output encoding (default: 'hex')
 * @returns Hash value
 */
export function computeFileSHA256(filepath: string, encoding: "hex" | "base64" = "hex"): string {
    const content = readFileSync(filepath);
    return createHash("sha256").update(content).digest(encoding);
}

/**
 * Generate cryptographically secure random bytes
 *
 * @param length Number of bytes
 * @returns Random bytes as Buffer
 */
export function secureRandomBytes(length: number): Buffer {
    if (length < 1) {
        throw new Error("length must be positive");
    }
    return randomBytes(length);
}

/**
 * Securely delete a file by overwriting with random data
 *
 * @param filepath Path to file
 */
export function secureDelete(filepath: string): void {
    try {
        const stats = readFileSync(filepath);
        const size = stats.length;

        // Overwrite with random data 3 times
        for (let i = 0; i < 3; i++) {
            writeFileSync(filepath, secureRandomBytes(size));
        }

        // Delete the file
        unlinkSync(filepath);
    } catch (err) {
        if ((err as NodeJS.ErrnoException).code !== "ENOENT") {
            throw err;
        }
        // File doesn't exist, nothing to do
    }
}
