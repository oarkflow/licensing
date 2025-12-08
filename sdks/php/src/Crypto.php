<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PublicKey;
use phpseclib3\Crypt\Common\PrivateKey;
use phpseclib3\Crypt\EC;

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
final class Crypto
{
    private const TAG_LENGTH = 16;

    public static function hexToBinary(string $hex): string
    {
        if (strlen($hex) % 2 !== 0) {
            throw new \InvalidArgumentException('Hex string must have even length');
        }
        return hex2bin($hex) ?: '';
    }

    public static function deriveTransportKey(string $fingerprint, string $nonceHex): string
    {
        $material = $fingerprint . strtolower($nonceHex);
        return hash('sha256', $material, true);
    }

    public static function decryptAesGcm(string $ciphertext, string $nonce, string $key): string
    {
        if (strlen($ciphertext) <= self::TAG_LENGTH) {
            throw new \RuntimeException('Ciphertext too small for AES-GCM tag');
        }
        $tag = substr($ciphertext, -self::TAG_LENGTH);
        $payload = substr($ciphertext, 0, -self::TAG_LENGTH);
        $plaintext = openssl_decrypt($payload, 'aes-256-gcm', $key, \OPENSSL_RAW_DATA, $nonce, $tag);
        if ($plaintext === false) {
            throw new \RuntimeException('AES-GCM decryption failed: ' . openssl_error_string());
        }
        return $plaintext;
    }

    public static function encryptAesGcm(string $plaintext, string $nonce, string $key): string
    {
        $tag = '';
        $ciphertext = openssl_encrypt($plaintext, 'aes-256-gcm', $key, \OPENSSL_RAW_DATA, $nonce, $tag);
        if ($ciphertext === false) {
            throw new \RuntimeException('AES-GCM encryption failed: ' . openssl_error_string());
        }
        return $ciphertext . $tag;
    }

    public static function verifySignature(string $payload, string $signature, string $publicKeyPem): bool
    {
        try {
            $baseKey = PublicKeyLoader::loadPublicKey($publicKeyPem);
        } catch (\Throwable $e) {
            throw new \RuntimeException('Failed to parse public key', 0, $e);
        }
        if (!$baseKey instanceof PublicKey) {
            throw new \RuntimeException('Loaded key is not an RSA public key');
        }
        // Go's rsa.SignPSS with nil options uses PSSSaltLengthAuto which equals
        // the maximum possible salt length: (keyBits/8) - hashLen - 2.
        // For 2048-bit RSA with SHA-256: 256 - 32 - 2 = 222 bytes.
        // We calculate this dynamically from the key size.
        $keyBits = $baseKey->getLength();
        $hashLen = 32; // SHA-256
        $maxSaltLen = (int)($keyBits / 8) - $hashLen - 2;
        /** @var PublicKey $rsaKey */
        $rsaKey = $baseKey
            ->withPadding(RSA::SIGNATURE_PSS)
            ->withHash('sha256')
            ->withMGFHash('sha256')
            ->withSaltLength($maxSaltLen);
        return $rsaKey->verify($payload, $signature);
    }

    /**
     * Generate Ed25519 key pair for SSH authentication
     *
     * @return array{private: string, public: string} PEM-encoded keys
     */
    public static function generateEd25519KeyPair(): array
    {
        $privateKey = EC::createKey('Ed25519');
        $publicKey = $privateKey->getPublicKey();

        return [
            'private' => $privateKey->toString('PKCS8'),
            'public' => $publicKey->toString('PKCS8'),
        ];
    }

    /**
     * Sign data with Ed25519 private key
     *
     * @param string $privateKeyPem PEM-encoded Ed25519 private key
     * @param string $data Data to sign
     * @return string Base64-encoded signature
     */
    public static function signEd25519(string $privateKeyPem, string $data): string
    {
        $privateKey = PublicKeyLoader::load($privateKeyPem);
        if (!$privateKey instanceof PrivateKey) {
            throw new \RuntimeException('Invalid Ed25519 private key');
        }
        $signature = $privateKey->sign($data);
        return base64_encode($signature);
    }

    /**
     * Verify Ed25519 signature
     *
     * @param string $publicKeyPem PEM-encoded Ed25519 public key
     * @param string $data Original data
     * @param string $signature Base64-encoded signature
     * @return bool True if signature is valid
     */
    public static function verifyEd25519(string $publicKeyPem, string $data, string $signature): bool
    {
        try {
            $publicKey = PublicKeyLoader::load($publicKeyPem);
            $signatureBytes = base64_decode($signature, true);
            if ($signatureBytes === false) {
                return false;
            }
            return $publicKey->verify($data, $signatureBytes);
        } catch (\Throwable $e) {
            return false;
        }
    }

    /**
     * Compute SHA-256 hash of data
     *
     * @param string $data Data to hash
     * @param bool $binary Return binary hash instead of hex
     * @return string Hash value
     */
    public static function computeSHA256(string $data, bool $binary = false): string
    {
        return hash('sha256', $data, $binary);
    }

    /**
     * Compute SHA-256 hash of file
     *
     * @param string $filepath Path to file
     * @param bool $binary Return binary hash instead of hex
     * @return string Hash value
     */
    public static function computeFileSHA256(string $filepath, bool $binary = false): string
    {
        $hash = hash_file('sha256', $filepath, $binary);
        if ($hash === false) {
            throw new \RuntimeException("Failed to compute hash of file: $filepath");
        }
        return $hash;
    }

    /**
     * Generate cryptographically secure random bytes
     *
     * @param int $length Number of bytes
     * @return string Random bytes
     */
    public static function secureRandomBytes(int $length): string
    {
        if ($length < 1) {
            throw new \InvalidArgumentException('Length must be positive');
        }
        return random_bytes($length);
    }

    /**
     * Securely delete a file by overwriting with random data
     *
     * @param string $filepath Path to file
     * @return bool True on success
     */
    public static function secureDelete(string $filepath): bool
    {
        if (!file_exists($filepath)) {
            return true;
        }

        $size = filesize($filepath);
        if ($size === false || $size === 0) {
            return unlink($filepath);
        }

        // Overwrite with random data 3 times
        $fp = fopen($filepath, 'r+b');
        if ($fp === false) {
            throw new \RuntimeException("Cannot open file for secure deletion: $filepath");
        }

        try {
            for ($i = 0; $i < 3; $i++) {
                fseek($fp, 0);
                fwrite($fp, self::secureRandomBytes($size));
                fflush($fp);
            }
            fclose($fp);
            return unlink($filepath);
        } catch (\Throwable $e) {
            fclose($fp);
            throw $e;
        }
    }
}
