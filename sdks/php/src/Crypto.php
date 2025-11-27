<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;
use phpseclib3\Crypt\RSA\PublicKey;

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
}
