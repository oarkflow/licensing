<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use phpseclib3\Crypt\PublicKeyLoader;
use phpseclib3\Crypt\RSA;

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
            $publicKey = PublicKeyLoader::load($publicKeyPem)
                ->withPadding(RSA::SIGNATURE_PSS)
                ->withHash('sha256')
                ->withMGFHash('sha256')
                ->withSaltLength(RSA::SALT_LENGTH_AUTO);
        } catch (\Throwable $e) {
            throw new \RuntimeException('Failed to parse public key', 0, $e);
        }
        return $publicKey->verify($payload, $signature);
    }
}
