<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use RuntimeException;

final class Device
{
    /**
     * @return array{secret_key:string, public_key:string, fingerprint:string, key_id:string, key_provider:string}
     */
    public static function loadOrCreateIdentity(string $deviceKeyFile): array
    {
        if (!function_exists('sodium_crypto_sign_keypair')) {
            throw new RuntimeException('PHP sodium extension is required for Ed25519 device proofs');
        }
        $dir = dirname($deviceKeyFile);
        if (!is_dir($dir) && !mkdir($dir, 0700, true) && !is_dir($dir)) {
            throw new RuntimeException("Failed to create device key directory: {$dir}");
        }

        if (file_exists($deviceKeyFile)) {
            $raw = file_get_contents($deviceKeyFile);
            if ($raw === false) {
                throw new RuntimeException("Failed to read device key file: {$deviceKeyFile}");
            }
            $data = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
            $secret = base64_decode((string)($data['secret_key'] ?? ''), true);
            $public = base64_decode((string)($data['public_key'] ?? ''), true);
            if ($secret === false || $public === false || strlen($public) !== SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES) {
                throw new RuntimeException('Invalid device key file');
            }
        } else {
            $pair = sodium_crypto_sign_keypair();
            $secret = sodium_crypto_sign_secretkey($pair);
            $public = sodium_crypto_sign_publickey($pair);
            $json = json_encode([
                'version' => 1,
                'algorithm' => 'ed25519',
                'secret_key' => base64_encode($secret),
                'public_key' => base64_encode($public),
            ], JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR);
            file_put_contents($deviceKeyFile, $json);
            @chmod($deviceKeyFile, 0600);
        }

        $keyID = hash('sha256', $public);
        return [
            'secret_key' => $secret,
            'public_key' => $public,
            'fingerprint' => 'fp:v2:ed25519:' . $keyID,
            'key_id' => $keyID,
            'key_provider' => 'software-file',
        ];
    }

    public static function base64UrlRaw(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    /**
     * @param array{purpose:string, challenge_id:string, nonce:string, license_key?:string, client_id?:string, email?:string, product_id?:string, fingerprint:string, public_key:string} $payload
     */
    public static function canonicalPayload(array $payload): string
    {
        $licenseKey = strtoupper(str_replace(['-', ' '], '', trim((string)($payload['license_key'] ?? ''))));
        $publicKeyHash = hash('sha256', $payload['public_key']);
        return implode("\n", [
            'v=2',
            'purpose=' . strtolower(trim($payload['purpose'])),
            'challenge_id=' . trim($payload['challenge_id']),
            'nonce=' . trim($payload['nonce']),
            'license_key=' . $licenseKey,
            'client_id=' . trim((string)($payload['client_id'] ?? '')),
            'email=' . strtolower(trim((string)($payload['email'] ?? ''))),
            'product_id=' . trim((string)($payload['product_id'] ?? '')),
            'fingerprint=' . trim($payload['fingerprint']),
            'public_key_sha256=' . $publicKeyHash,
        ]);
    }

    /**
     * @param array{secret_key:string, public_key:string, fingerprint:string, key_id:string, key_provider:string} $identity
     * @param array{challenge_id:string, nonce:string} $challenge
     * @param array<string,mixed> $request
     * @return array<string,mixed>
     */
    public static function buildProof(array $identity, array $challenge, string $purpose, array $request): array
    {
        $payload = self::canonicalPayload([
            'purpose' => $purpose,
            'challenge_id' => $challenge['challenge_id'],
            'nonce' => $challenge['nonce'],
            'license_key' => (string)($request['license_key'] ?? ''),
            'client_id' => (string)($request['client_id'] ?? ''),
            'email' => (string)($request['email'] ?? ''),
            'product_id' => (string)($request['product_id'] ?? ''),
            'fingerprint' => (string)$request['device_fingerprint'],
            'public_key' => $identity['public_key'],
        ]);
        $signature = sodium_crypto_sign_detached($payload, $identity['secret_key']);
        return [
            'version' => 2,
            'purpose' => $purpose,
            'challenge_id' => $challenge['challenge_id'],
            'nonce' => $challenge['nonce'],
            'fingerprint' => $request['device_fingerprint'],
            'key_id' => $identity['key_id'],
            'key_provider' => $identity['key_provider'],
            'public_key_alg' => 'ed25519',
            'public_key' => self::base64UrlRaw($identity['public_key']),
            'signature' => self::base64UrlRaw($signature),
            'attestation' => [
                'type' => 'software',
                'status' => 'file',
            ],
        ];
    }
}
