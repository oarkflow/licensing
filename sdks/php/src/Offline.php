<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use RuntimeException;

final class Offline
{
    /**
     * Convert a raw Ed25519 public key (32 bytes) into a SubjectPublicKeyInfo DER PEM
     */
    public static function rawEd25519ToPem(string $raw): string
    {
        // ASN.1 SubjectPublicKeyInfo header for Ed25519
        $prefix = hex2bin('302a300506032b6570032100');
        $der = $prefix . $raw;
        $b64 = chunk_split(base64_encode($der), 64, "\n");
        return "-----BEGIN PUBLIC KEY-----\n" . $b64 . "-----END PUBLIC KEY-----\n";
    }

    /**
     * Fetch the active signing public key (raw bytes base64) from the server endpoint
     * returns [key_id, public_key_pem]
     */
    public static function fetchActiveSigningKey(string $serverUrl): array
    {
        $url = rtrim($serverUrl, '/') . '/api/keys/offline-signing-public';
        $payload = @file_get_contents($url);
        if ($payload === false) {
            throw new RuntimeException("failed to fetch signing key from server: $url");
        }
        $data = json_decode($payload, true);
        if (!is_array($data) || empty($data['key_id']) || empty($data['public_key'])) {
            throw new RuntimeException('invalid signing key response');
        }
        $raw = base64_decode($data['public_key'], true);
        if ($raw === false) {
            throw new RuntimeException('failed to decode public key');
        }
        $pem = self::rawEd25519ToPem($raw);
        return [$data['key_id'], $pem];
    }

    /**
     * Verify a signed bundle JSON using server public key (or cached PEM), optional device fingerprint
     * Returns payload array on success or throws RuntimeException
     */
    public static function verifySignedBundle(string $bundleJson, string $serverUrl, ?string $cacheDir = null, ?string $deviceFingerprint = null): array
    {
        $obj = json_decode($bundleJson, true);
        if (!is_array($obj) || !isset($obj['payload']) || !isset($obj['signature'])) {
            throw new RuntimeException('invalid bundle JSON');
        }
        $payload = $obj['payload'];
        if (!isset($payload['signing_key_id'])) {
            throw new RuntimeException('bundle missing signing_key_id');
        }
        $signingKeyID = $payload['signing_key_id'];

        // Try to fetch cached manifest (if cache provided) first/ public key is fetched from server
        [$keyID, $pem] = self::fetchActiveSigningKey($serverUrl);
        if ($keyID !== $signingKeyID) {
            // we still use the returned key -- server may have rotated keys but the payload will contain key id
            // attempt to fetch that key explicitly by re-requesting (same endpoint currently returns active only)
        }

        $payloadBytes = json_encode($payload);
        $sig = $obj['signature'];
        if (!Crypto::verifyEd25519($pem, $payloadBytes, $sig)) {
            throw new RuntimeException('invalid bundle signature');
        }

        if ($deviceFingerprint !== null && isset($payload['device_fingerprint'])) {
            if ($payload['device_fingerprint'] !== $deviceFingerprint) {
                throw new RuntimeException('device fingerprint mismatch');
            }
        }

        // Check cached manifest for revocation if available
        if ($cacheDir !== null) {
            $manifestFile = rtrim($cacheDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'revocation_manifest.json';
            if (file_exists($manifestFile)) {
                $mdata = @file_get_contents($manifestFile);
                if ($mdata !== false) {
                    $mobj = json_decode($mdata, true);
                    if (is_array($mobj) && isset($mobj['manifest'])) {
                        $manifest = $mobj['manifest'];
                        $token = $payload['token'] ?? '';
                        foreach ($manifest['revoked_offline_tokens'] ?? [] as $r) {
                            if (isset($r['token']) && $r['token'] === $token) {
                                throw new RuntimeException('token revoked in manifest');
                            }
                        }
                    }
                }
            }
        }

        return $payload;
    }

    /**
     * Sync and verify revocation manifest from server, optional since param for incremental sync.
     * Caches to $cacheDir/revocation_manifest.json when $cacheDir provided.
     * Returns manifest array.
     */
    public static function syncManifest(string $serverUrl, ?string $cacheDir = null, ?string $since = null): array
    {
        $url = rtrim($serverUrl, '/') . '/api/licenses/offline-revocations';
        if ($since) {
            $url .= '?since=' . urlencode($since);
        }
        $payload = @file_get_contents($url);
        if ($payload === false) {
            throw new RuntimeException("failed to fetch manifest from server: $url");
        }
        $obj = json_decode($payload, true);
        if (!is_array($obj) || !isset($obj['manifest'])) {
            throw new RuntimeException('invalid manifest response');
        }
        $manifest = $obj['manifest'];

        if (!empty($obj['signature']) && !empty($obj['signing_key_id'])) {
            // fetch signing key
            [$kid, $pem] = self::fetchActiveSigningKey($serverUrl);
            // ensure we have matching kid
            if ($kid !== $obj['signing_key_id']) {
                // still proceed; fetchActiveSigningKey returns active key
            }
            $sig = $obj['signature'];
            $payloadBytes = json_encode($manifest);
            if (!Crypto::verifyEd25519($pem, $payloadBytes, $sig)) {
                throw new RuntimeException('manifest signature verification failed');
            }
        }

        if ($cacheDir !== null) {
            if (!is_dir($cacheDir)) {
                @mkdir($cacheDir, 0700, true);
            }
            $out = ['manifest' => $manifest];
            if (!empty($obj['signature'])) {
                $out['signature'] = $obj['signature'];
                $out['signing_key_id'] = $obj['signing_key_id'] ?? '';
            }
            @file_put_contents(rtrim($cacheDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . 'revocation_manifest.json', json_encode($out, JSON_PRETTY_PRINT));
        }

        return $manifest;
    }
}
