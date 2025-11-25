<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use RuntimeException;

final class License
{
    /**
     * @param array{
     *   encrypted_data:string,
     *   nonce:string,
     *   signature:string,
     *   public_key:string,
     *   device_fingerprint:string,
     *   expires_at:string
     * } $stored
     * @return array{sessionKey:string, license:array<string,mixed>}
     */
    public static function decrypt(array $stored): array
    {
        $encrypted = base64_decode($stored['encrypted_data'], true);
        $nonce = base64_decode($stored['nonce'], true);
        $signature = base64_decode($stored['signature'], true);
        $publicKeyDer = base64_decode($stored['public_key'], true);
        if ($encrypted === false || $nonce === false || $signature === false || $publicKeyDer === false) {
            throw new RuntimeException('Failed to decode stored license blobs');
        }

        $publicKeyPem = self::derToPem($publicKeyDer, 'PUBLIC KEY');
        if (!Crypto::verifySignature($encrypted, $signature, $publicKeyPem)) {
            throw new RuntimeException('Stored license signature invalid');
        }

        $transportKey = Crypto::deriveTransportKey($stored['device_fingerprint'], bin2hex($nonce));
        $decrypted = Crypto::decryptAesGcm($encrypted, $nonce, $transportKey);
        if (strlen($decrypted) <= 32) {
            throw new RuntimeException('Decrypted payload missing session key');
        }
        $sessionKey = substr($decrypted, 0, 32);
        $licensePayload = substr($decrypted, 32);
        /** @var array<string,mixed> $decoded */
        $decoded = json_decode($licensePayload, true, flags: JSON_THROW_ON_ERROR);
        $decoded['device_fingerprint'] = $stored['device_fingerprint'];
        return [
            'sessionKey' => $sessionKey,
            'license' => $decoded,
        ];
    }

    private static function derToPem(string $der, string $label): string
    {
        $base64 = chunk_split(base64_encode($der), 64, "\n");
        return "-----BEGIN {$label}-----\n{$base64}-----END {$label}-----\n";
    }
}
