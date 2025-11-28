<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use RuntimeException;

final class License
{
    /**
     * Load license activation credentials from a JSON file.
     *
     * The file should contain:
     * {
     *   "email": "user@example.com",
     *   "client_id": "client-123",
     *   "license_key": "XXXX-XXXX-..."
     * }
     *
     * @param string $path Path to the credentials JSON file
     * @return array{email:string, client_id:string, license_key:string}
     * @throws RuntimeException if the file cannot be read/parsed or fields are missing
     */
    public static function loadCredentialsFile(string $path): array
    {
        if (!file_exists($path)) {
            throw new RuntimeException("Credentials file not found: {$path}");
        }

        $content = file_get_contents($path);
        if ($content === false) {
            throw new RuntimeException("Failed to read credentials file: {$path}");
        }

        /** @var array<string,string>|null $data */
        $data = json_decode($content, true);
        if ($data === null) {
            throw new RuntimeException("Failed to parse credentials file: " . json_last_error_msg());
        }

        if (!isset($data['email']) || $data['email'] === '') {
            throw new RuntimeException("Credentials file missing 'email' field");
        }
        if (!isset($data['client_id']) || $data['client_id'] === '') {
            throw new RuntimeException("Credentials file missing 'client_id' field");
        }
        if (!isset($data['license_key']) || $data['license_key'] === '') {
            throw new RuntimeException("Credentials file missing 'license_key' field");
        }

        return [
            'email' => $data['email'],
            'client_id' => $data['client_id'],
            'license_key' => $data['license_key'],
        ];
    }

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

    /**
     * Check if the license has access to a specific feature.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @param string $featureSlug The slug of the feature to check
     * @return bool true if the feature is enabled
     */
    public static function hasFeature(array $license, string $featureSlug): bool
    {
        if (!isset($license['entitlements']['features'][$featureSlug])) {
            return false;
        }
        return $license['entitlements']['features'][$featureSlug]['enabled'] ?? false;
    }

    /**
     * Get a feature grant from the license.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @param string $featureSlug The slug of the feature to get
     * @return array<string,mixed>|null The feature grant if found and enabled, null otherwise
     */
    public static function getFeature(array $license, string $featureSlug): ?array
    {
        if (!self::hasFeature($license, $featureSlug)) {
            return null;
        }
        return $license['entitlements']['features'][$featureSlug];
    }

    /**
     * Check if the license has access to a specific scope within a feature.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @param string $featureSlug The slug of the feature
     * @param string $scopeSlug The slug of the scope to check
     * @return bool true if the scope is allowed
     */
    public static function hasScope(array $license, string $featureSlug, string $scopeSlug): bool
    {
        $feature = self::getFeature($license, $featureSlug);
        if ($feature === null || !isset($feature['scopes'][$scopeSlug])) {
            return false;
        }
        $scope = $feature['scopes'][$scopeSlug];
        return ($scope['permission'] ?? 'deny') !== 'deny';
    }

    /**
     * Get a scope grant from the license.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @param string $featureSlug The slug of the feature
     * @param string $scopeSlug The slug of the scope to get
     * @return array<string,mixed>|null The scope grant if found and allowed, null otherwise
     */
    public static function getScope(array $license, string $featureSlug, string $scopeSlug): ?array
    {
        $feature = self::getFeature($license, $featureSlug);
        if ($feature === null || !isset($feature['scopes'][$scopeSlug])) {
            return null;
        }
        $scope = $feature['scopes'][$scopeSlug];
        if (($scope['permission'] ?? 'deny') === 'deny') {
            return null;
        }
        return $scope;
    }

    /**
     * Check if the license allows performing an operation (scope) on a feature.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @param string $featureSlug The slug of the feature
     * @param string $scopeSlug The slug of the scope/operation
     * @return array{allowed:bool, limit:int} allowed status and limit (0 if no limit)
     */
    public static function canPerform(array $license, string $featureSlug, string $scopeSlug): array
    {
        $scope = self::getScope($license, $featureSlug, $scopeSlug);
        if ($scope === null) {
            return ['allowed' => false, 'limit' => 0];
        }
        return ['allowed' => true, 'limit' => $scope['limit'] ?? 0];
    }

    // Trial-related methods

    /**
     * Trial status constants.
     */
    public const TRIAL_STATUS_NOT_TRIAL = 'not_trial';
    public const TRIAL_STATUS_ACTIVE = 'active';
    public const TRIAL_STATUS_EXPIRED = 'expired';

    /**
     * Get detailed information about the trial status of a license.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @param string|null $subscriptionUrl Optional URL to display when trial expires
     * @return array{status:string, is_trial:bool, is_expired:bool, days_remaining:int, expires_at:string|null, message:string, subscription_url:string|null}
     */
    public static function getTrialInfo(array $license, ?string $subscriptionUrl = null): array
    {
        $info = [
            'status' => self::TRIAL_STATUS_NOT_TRIAL,
            'is_trial' => (bool) ($license['is_trial'] ?? false),
            'is_expired' => false,
            'days_remaining' => 0,
            'expires_at' => null,
            'message' => '',
            'subscription_url' => $subscriptionUrl,
        ];

        if (!$info['is_trial']) {
            $info['status'] = self::TRIAL_STATUS_NOT_TRIAL;
            $info['message'] = 'This is a licensed version.';
            return $info;
        }

        $expiresAtStr = $license['trial_expires_at'] ?? $license['expires_at'] ?? null;
        if ($expiresAtStr === null) {
            $info['message'] = 'Trial expiration date not available.';
            return $info;
        }

        $info['expires_at'] = $expiresAtStr;
        $expiresAt = strtotime($expiresAtStr);
        $now = time();

        if ($now > $expiresAt) {
            $info['status'] = self::TRIAL_STATUS_EXPIRED;
            $info['is_expired'] = true;
            $info['days_remaining'] = 0;
            $info['message'] = 'Your trial has expired. Please subscribe to continue using the application.';
            return $info;
        }

        $remainingSeconds = $expiresAt - $now;
        $info['days_remaining'] = (int) floor($remainingSeconds / 86400);
        $info['status'] = self::TRIAL_STATUS_ACTIVE;
        $info['is_expired'] = false;

        if ($info['days_remaining'] <= 3) {
            $info['message'] = sprintf(
                'Your trial expires in %d day(s). Please subscribe to continue using the application.',
                $info['days_remaining']
            );
        } else {
            $info['message'] = sprintf('Trial active: %d days remaining.', $info['days_remaining']);
        }

        return $info;
    }

    /**
     * Check if the license is a trial that has expired.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @return bool true if this is an expired trial license
     */
    public static function isTrialExpired(array $license): bool
    {
        if (!($license['is_trial'] ?? false)) {
            return false;
        }

        $expiresAtStr = $license['trial_expires_at'] ?? $license['expires_at'] ?? null;
        if ($expiresAtStr === null) {
            return false;
        }

        return time() > strtotime($expiresAtStr);
    }

    /**
     * Check if the license is an active (non-expired) trial.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @return bool true if this is an active trial license
     */
    public static function isTrialActive(array $license): bool
    {
        if (!($license['is_trial'] ?? false)) {
            return false;
        }

        $expiresAtStr = $license['trial_expires_at'] ?? $license['expires_at'] ?? null;
        if ($expiresAtStr === null) {
            return false;
        }

        return time() < strtotime($expiresAtStr);
    }

    /**
     * Get the number of days remaining in the trial.
     *
     * @param array<string,mixed> $license The decrypted license data
     * @return int Number of days remaining, or 0 if not a trial or expired
     */
    public static function trialDaysRemaining(array $license): int
    {
        if (!($license['is_trial'] ?? false)) {
            return 0;
        }

        $expiresAtStr = $license['trial_expires_at'] ?? $license['expires_at'] ?? null;
        if ($expiresAtStr === null) {
            return 0;
        }

        $expiresAt = strtotime($expiresAtStr);
        $remainingSeconds = $expiresAt - time();
        if ($remainingSeconds <= 0) {
            return 0;
        }

        return (int) floor($remainingSeconds / 86400);
    }

    /**
     * Check if the license is a trial license (regardless of status).
     *
     * @param array<string,mixed> $license The decrypted license data
     * @return bool true if this is a trial license
     */
    public static function isTrial(array $license): bool
    {
        return (bool) ($license['is_trial'] ?? false);
    }
}
