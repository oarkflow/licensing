<?php

declare(strict_types=1);

namespace Oarkflow\Licensing;

use RuntimeException;

final class Client
{
    private string $serverUrl;
    private bool $allowInsecureHttp;
    private string $configDir;
    private string $licenseFile;
    private string $deviceKeyFile;
    private ?string $productID;
    private string $appName;
    private string $appVersion;
    private int $timeoutSeconds;

    /**
     * @param array{server_url:string, allow_insecure_http?:bool, config_dir?:string, license_file?:string, device_key_file?:string, product_id?:string, app_name?:string, app_version?:string, timeout_seconds?:int} $options
     */
    public function __construct(array $options)
    {
        $this->serverUrl = rtrim((string)($options['server_url'] ?? ''), '/');
        if ($this->serverUrl === '') {
            throw new RuntimeException('server_url is required');
        }
        $this->allowInsecureHttp = (bool)($options['allow_insecure_http'] ?? false);
        if (!$this->allowInsecureHttp && str_starts_with($this->serverUrl, 'http://')) {
            throw new RuntimeException('insecure HTTP requires allow_insecure_http=true');
        }
        $home = getenv('HOME') ?: getcwd() ?: '.';
        $this->configDir = (string)($options['config_dir'] ?? ($home . DIRECTORY_SEPARATOR . '.licensing'));
        $this->licenseFile = (string)($options['license_file'] ?? ($this->configDir . DIRECTORY_SEPARATOR . '.license.dat'));
        $this->deviceKeyFile = (string)($options['device_key_file'] ?? ($this->configDir . DIRECTORY_SEPARATOR . 'device_ed25519.json'));
        $this->productID = isset($options['product_id']) ? (string)$options['product_id'] : null;
        $this->appName = (string)($options['app_name'] ?? 'php-sdk');
        $this->appVersion = (string)($options['app_version'] ?? '0.1.0');
        $this->timeoutSeconds = (int)($options['timeout_seconds'] ?? 15);
    }

    public function licenseFile(): string
    {
        return $this->licenseFile;
    }

    /**
     * @return array{secret_key:string, public_key:string, fingerprint:string, key_id:string, key_provider:string}
     */
    public function deviceIdentity(): array
    {
        if (!is_dir($this->configDir)) {
            mkdir($this->configDir, 0700, true);
        }
        return Device::loadOrCreateIdentity($this->deviceKeyFile);
    }

    /**
     * @return array<string,mixed>
     */
    public function requestDeviceChallenge(string $purpose): array
    {
        return $this->request('POST', '/api/device/challenge', ['purpose' => $purpose]);
    }

    /**
     * @param array{email:string, client_id:string, license_key:string} $credentials
     * @param array{product_id?:string, replacement_token?:string, license_file?:string} $options
     * @return array{response:array<string,mixed>, stored:array<string,string>}
     */
    public function activate(array $credentials, array $options = []): array
    {
        $identity = $this->deviceIdentity();
        $request = [
            'email' => $credentials['email'],
            'client_id' => $credentials['client_id'],
            'license_key' => $credentials['license_key'],
            'device_fingerprint' => $identity['fingerprint'],
            'product_id' => $options['product_id'] ?? $this->productID,
            'replacement_token' => $options['replacement_token'] ?? null,
        ];
        $request = array_filter($request, static fn($value) => $value !== null && $value !== '');
        $request['device_proof'] = Device::buildProof($identity, $this->requestDeviceChallenge('activate'), 'activate', $request);
        $response = $this->request('POST', '/api/activate', $request, $request);
        if (empty($response['success'])) {
            throw new RuntimeException((string)($response['message'] ?? 'activation failed'));
        }
        $stored = self::storedLicenseFromActivationResponse($response, $identity['fingerprint']);
        $this->saveStoredLicense((string)($options['license_file'] ?? $this->licenseFile), $stored);
        return ['response' => $response, 'stored' => $stored];
    }

    /**
     * @param array{email:string, client_id:string, license_key:string} $credentials
     * @param array{product_id?:string, license_file?:string} $options
     * @return array{response:array<string,mixed>, stored:array<string,string>}
     */
    public function verify(array $credentials, array $options = []): array
    {
        $identity = $this->deviceIdentity();
        $request = [
            'email' => $credentials['email'],
            'client_id' => $credentials['client_id'],
            'license_key' => $credentials['license_key'],
            'device_fingerprint' => $identity['fingerprint'],
            'product_id' => $options['product_id'] ?? $this->productID,
        ];
        $request = array_filter($request, static fn($value) => $value !== null && $value !== '');
        $request['device_proof'] = Device::buildProof($identity, $this->requestDeviceChallenge('verify'), 'verify', $request);
        $response = $this->request('POST', '/api/verify', $request, $request);
        if (empty($response['success'])) {
            throw new RuntimeException((string)($response['message'] ?? 'verification failed'));
        }
        $stored = self::storedLicenseFromActivationResponse($response, $identity['fingerprint']);
        $this->saveStoredLicense((string)($options['license_file'] ?? $this->licenseFile), $stored);
        return ['response' => $response, 'stored' => $stored];
    }

    /**
     * @param array<string,mixed> $request
     * @return array<string,mixed>
     */
    public function startTrial(array $request): array
    {
        $identity = $this->deviceIdentity();
        $request['device_fingerprint'] = $identity['fingerprint'];
        $request['product_id'] = $request['product_id'] ?? $this->productID;
        $proofRequest = [
            'email' => (string)($request['email'] ?? ''),
            'client_id' => '',
            'license_key' => '',
            'device_fingerprint' => $identity['fingerprint'],
            'product_id' => (string)($request['product_id'] ?? ''),
        ];
        $request['device_proof'] = Device::buildProof($identity, $this->requestDeviceChallenge('trial'), 'trial', $proofRequest);
        return $this->request('POST', '/api/trial', $request);
    }

    /**
     * @return array<string,mixed>
     */
    public function checkTrial(?string $deviceFingerprint = null): array
    {
        $fingerprint = $deviceFingerprint ?: $this->deviceIdentity()['fingerprint'];
        return $this->request('GET', '/api/trial/check?device_fingerprint=' . rawurlencode($fingerprint));
    }

    /**
     * @param array<string,mixed> $response
     * @return array<string,string>
     */
    public static function storedLicenseFromActivationResponse(array $response, string $deviceFingerprint): array
    {
        foreach (['encrypted_license', 'nonce', 'signature', 'public_key', 'expires_at'] as $field) {
            if (empty($response[$field])) {
                throw new RuntimeException("activation response missing {$field}");
            }
        }
        return [
            'encrypted_data' => base64_encode(hex2bin((string)$response['encrypted_license']) ?: ''),
            'nonce' => base64_encode(hex2bin((string)$response['nonce']) ?: ''),
            'signature' => base64_encode(hex2bin((string)$response['signature']) ?: ''),
            'public_key' => base64_encode(self::pemToDer((string)$response['public_key'])),
            'device_fingerprint' => $deviceFingerprint,
            'expires_at' => (string)$response['expires_at'],
        ];
    }

    /**
     * @param array<string,string> $stored
     */
    public function saveStoredLicense(string $path, array $stored): void
    {
        $dir = dirname($path);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        file_put_contents($path, json_encode($stored, JSON_PRETTY_PRINT | JSON_THROW_ON_ERROR));
        @chmod($path, 0600);
    }

    /**
     * @param array<string,mixed>|null $body
     * @param array<string,mixed>|null $licenseHeaders
     * @return array<string,mixed>
     */
    private function request(string $method, string $path, ?array $body = null, ?array $licenseHeaders = null): array
    {
        $headers = [
            'Content-Type: application/json',
            'User-Agent: ' . $this->appName . '/' . $this->appVersion,
            'X-App-Version: ' . $this->appVersion,
        ];
        if ($licenseHeaders !== null) {
            if (!empty($licenseHeaders['device_fingerprint'])) {
                $headers[] = 'X-Device-Fingerprint: ' . $licenseHeaders['device_fingerprint'];
            }
            if (!empty($licenseHeaders['license_key'])) {
                $headers[] = 'X-License-Key: ' . strtoupper(str_replace(['-', ' '], '', (string)$licenseHeaders['license_key']));
            }
        }
        $payload = $body === null ? '' : json_encode($body, JSON_THROW_ON_ERROR);
        $status = 0;
        if (function_exists('curl_init')) {
            $ch = curl_init($this->serverUrl . $path);
            if ($ch === false) {
                throw new RuntimeException('failed to initialize curl');
            }
            curl_setopt_array($ch, [
                CURLOPT_CUSTOMREQUEST => $method,
                CURLOPT_HTTPHEADER => $headers,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_TIMEOUT => $this->timeoutSeconds,
            ]);
            if ($method !== 'GET') {
                curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
            }
            $raw = curl_exec($ch);
            if ($raw === false) {
                $err = curl_error($ch);
                curl_close($ch);
                throw new RuntimeException("request failed: {$method} {$path}: {$err}");
            }
            $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
            curl_close($ch);
        } else {
            $context = stream_context_create([
                'http' => [
                    'method' => $method,
                    'header' => implode("\r\n", $headers),
                    'content' => $payload,
                    'timeout' => $this->timeoutSeconds,
                    'ignore_errors' => true,
                ],
            ]);
            $raw = file_get_contents($this->serverUrl . $path, false, $context);
            if ($raw === false) {
                throw new RuntimeException("request failed: {$method} {$path}");
            }
            foreach ($http_response_header ?? [] as $header) {
                if (preg_match('/^HTTP\/\S+\s+(\d+)/', $header, $m)) {
                    $status = (int)$m[1];
                    break;
                }
            }
        }
        $json = json_decode($raw, true);
        if (!is_array($json)) {
            throw new RuntimeException("invalid JSON response from {$path}");
        }
        if ($status >= 400) {
            throw new RuntimeException((string)($json['error'] ?? $json['message'] ?? "request failed with status {$status}"));
        }
        return $json;
    }

    private static function pemToDer(string $pem): string
    {
        $clean = preg_replace('/-----BEGIN [^-]+-----|-----END [^-]+-----|\s+/', '', $pem);
        if ($clean === null || $clean === '') {
            throw new RuntimeException('invalid PEM public key');
        }
        $der = base64_decode($clean, true);
        if ($der === false) {
            throw new RuntimeException('failed to decode PEM public key');
        }
        return $der;
    }
}
