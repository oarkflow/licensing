<?php

declare(strict_types=1);

use Oarkflow\Licensing\Crypto;
use Oarkflow\Licensing\License;

require __DIR__ . '/../vendor/autoload.php';

$repoRoot = realpath(__DIR__ . '/../../..');
if ($repoRoot === false) {
    throw new RuntimeException('Failed to resolve repository root');
}
$fixtureDir = $repoRoot . '/docs/fixtures/v1';

$activationReq = json_decode(file_get_contents($fixtureDir . '/activation_request.json'), true, 512, JSON_THROW_ON_ERROR);
$activationResp = json_decode(file_get_contents($fixtureDir . '/activation_response.json'), true, 512, JSON_THROW_ON_ERROR);
$storedLicense = json_decode(file_get_contents($fixtureDir . '/stored_license.json'), true, 512, JSON_THROW_ON_ERROR);
$licenseData = json_decode(file_get_contents($fixtureDir . '/license_data.json'), true, 512, JSON_THROW_ON_ERROR);

$result = License::decrypt($storedLicense);
if ($result['license'] !== $licenseData) {
    throw new RuntimeException('Stored license payload mismatch');
}

$storedEncrypted = base64_decode($storedLicense['encrypted_data'], true);
$storedNonce = base64_decode($storedLicense['nonce'], true);
$storedSignature = base64_decode($storedLicense['signature'], true);
$storedPublicKeyPem = (static function (string $der): string {
    $base64 = chunk_split(base64_encode($der), 64, "\n");
    return "-----BEGIN PUBLIC KEY-----\n{$base64}-----END PUBLIC KEY-----\n";
})(base64_decode($storedLicense['public_key'], true));

if (!Crypto::verifySignature($storedEncrypted, $storedSignature, $storedPublicKeyPem)) {
    throw new RuntimeException('Stored license signature invalid');
}

$activationEncrypted = hex2bin($activationResp['encrypted_license']);
$activationNonce = Crypto::hexToBinary($activationResp['nonce']);
$activationSignature = hex2bin($activationResp['signature']);
$activationKey = Crypto::deriveTransportKey($activationReq['device_fingerprint'], $activationResp['nonce']);
$activationPublicKey = $activationResp['public_key'];

if (!Crypto::verifySignature($activationEncrypted, $activationSignature, $activationPublicKey)) {
    throw new RuntimeException('Activation response signature invalid');
}

$decryptedActivation = Crypto::decryptAesGcm($activationEncrypted, $activationNonce, $activationKey);
$activationSessionKey = substr($decryptedActivation, 0, 32);
if ($activationSessionKey !== $result['sessionKey']) {
    throw new RuntimeException('Activation session key mismatch');
}
$activationPayload = json_decode(substr($decryptedActivation, 32), true, 512, JSON_THROW_ON_ERROR);
$activationPayload['device_fingerprint'] = $storedLicense['device_fingerprint'];
if ($activationPayload !== $licenseData) {
    throw new RuntimeException('Activation payload mismatch');
}

echo "PHP SDK fixture verification passed ✅" . PHP_EOL;
