<?php
// If composer autoload exists, use it; otherwise include the License class directly for standalone verification.
if (file_exists(__DIR__ . '/../../vendor/autoload.php')) {
    require __DIR__ . '/../../vendor/autoload.php';
    $LicenseClass = '\\Oarkflow\\Licensing\\License';
} else {
    require __DIR__ . '/../src/License.php';
    $LicenseClass = '\\Oarkflow\\Licensing\\License';
}

$testLicense = [
    'entitlements' => [
        'features' => [
            'file' => [
                'enabled' => true,
                'scopes' => [
                    'basic_storage' => [
                        'scope_slug' => 'basic_storage',
                        'permission' => 'limit',
                        'limit' => 0,
                        'restrictions' => [ ['type' => 'storage', 'limit' => 10] ]
                    ],
                    'export' => [
                        'scope_slug' => 'export',
                        'permission' => 'limit',
                        'limit' => 0,
                        'restrictions' => [ ['type' => 'device', 'limit' => 2], ['type' => 'user', 'limit' => 3] ]
                    ]
                ]
            ]
        ]
    ]
];

$res1 = $LicenseClass::canPerformWithContext($testLicense, 'file', 'basic_storage', ['subject_type' => 'storage', 'amount' => 5]);
if (!$res1['allowed']) { echo "FAIL: expected allowed for storage 5\n"; exit(1); }
$res2 = $LicenseClass::canPerformWithContext($testLicense, 'file', 'basic_storage', ['subject_type' => 'storage', 'amount' => 15]);
if ($res2['allowed']) { echo "FAIL: expected denied for storage 15\n"; exit(1); }

$dev1 = $LicenseClass::canPerformWithContext($testLicense, 'file', 'export', ['subject_type' => 'device', 'amount' => 1]);
if (!$dev1['allowed']) { echo "FAIL: device 1 should be allowed\n"; exit(1); }
$dev2 = $LicenseClass::canPerformWithContext($testLicense, 'file', 'export', ['subject_type' => 'device', 'amount' => 3]);
if ($dev2['allowed']) { echo "FAIL: device 3 should be denied\n"; exit(1); }

$user1 = $LicenseClass::canPerformWithContext($testLicense, 'file', 'export', ['subject_type' => 'user', 'amount' => 2]);
if (!$user1['allowed']) { echo "FAIL: user 2 should be allowed\n"; exit(1); }
$user2 = $LicenseClass::canPerformWithContext($testLicense, 'file', 'export', ['subject_type' => 'user', 'amount' => 4]);
if ($user2['allowed']) { echo "FAIL: user 4 should be denied\n"; exit(1); }

echo "PHP SDK restriction checks passed ✅\n";
