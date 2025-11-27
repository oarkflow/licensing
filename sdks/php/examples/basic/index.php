#!/usr/bin/env php
<?php
/**
 * Basic License Verification Example
 *
 * This example demonstrates how to:
 * 1. Load credentials from a JSON file
 * 2. Load and decrypt a stored license file
 * 3. Check license validity and expiration
 * 4. Access license data and check features/scopes
 *
 * Usage:
 *   php index.php --license-file /path/to/.license.dat
 *   php index.php --credentials-file /path/to/credentials.json
 */

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use Oarkflow\Licensing\License;

/**
 * Parse command line arguments
 */
function parseArgs(): array
{
    $options = getopt('l:c:h', ['license-file:', 'credentials-file:', 'help']);

    return [
        'license_file' => $options['license-file'] ?? $options['l'] ?? null,
        'credentials_file' => $options['credentials-file'] ?? $options['c'] ?? null,
        'help' => isset($options['help']) || isset($options['h']),
    ];
}

/**
 * Print usage information
 */
function printUsage(): void
{
    echo <<<USAGE

PHP Licensing SDK - Basic Example

Usage:
  php index.php --license-file <path>       Load and verify a license file
  php index.php --credentials-file <path>   Load credentials for activation

Options:
  -l, --license-file <path>      Path to stored license file (.license.dat)
  -c, --credentials-file <path>  Path to credentials JSON file
  -h, --help                     Show this help message

Credentials file format:
  {
    "email": "user@example.com",
    "client_id": "client-123",
    "license_key": "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
  }

USAGE;
}

/**
 * Format a date string for display
 */
function formatDate(string $dateStr): string
{
    $date = new DateTime($dateStr);
    return $date->format('Y-m-d H:i:s');
}

/**
 * Print license information
 * @param array<string,mixed> $license
 */
function printLicenseInfo(array $license): void
{
    echo "\n=== License Information ===\n";
    echo sprintf("ID:            %s\n", $license['id'] ?? 'N/A');
    echo sprintf("Email:         %s\n", $license['email'] ?? 'N/A');
    echo sprintf("Client ID:     %s\n", $license['client_id'] ?? 'N/A');
    echo sprintf("Plan:          %s\n", $license['plan_slug'] ?? 'N/A');
    echo sprintf("Issued:        %s\n", formatDate($license['issued_at'] ?? ''));
    echo sprintf("Expires:       %s\n", formatDate($license['expires_at'] ?? ''));
    echo sprintf("Max Devices:   %d\n", $license['max_devices'] ?? 0);
    echo sprintf("Activations:   %d\n", $license['current_activations'] ?? 0);
    echo sprintf("Check Mode:    %s\n", $license['check_mode'] ?? 'N/A');

    if (!empty($license['is_revoked'])) {
        $reason = $license['revoke_reason'] ?? 'No reason provided';
        echo sprintf("\n⚠️  LICENSE REVOKED: %s\n", $reason);
    }
}

/**
 * Print feature entitlements
 * @param array<string,mixed> $license
 */
function printEntitlements(array $license): void
{
    echo "\n=== Feature Entitlements ===\n";

    if (!isset($license['entitlements']['features'])) {
        echo "No feature entitlements configured for this license.\n";
        echo "Configure a product, plan, and features in the license server\n";
        echo "to enable feature-based access control.\n";
        return;
    }

    echo sprintf("Product: %s\n", $license['entitlements']['product_slug'] ?? 'N/A');
    echo sprintf("Plan:    %s\n", $license['entitlements']['plan_slug'] ?? 'N/A');
    echo "\n";

    // List all features
    foreach ($license['entitlements']['features'] as $slug => $feature) {
        $status = ($feature['enabled'] ?? false) ? "✅ Enabled" : "❌ Disabled";
        echo sprintf("  Feature: %s - %s\n", $slug, $status);

        // List scopes
        if (isset($feature['scopes']) && is_array($feature['scopes'])) {
            foreach ($feature['scopes'] as $scopeSlug => $scope) {
                $permission = $scope['permission'] ?? 'deny';
                if (isset($scope['limit']) && $scope['limit'] > 0) {
                    $permission = sprintf("%s (limit: %d)", $permission, $scope['limit']);
                }
                echo sprintf("    - %s: %s\n", $scopeSlug, $permission);
            }
        }
    }
}

/**
 * Check features
 * @param array<string,mixed> $license
 */
function checkFeatures(array $license): void
{
    echo "\n=== Feature Checks ===\n";

    $features = ['gui', 'cli', 'api', 'premium'];
    foreach ($features as $feat) {
        if (License::hasFeature($license, $feat)) {
            echo sprintf("✅ Feature '%s' is available\n", $feat);
        } else {
            echo sprintf("❌ Feature '%s' is not available\n", $feat);
        }
    }
}

/**
 * Check scopes
 * @param array<string,mixed> $license
 */
function checkScopes(array $license): void
{
    echo "\n=== Scope Checks ===\n";

    $scopes = [
        ['gui', 'list'],
        ['gui', 'create'],
        ['gui', 'update'],
        ['gui', 'delete'],
        ['api', 'read'],
        ['api', 'write'],
    ];

    foreach ($scopes as [$feature, $scope]) {
        $result = License::canPerform($license, $feature, $scope);
        if ($result['allowed']) {
            if ($result['limit'] > 0) {
                echo sprintf("✅ Can %s:%s (limit: %d)\n", $feature, $scope, $result['limit']);
            } else {
                echo sprintf("✅ Can %s:%s\n", $feature, $scope);
            }
        } else {
            echo sprintf("❌ Cannot %s:%s\n", $feature, $scope);
        }
    }
}

/**
 * Main function
 */
function main(): int
{
    echo "=== PHP Licensing SDK - Basic Example ===\n";

    $args = parseArgs();

    if ($args['help']) {
        printUsage();
        return 0;
    }

    // Load credentials file if provided
    if ($args['credentials_file'] !== null) {
        $credPath = $args['credentials_file'];

        if (!file_exists($credPath)) {
            echo sprintf("❌ Credentials file not found: %s\n", $credPath);
            return 1;
        }

        try {
            echo sprintf("📄 Loading credentials from: %s\n", $credPath);
            $creds = License::loadCredentialsFile($credPath);

            echo "\n=== Credentials Loaded ===\n";
            echo sprintf("Email:       %s\n", $creds['email']);
            echo sprintf("Client ID:   %s\n", $creds['client_id']);
            echo sprintf("License Key: %s...\n", substr($creds['license_key'], 0, 10));
            echo "\n✅ Credentials are valid and ready for activation\n";
            echo "\nNote: This SDK currently only supports license verification.\n";
            echo "Use the Go SDK example for full activation flow.\n";
        } catch (Exception $e) {
            echo sprintf("❌ Failed to load credentials: %s\n", $e->getMessage());
            return 1;
        }
        return 0;
    }

    // Load and verify license file
    if ($args['license_file'] !== null) {
        $licensePath = $args['license_file'];

        if (!file_exists($licensePath)) {
            echo sprintf("❌ License file not found: %s\n", $licensePath);
            return 1;
        }

        try {
            echo sprintf("📄 Loading license from: %s\n", $licensePath);

            $content = file_get_contents($licensePath);
            if ($content === false) {
                throw new RuntimeException("Failed to read license file");
            }

            $stored = json_decode($content, true, flags: JSON_THROW_ON_ERROR);

            echo "🔍 Verifying signature...\n";
            echo "🔓 Decrypting license...\n";

            $result = License::decrypt($stored);
            $license = $result['license'];

            echo "✅ License verified and decrypted!\n";

            // Check expiration
            $expiresAt = new DateTime($license['expires_at'] ?? 'now');
            $now = new DateTime();

            if ($now > $expiresAt) {
                echo sprintf("\n❌ LICENSE EXPIRED on %s\n", $expiresAt->format('Y-m-d'));
                return 1;
            }

            $daysLeft = (int) $now->diff($expiresAt)->days;
            if ($daysLeft <= 30) {
                echo sprintf("\n⚠️  License expires in %d days!\n", $daysLeft);
            }

            printLicenseInfo($license);
            printEntitlements($license);
            checkFeatures($license);
            checkScopes($license);

            echo "\n=== Done ===\n";
        } catch (Exception $e) {
            echo sprintf("❌ Failed to verify license: %s\n", $e->getMessage());
            return 1;
        }
        return 0;
    }

    // No arguments provided
    printUsage();
    return 1;
}

exit(main());
