#!/usr/bin/env php
<?php
/**
 * Offline verification example for PHP SDK
 *
 * Usage:
 *   php index.php --server http://localhost:6601 --bundle /path/to/bundle.json --cache /tmp/licensing-cache
 */

declare(strict_types=1);

require_once __DIR__ . '/../../vendor/autoload.php';

use Oarkflow\Licensing\Offline;

$options = getopt('', ['server:', 'bundle:', 'cache:']);
$server = $options['server'] ?? 'http://localhost:6601';
$bundleFile = $options['bundle'] ?? null;
$cacheDir = $options['cache'] ?? sys_get_temp_dir() . '/licensing-offline-cache';

if ($bundleFile === null) {
    echo "Usage: php index.php --server http://... --bundle /path/to/bundle.json --cache /tmp/cache\n";
    exit(1);
}

if (!file_exists($bundleFile)) {
    echo "Bundle file not found: $bundleFile\n";
    exit(2);
}

$bundle = file_get_contents($bundleFile);
if ($bundle === false) {
    echo "Failed to read bundle\n";
    exit(3);
}

try {
    $payload = Offline::verifySignedBundle($bundle, $server, $cacheDir);
    echo "✅ Bundle verified: \n";
    echo json_encode($payload, JSON_PRETTY_PRINT), PHP_EOL;
} catch (Throwable $e) {
    echo "Verification failed: " . $e->getMessage() . PHP_EOL;
    exit(4);
}

// Try to sync manifest
try {
    $manifest = Offline::syncManifest($server, $cacheDir);
    echo "Manifest synced: generated_at=" . ($manifest['generated_at'] ?? 'unknown') . PHP_EOL;
} catch (Throwable $e) {
    echo "Failed to sync manifest: " . $e->getMessage() . PHP_EOL;
}

exit(0);
