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
 *   npx ts-node index.ts --license-file /path/to/.license.dat
 *   npx ts-node index.ts --credentials-file /path/to/credentials.json
 */

import { parseArgs } from "node:util";
import { existsSync } from "node:fs";
import {
    loadLicenseFile,
    decryptStoredLicense,
    loadCredentialsFile,
    hasFeature,
    canPerform,
    LicensingClient,
} from "../../src/index.js";
import type { LicenseData } from "../../src/types.js";

// Parse command line arguments
const { values } = parseArgs({
    options: {
        "license-file": { type: "string", short: "l" },
        "credentials-file": { type: "string", short: "c" },
        "server-url": { type: "string" },
        "product-id": { type: "string" },
        "config-dir": { type: "string" },
        activate: { type: "boolean" },
        verify: { type: "boolean" },
        "allow-insecure-http": { type: "boolean" },
        help: { type: "boolean", short: "h" },
    },
});

function printUsage(): void {
    console.log(`
TypeScript Licensing SDK - Basic Example

Usage:
  npx ts-node index.ts --license-file <path>       Load and verify a license file
  npx ts-node index.ts --credentials-file <path>  Load credentials for activation
  npx ts-node index.ts --activate --credentials-file <path> --server-url http://localhost:6601 --allow-insecure-http
  npx ts-node index.ts --verify --credentials-file <path> --server-url http://localhost:6601 --allow-insecure-http

Options:
  -l, --license-file <path>      Path to stored license file (.license.dat)
  -c, --credentials-file <path>  Path to credentials JSON file
  --server-url <url>             Licensing server URL
  --product-id <id-or-slug>      Product ID/slug for activation or verification
  --config-dir <path>            Local SDK config directory
  --activate                     Activate and save a license file
  --verify                       Verify with the server and refresh the license file
  --allow-insecure-http          Permit http:// server URLs for local development
  -h, --help                     Show this help message

Credentials file format:
  {
    "email": "user@example.com",
    "client_id": "client-123",
    "license_key": "XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX"
  }
`);
}

function formatDate(dateStr: string): string {
    return new Date(dateStr).toLocaleString();
}

function printLicenseInfo(license: LicenseData): void {
    console.log("\n=== License Information ===");
    console.log(`ID:            ${license.id}`);
    console.log(`Email:         ${license.email}`);
    console.log(`Client ID:     ${license.client_id}`);
    console.log(`Plan:          ${license.plan_slug}`);
    console.log(`Issued:        ${formatDate(license.issued_at)}`);
    console.log(`Expires:       ${formatDate(license.expires_at)}`);
    console.log(`Max Devices:   ${license.max_devices}`);
    console.log(`Activations:   ${license.current_activations}`);
    console.log(`Check Mode:    ${license.check_mode}`);

    if (license.is_revoked) {
        console.log(`\n⚠️  LICENSE REVOKED: ${license.revoke_reason || "No reason provided"}`);
    }
}

function printEntitlements(license: LicenseData): void {
    console.log("\n=== Feature Entitlements ===");

    if (!license.entitlements?.features) {
        console.log("No feature entitlements configured for this license.");
        console.log("Configure a product, plan, and features in the license server");
        console.log("to enable feature-based access control.");
        return;
    }

    console.log(`Product: ${license.entitlements.product_slug}`);
    console.log(`Plan:    ${license.entitlements.plan_slug}`);
    console.log("");

    // List all features
    for (const [slug, feature] of Object.entries(license.entitlements.features)) {
        const status = feature.enabled ? "✅ Enabled" : "❌ Disabled";
        console.log(`  Feature: ${slug} - ${status}`);

        // List scopes
        if (feature.scopes) {
            for (const [scopeSlug, scope] of Object.entries(feature.scopes)) {
                let permission = scope.permission;
                if (scope.limit && scope.limit > 0) {
                    permission = `${permission} (limit: ${scope.limit})`;
                }
                console.log(`    - ${scopeSlug}: ${permission}`);
            }
        }
    }
}

function checkFeatures(license: LicenseData): void {
    console.log("\n=== Feature Checks ===");

    const features = ["gui", "cli", "api", "premium"];
    for (const feat of features) {
        if (hasFeature(license, feat)) {
            console.log(`✅ Feature '${feat}' is available`);
        } else {
            console.log(`❌ Feature '${feat}' is not available`);
        }
    }
}

function checkScopes(license: LicenseData): void {
    console.log("\n=== Scope Checks ===");

    const scopes: [string, string][] = [
        ["gui", "list"],
        ["gui", "create"],
        ["gui", "update"],
        ["gui", "delete"],
        ["api", "read"],
        ["api", "write"],
    ];

    for (const [feature, scope] of scopes) {
        const result = canPerform(license, feature, scope);
        if (result.allowed) {
            if (result.limit > 0) {
                console.log(`✅ Can ${feature}:${scope} (limit: ${result.limit})`);
            } else {
                console.log(`✅ Can ${feature}:${scope}`);
            }
        } else {
            console.log(`❌ Cannot ${feature}:${scope}`);
        }
    }
}

async function main(): Promise<void> {
    console.log("=== TypeScript Licensing SDK - Basic Example ===\n");

    if (values.help) {
        printUsage();
        process.exit(0);
    }

    // Load credentials file if provided
    if (values["credentials-file"]) {
        const credPath = values["credentials-file"];

        if (!existsSync(credPath)) {
            console.error(`❌ Credentials file not found: ${credPath}`);
            process.exit(1);
        }

        try {
            console.log(`📄 Loading credentials from: ${credPath}`);
            const creds = await loadCredentialsFile(credPath);

            if (values.activate || values.verify) {
                const client = new LicensingClient({
                    serverUrl: values["server-url"] ?? "https://localhost:6601",
                    allowInsecureHttp: values["allow-insecure-http"],
                    configDir: values["config-dir"],
                    licenseFile: values["license-file"],
                    productId: values["product-id"],
                    appName: "typescript-basic-example",
                    appVersion: "0.1.0",
                });
                const result = values.activate
                    ? await client.activate(creds, { productId: values["product-id"], licenseFile: values["license-file"] })
                    : await client.verify(creds, { productId: values["product-id"], licenseFile: values["license-file"] });
                const storedPath = values["license-file"] ?? client.licenseFile();
                console.log(`\n✅ ${values.activate ? "Activation" : "Verification"} succeeded`);
                console.log(`Saved license: ${storedPath}`);
                const { license } = decryptStoredLicense(result.stored, client.deviceIdentity().fingerprint);
                printLicenseInfo(license);
                printEntitlements(license);
                return;
            }

            console.log("\n=== Credentials Loaded ===");
            console.log(`Email:       ${creds.email}`);
            console.log(`Client ID:   ${creds.client_id}`);
            console.log(`License Key: ${creds.license_key.substring(0, 10)}...`);
            console.log("\n✅ Credentials are valid and ready for activation");
            console.log("Use --activate or --verify with --server-url to contact a licensing server.");
        } catch (err) {
            console.error(`❌ Failed to load credentials: ${err}`);
            process.exit(1);
        }
        return;
    }

    // Load and verify license file
    if (values["license-file"]) {
        const licensePath = values["license-file"];

        if (!existsSync(licensePath)) {
            console.error(`❌ License file not found: ${licensePath}`);
            process.exit(1);
        }

        try {
            console.log(`📄 Loading license from: ${licensePath}`);
            const stored = await loadLicenseFile(licensePath);

            console.log("🔍 Verifying signature...");
            console.log("🔓 Decrypting license...");
            const { license } = decryptStoredLicense(stored);

            console.log("✅ License verified and decrypted!");

            // Check expiration
            const expiresAt = new Date(license.expires_at);
            const now = new Date();

            if (now > expiresAt) {
                console.log(`\n❌ LICENSE EXPIRED on ${expiresAt.toLocaleDateString()}`);
                process.exit(1);
            }

            const daysLeft = Math.ceil((expiresAt.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
            if (daysLeft <= 30) {
                console.log(`\n⚠️  License expires in ${daysLeft} days!`);
            }

            printLicenseInfo(license);
            printEntitlements(license);
            checkFeatures(license);
            checkScopes(license);

            console.log("\n=== Done ===");
        } catch (err) {
            console.error(`❌ Failed to verify license: ${err}`);
            process.exit(1);
        }
        return;
    }

    // No arguments provided
    printUsage();
    process.exit(1);
}

main().catch((err) => {
    console.error("Fatal error:", err);
    process.exit(1);
});
