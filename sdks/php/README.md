# PHP Licensing SDK (Plan)

The PHP SDK will mirror the Go + TypeScript implementations by consuming the shared fixtures under `docs/fixtures/v1`. Immediate next steps:

1. **Project scaffold**
   - Initialize a Composer package (`oarkflow/licensing-client`), target PHP 8.2+, and enable strict types.
   - Configure PSR-4 autoloading under `src/` and add PHPUnit for fixture validation tests.

2. **Crypto utilities**
   - Implement helpers for:
     - Device fingerprint hashing (reuse server-side fingerprint inputs exposed through the API).
     - AES-256-GCM decrypt/encrypt using `openssl_decrypt`.
     - RSA-PSS signature validation via `openssl_verify` with SHA-256 + automatic salt length.

3. **Fixture verification test**
   - Load `docs/fixtures/v1/*` with Symfony/YAML or native PHP JSON decoding.
   - Verify activation + stored responses the same way as `pkg/client/fixtures_validation_test.go` and `sdks/typescript/scripts/verifyFixtures.ts`.

4. **HTTP + storage abstraction**
   - Wrap Guzzle (or native cURL) to hit `/api/activate` + `/api/verify` with the secure envelope header dance.
   - Persist `.license.dat` and `.license.dat.chk` under `$HOME/.licensing` (matching permissions via `chmod 0600`).

These tasks will ensure the PHP SDK stays protocol-compliant before real application bindings ship.
