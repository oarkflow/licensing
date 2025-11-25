# Licensing SDK Fixtures

Deterministic fixtures keep every client SDK aligned with the Go reference implementation. Each bundle captures the exact activation, response, and on-disk artifacts for a known license so other runtimes can replay the crypto without a running server.

## Directory layout

```
docs/fixtures/
  v1/
    activation_request.json
    activation_response.json
    license.dat                # exact on-disk license file (compact JSON)
    stored_license.json        # prettified view of license.dat
    license.dat.chk            # checksum sidecar exactly as persisted
    checksum_pretty.json       # human-readable view of license.dat.chk
    license_data.json          # decrypted payload + fingerprint
```

- **activation_request.json** – raw body posted to `/api/activate`.
- **activation_response.json** – plaintext server response before persistence.
- **license.dat** – byte-for-byte output of the Go client (JSON with base64 blobs).
- **stored_license.json** – prettified copy of `license.dat` for easier inspection.
- **license_data.json** – decrypted payload (session key removed) plus `device_fingerprint`.
- **license.dat.chk** – checksum vault written by the Go client.
- **checksum_pretty.json** – prettified copy of the checksum vault for documentation.

## Regenerating fixtures

1. Run the generator helper: `go test ./pkg/client -run TestGenerateFixtures -update-fixtures`.
2. Commit the updated bundle together with the generator change to keep provenance intact.

Each bundle’s `README.md` should note:

- Go commit hash and date.
- Signing provider type and key fingerprint.
- Any deviations (e.g., mocked transport key).

## Roadmap

- [x] Implement `TestGenerateFixtures` to emit the bundle under `docs/fixtures/v1/`.
- [ ] Add a local CI/test harness (per SDK repo) that downloads fixture bundles and runs compatibility tests before merging.
- [ ] Expand bundles for future protocol versions (e.g., v1.1) while retaining older sets for regression tests.
