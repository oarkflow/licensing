# External API Request Guide

This guide explains how third-party systems can call the licensing service over HTTP. It complements `README.md`, `USAGE.md`, and `docs/api/licensing_openapi.yaml` by focusing on concrete request examples and the headers every integration must send.

## Base URL & Transport Requirements

- **Base URL** – default development server runs at `http://localhost:8801`; production deployments should expose `https://<your-domain>`.
- **TLS** – enable `LICENSE_SERVER_TLS_CERT`/`LICENSE_SERVER_TLS_KEY` so external callers always use HTTPS. Local-only HTTP is supported when `LICENSE_SERVER_ALLOW_INSECURE_HTTP=1`.
- **Rate limiting** – all endpoints are protected. Include a descriptive `User-Agent` so throttling and logging stay informative.

```bash
export BASE_URL="https://licensing.example.com"
export ADMIN_KEY="prod-admin-token"
```

## Authentication & Headers

Admin endpoints rely on static API keys; client endpoints use per-license headers. Always set the following:

| Header | Applies to | Notes |
| --- | --- | --- |
| `X-API-Key` | Admin endpoints (`/api/clients`, `/api/licenses`, etc.) | Value must match `LICENSE_SERVER_API_KEY` or any key in `LICENSE_SERVER_API_KEYS`. |
| `Content-Type: application/json` | All write operations | Requests and responses are JSON encoded. |
| `User-Agent` | All endpoints | Identify your system, e.g. `MyApp-Licensing/1.2.0`. |
| `X-Device-Fingerprint` | `/api/activate`, `/api/verify` | Required for device binding; format described in `docs/sdk_protocol.md`. |
| `X-License-Key` | `/api/activate`, `/api/verify` | Upper-case, hyphenless license key. |
| `X-License-Secure: 1` | Optional | When present, responses are wrapped in a secure envelope for transport re-encryption. |

## Standard Request Template

```bash
curl -sSL \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: my-erp/2024.05' \
  "$BASE_URL/api/..."
```

Automation pipelines typically export `BASE_URL` and `ADMIN_KEY`; rotate the key regularly and scope one key per integration partner when possible.

## Workflow: Onboard a Customer & Issue a License

### 1. Create or update the client record

```bash
curl -sSL -X POST "$BASE_URL/api/clients" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: my-erp/2024.05' \
  -d '{
    "email": "owner@example.com",
    "metadata": {
      "account_id": "acct_123",
      "plan": "enterprise"
    }
  }'
```

The response contains the canonical `id` you will reference everywhere else. Store it alongside your billing/customer record.

### 2. Issue a license tied to a plan

```bash
curl -sSL -X POST "$BASE_URL/api/licenses" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: my-erp/2024.05' \
  -d '{
    "client_id": "client-123",
    "duration_days": 365,
    "max_devices": 5,
    "plan_slug": "enterprise",
    "check_mode": "monthly",
    "check_interval_seconds": 0
  }'
```

Important response fields:

- `id` – internal license ID for future revoke/reinstate calls.
- `license_key` – share with your customer or activation automation.
- `expires_at`, `plan_slug`, `max_devices` – echo the current policy.

### 3. Distribute the activation bundle

Send the customer (or downstream tool) the trio of values required by `/api/activate`:

```json
{
  "email": "owner@example.com",
  "client_id": "client-123",
  "license_key": "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"
}
```

They can feed this into the provided CLI (`--license-file`) or call the activation endpoint directly as shown below.

## Workflow: Device Activation & Periodic Verification

External systems that skip the CLI must reproduce the handshake defined in `docs/sdk_protocol.md`:

```bash
DEVICE_FP="$(./fingerprint-helper)"
LICENSE_KEY="AAAA..." # uppercase + no dashes

curl -sSL -X POST "$BASE_URL/api/activate" \
  -H 'User-Agent: billing-sync/1.0' \
  -H "X-Device-Fingerprint: $DEVICE_FP" \
  -H "X-License-Key: $LICENSE_KEY" \
  -H 'X-License-Secure: 1' \
  -H 'Content-Type: application/json' \
  -d '{
    "email": "owner@example.com",
    "client_id": "client-123",
    "license_key": "AAAA-BBBB-...",
    "device_fingerprint": "'$DEVICE_FP'"
  }'
```

A successful response returns either:

- Plain JSON containing `encrypted_license`, `nonce`, `signature`, and `public_key`.
- A secure envelope (`nonce`, `ciphertext`, `tag`) when `X-License-Secure: 1` is supplied.

Store the encrypted blob exactly; it is already sealed to the fingerprint. To refresh the lease, repeat the same call against `/api/verify` with the cached license data.

## Workflow: License Lifecycle Management

```bash
LICENSE_ID="lic_01HRV..."
CLIENT_ID="client-123"

# Revoke a compromised key
curl -sSL -X POST "$BASE_URL/api/licenses/$LICENSE_ID/revoke" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -H 'User-Agent: my-erp/2024.05' \
  -d '{"reason":"chargeback"}'

# Reinstate after resolving the issue
curl -sSL -X POST "$BASE_URL/api/licenses/$LICENSE_ID/reinstate" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'User-Agent: my-erp/2024.05'

# Temporarily block a reseller or abusive client
curl -sSL -X POST "$BASE_URL/api/clients/$CLIENT_ID/ban" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"reason":"abuse"}'

curl -sSL -X POST "$BASE_URL/api/clients/$CLIENT_ID/unban" \
  -H "X-API-Key: $ADMIN_KEY" \
  -H 'User-Agent: my-erp/2024.05'
```

These endpoints immediately affect subsequent activations and verifications; no server restart is required.

## Error Handling Cheatsheet

| Status | Meaning | Recommended Action |
| --- | --- | --- |
| `400` | Validation failed (missing field, malformed fingerprint) | Fix the payload and retry. |
| `401` | Bad `X-API-Key`, banned client, or revoked license | Confirm you are using the correct key and that the client/license is active. |
| `404` | Resource not found | Ensure IDs are correct and issued in the target environment. |
| `409` | Activation limit reached | Increase `max_devices` or revoke unused activations. |
| `429` | Rate limit exceeded | Back off exponentially and include a clearer `User-Agent`. |
| `500` | Server error | Retry with jitter, then escalate with logs. |

Most admin operations are idempotent; resubmitting the same revoke/reinstate call is safe.

## Additional Resources

- `README.md` – architecture and feature overview.
- `USAGE.md` – end-to-end operational runbooks.
- `docs/api/licensing_openapi.yaml` – canonical request/response schema.
- `docs/sdk_protocol.md` – device fingerprint and secure transport details.

Use this file as the onboarding reference for partners who need to call the API directly without embedding the provided CLI or SDKs.
