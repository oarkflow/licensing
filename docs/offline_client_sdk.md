# Offline Client SDK guide

This document summarizes how client applications can verify signed offline bundles locally, keep a revocation manifest in sync and fall back to server-side validation.

## 1. Verification primitives

- Server issues a signed bundle when an offline token is requested. The bundle format:

```json
{
  "payload": { ... },
  "signature": "BASE64(ED25519_SIGNATURE)"
}
```

The payload includes token, license_key, client_id, device_fingerprint, valid_until, max_uses, issued_at and signing_key_id.

Clients should:

1. Fetch the active public key from `/api/keys/offline-signing-public` (contains key_id and base64 public key).
2. Verify signature over the payload using Ed25519 and the public key.
3. Inspect payload fields (expiry, fingerprint, max_uses). If valid locally, allow offline operation.

If local verification fails or you need to log usage, fallback to server validation by POSTing the bundle or token to `/api/licenses/offline-validate`.

## 2. Revocation manifest

The server exposes `/api/licenses/offline-revocations` which returns a JSON manifest listing revoked offline tokens and revoked license keys, optionally filtered by since=ISO timestamp.

Manifest example:

```json
{
  "manifest": { "version":"1", "generated_at":"...",
    "revoked_offline_tokens": [{"token":"...","license_key":"...","revoked_at":"..."}],
    "revoked_licenses": [{"license_key":"...","revoked_at":"..."}] },
  "signature": "BASE64",
  "signing_key_id": "key-id"
}
```

Clients should fetch the manifest periodically (startup and periodic sync) and verify the manifest's signature against the known public key. If the manifest lists your token/license as revoked, mark it revoked locally.

### Fetching a specific public key by id

When bundles include a `signing_key_id` (the ID of the private key used), clients should fetch the matching public key if they don't already have it cached. The server exposes a per-key endpoint so clients can verify older bundles after a key rotation:

GET /api/keys/offline-signing-public/{id}

Response: { key_id: string, public_key: string (base64) }

Prefer requesting the exact key by id before falling back to the active key endpoint — this ensures you can verify older bundles after a rotation.

Use the `since` query param to request only revocations since your last sync time.

## 3. Synchronization strategy (client side)

Recommended approach for client applications:

1. On startup:
   - Download the active signing public key (cache it).
   - Download the revocation manifest (with since=last_sync_time).
   - Verify the manifest signature using the public key and merge revocations into local revocation state.

2. On license issuance:
   - Receive the signed bundle; verify locally using cached public key. If verification fails, optionally fetch fresh public key and retry.
   - If still failing, fall back to server validation.

3. Periodically (hourly/daily):
   - Re-fetch revocation manifest (use since) and update revocation cache.

4. When connecting online (optional):
   - POST the signed bundle or token to `/api/licenses/offline-validate` for server-side validation and usage logging.

## 4. Examples

- Go example: `examples/offline-client/go/` (main.go) — uses standard library and ed25519.
- Node example: `examples/offline-client/node/` (client.js) — uses tweetnacl to verify signatures.

Use these examples as starting points for production SDKs. For production, integrate with system-level secure key storage and verify library support for ed25519.

## React (browser) — concrete verification + manifest caching example

Below is a concrete React hook / component snippet using the existing `api` client (web/src/services/api.ts) that shows how to:
- Verify a signed bundle using the signing_key_id → fetch per-key public key
- Verify the revocation manifest and cache it locally (IndexedDB/localStorage)

Important: This example uses `tweetnacl` for ed25519 verification in the browser. Add `tweetnacl` to your web dependencies before using it.

```tsx
import { useState } from 'react';
import nacl from 'tweetnacl';
import { api } from '@/services/api';

async function fetchPublicKeyFor(skid: string) {
   // Try per-key endpoint first (most robust)
   let resp = await api.getOfflineSigningPublicKeyByID(skid);
   if (!resp.success) {
      // fallback to active key
      resp = await api.getActiveOfflineSigningPublicKey();
   }
   if (!resp.success || !resp.data) throw new Error('failed to fetch public key');
   const { public_key } = resp.data as { key_id: string; public_key: string };
   return Uint8Array.from(atob(public_key).split('').map(c => c.charCodeAt(0)));
}

export default function VerifyBundle({ bundleJSON }) {
   const [ok, setOk] = useState<boolean | null>(null);

   const verify = async () => {
      const parsed = JSON.parse(bundleJSON);
      const skid = parsed.payload.signing_key_id;
      if (!skid) throw new Error('bundle missing signing_key_id');

      const pub = await fetchPublicKeyFor(skid);
      const payloadJSON = JSON.stringify(parsed.payload);
      const payloadBytes = new TextEncoder().encode(payloadJSON);
      const sigBytes = Uint8Array.from(atob(parsed.signature).split('').map(c => c.charCodeAt(0)));

      const okSig = nacl.sign.detached.verify(payloadBytes, sigBytes, pub as Uint8Array);
      if (!okSig) {
         setOk(false);
         return;
      }

      // basic checks
      if (parsed.payload.valid_until && Date.parse(parsed.payload.valid_until) < Date.now()) {
         setOk(false);
         return; // expired
      }

      // fetch and verify manifest (cached)
      const manifestResp = await api.request('/api/licenses/offline-revocations');
      if (manifestResp.success && manifestResp.data) {
         const man = manifestResp.data as any;
         if (man.signature) {
            const manBytes = new TextEncoder().encode(JSON.stringify(man.manifest));
            const manSig = Uint8Array.from(atob(man.signature).split('').map(c => c.charCodeAt(0)));
            const verified = nacl.sign.detached.verify(manBytes, manSig, pub as Uint8Array);
            if (!verified) throw new Error('manifest signature invalid');
         }
         // cache manifest locally — here we use localStorage for simplicity
         localStorage.setItem('revocation_manifest', JSON.stringify(man));

         // reject offline token if present in manifest
         const token = parsed.payload.token;
         const isRevoked = (man.manifest.revoked_offline_tokens || []).some((r:any) => r.token === token);
         if (isRevoked) {
            setOk(false);
            return;
         }
      }

      setOk(true);
   };

   return (
      <div>
         <button onClick={() => verify()}>Verify bundle</button>
         {ok === true && <div>Bundle verified and manifest checked ✅</div>}
         {ok === false && <div>Verification failed ❌</div>}
      </div>
   );
}
```

Notes:
- In production, replace `localStorage` with an encrypted local cache (IndexedDB + encryption) and validate cached manifest timestamps and signatures on every use.
- Always prefer fetching the key by ID (`/api/keys/offline-signing-public/:id`) so rotated keys can still be verified.
