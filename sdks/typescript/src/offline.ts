import fetch from 'cross-fetch';
import nacl from 'tweetnacl';
import fs from 'fs';
import path from 'path';

export type Config = {
    serverUrl: string;
    cacheDir?: string;
    fetcher?: typeof fetch;
};

export class OfflineClient {
    private serverUrl: string;
    private cacheDir?: string;
    private fetcher: typeof fetch;
    private signingKeys: Map<string, Uint8Array> = new Map();
    private manifest: any | null = null;

    constructor(cfg: Config) {
        if (!cfg.serverUrl) throw new Error('serverUrl required');
        this.serverUrl = cfg.serverUrl.replace(/\/$/, '');
        this.cacheDir = cfg.cacheDir;
        this.fetcher = cfg.fetcher ?? fetch;
        if (this.cacheDir) {
            fs.mkdirSync(this.cacheDir, { recursive: true });
            this.loadCachedManifest();
        }
    }

    private loadCachedManifest() {
        if (!this.cacheDir) return;
        const f = path.join(this.cacheDir, 'revocation_manifest.json');
        try {
            const b = fs.readFileSync(f, 'utf8');
            const obj = JSON.parse(b);
            this.manifest = obj.manifest;
            if (obj.signing_key_id && obj.manifest) this.manifest._signingKeyId = obj.signing_key_id;
        } catch (e) {
            // ignore
        }
    }

    async fetchActiveSigningKey() {
        const res = await this.fetcher(this.serverUrl + '/api/keys/offline-signing-public');
        if (!res.ok) throw new Error('fetch signing key failed: ' + res.status);
        const json = await res.json();
        if (!json.key_id || !json.public_key) throw new Error('invalid signing key response');
        const bytes = Buffer.from(json.public_key, 'base64');
        this.signingKeys.set(json.key_id, bytes);
        return json.key_id;
    }

    async fetchSigningKeyByID(keyID: string) {
        if (!keyID) throw new Error('keyID required');
        const res = await this.fetcher(this.serverUrl + '/api/keys/offline-signing-public/' + encodeURIComponent(keyID));
        if (!res.ok) throw new Error('fetch signing key by id failed: ' + res.status);
        const json = await res.json();
        if (!json.key_id || !json.public_key) throw new Error('invalid signing key response');
        const bytes = Buffer.from(json.public_key, 'base64');
        this.signingKeys.set(json.key_id, bytes);
        return json.key_id;
    }

    async verifySignedBundle(bundleJSON: string, deviceFingerprint?: string) {
        const b = JSON.parse(bundleJSON);
        if (!b.payload || !b.signature) throw new Error('invalid bundle JSON');
        const skid = b.payload.signing_key_id;
        if (!skid) throw new Error('bundle missing signing_key_id');
        let pk = this.signingKeys.get(skid);
        if (!pk) {
            // try fetching the specific key first (handles rotations)
            try {
                await this.fetchSigningKeyByID(skid);
                pk = this.signingKeys.get(skid);
            } catch (e) {
                // fallback to active
                await this.fetchActiveSigningKey();
                pk = this.signingKeys.get(skid);
            }
            if (!pk) throw new Error('signing key not available');
        }
        const payloadJSON = JSON.stringify(b.payload);
        const ok = nacl.sign.detached.verify(new TextEncoder().encode(payloadJSON), Buffer.from(b.signature, 'base64'), pk as Uint8Array);
        if (!ok) throw new Error('invalid bundle signature');

        if (deviceFingerprint && b.payload.device_fingerprint && b.payload.device_fingerprint !== deviceFingerprint) {
            throw new Error('device fingerprint mismatch');
        }

        // check manifest for revocation if loaded
        if (this.manifest) {
            const token = b.payload.token;
            const revoked = (this.manifest.revoked_offline_tokens || []).some((r: any) => r.token === token);
            if (revoked) throw new Error('token revoked in manifest');
        }

        return b.payload;
    }

    async syncManifest(since?: string) {
        let url = this.serverUrl + '/api/licenses/offline-revocations';
        if (since) url += '?since=' + encodeURIComponent(since);
        const res = await this.fetcher(url);
        if (!res.ok) throw new Error('failed to fetch manifest: ' + res.status);
        const json = await res.json();
        if (json.signature) {
            const skid = json.signing_key_id;
            let pk = this.signingKeys.get(skid);
            if (!pk) {
                try {
                    await this.fetchSigningKeyByID(skid);
                    pk = this.signingKeys.get(skid);
                } catch (e) {
                    // fallback to active
                    await this.fetchActiveSigningKey();
                    pk = this.signingKeys.get(skid);
                }
                if (!pk) throw new Error('signing key not available');
            }
            const manifestJSON = JSON.stringify(json.manifest);
            const ok = nacl.sign.detached.verify(new TextEncoder().encode(manifestJSON), Buffer.from(json.signature, 'base64'), pk as Uint8Array);
            if (!ok) throw new Error('manifest signature invalid');
            json.manifest._signingKeyId = skid;
        }

        if (since && this.manifest) {
            // merge incremental lists
            const existing = this.manifest;
            const seen = new Set(existing.revoked_offline_tokens?.map((r: any) => r.token) || []);
            for (const t of json.manifest.revoked_offline_tokens || []) {
                if (!seen.has(t.token)) existing.revoked_offline_tokens.push(t);
            }
            const licSeen = new Set(existing.revoked_licenses?.map((r: any) => r.license_key) || []);
            for (const l of json.manifest.revoked_licenses || []) {
                if (!licSeen.has(l.license_key)) existing.revoked_licenses.push(l);
            }
            existing.version = json.manifest.version;
            existing.generated_at = json.manifest.generated_at;
            existing._signingKeyId = json.signing_key_id;
            this.manifest = existing;
        } else {
            this.manifest = json.manifest;
            if (json.signing_key_id) this.manifest._signingKeyId = json.signing_key_id;
        }

        if (this.cacheDir) {
            const out = { manifest: this.manifest } as any;
            if (json.signature) {
                out.signature = json.signature;
                out.signing_key_id = json.signing_key_id;
            }
            fs.writeFileSync(path.join(this.cacheDir, 'revocation_manifest.json'), JSON.stringify(out, null, 2), 'utf8');
        }

        return this.manifest;
    }
}

export default OfflineClient;
