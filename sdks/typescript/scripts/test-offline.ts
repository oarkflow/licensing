import http from 'http';
import { randomBytes } from 'crypto';
import nacl from 'tweetnacl';
import OfflineClient from '../src/offline';

async function run() {
    // generate a keypair
    const keypair = nacl.sign.keyPair();
    const pub = Buffer.from(keypair.publicKey).toString('base64');

    const manifest = {
        version: '1',
        generated_at: new Date().toISOString(),
        revoked_offline_tokens: [{ token: 'tok-123', license_key: 'LIC-AAA', revoked_at: new Date().toISOString() }],
        revoked_licenses: []
    };
    const manifestBytes = Buffer.from(JSON.stringify(manifest));
    const sig = Buffer.from(nacl.sign.detached(manifestBytes, keypair.secretKey)).toString('base64');

    // create a test server
    const server = http.createServer((req, res) => {
        if (req.url === '/api/keys/offline-signing-public') {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ key_id: 'k1', public_key: pub }));
            return;
        }
        if (req.url && req.url.startsWith('/api/licenses/offline-revocations')) {
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({ manifest, signature: sig, signing_key_id: 'k1' }));
            return;
        }
        res.statusCode = 404;
        res.end('not found');
    });

    server.listen(0, async () => {
        const port = (server.address() as any).port;
        const client = new OfflineClient({ serverUrl: `http://127.0.0.1:${port}`, cacheDir: './tmp-offline-cache' });
        try {
            const m = await client.syncManifest();
            console.log('synced manifest ok:', m.version);

            // create signed bundle for a revoked token and verify should fail
            const payload = { token: 'tok-123', device_fingerprint: 'dev-1', valid_until: new Date(Date.now() + 86400000).toISOString(), signing_key_id: 'k1' };
            const payloadBytes = Buffer.from(JSON.stringify(payload));
            const bundle = { payload, signature: Buffer.from(nacl.sign.detached(payloadBytes, keypair.secretKey)).toString('base64') };
            try {
                await client.verifySignedBundle(JSON.stringify(bundle), 'dev-1');
                console.error('expected verification to fail for revoked token');
                process.exit(2);
            } catch (e) {
                console.log('verification correctly failed for revoked token:', e.message || e);
            }

            console.log('offline SDK smoke tests passed');
            process.exit(0);
        } catch (e) {
            console.error('offline sdk failed', e);
            process.exit(1);
        } finally {
            server.close();
            try { require('fs').rmSync('./tmp-offline-cache', { recursive: true, force: true }) } catch { }
        }
    });
}

run();
