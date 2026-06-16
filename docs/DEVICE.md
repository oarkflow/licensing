# Device Fingerprinting Tool

Standalone, tamper-resistant device fingerprint tooling for hardware diagnostics and proof-key-bound license activation. Delivered as a small, self-verifying CLI.

## File Map

| File | Role |
|------|------|
| `cmd/device-fingerprint/main.go` | Fingerprint binary — outputs proof-key identity plus hardware diagnostics, runs self-verification |
| `cmd/device-keygen/main.go` | Device Ed25519 key pair generator (optional, for proof-key fingerprinting) |
| `scripts/sign-fingerprint.go` | Build-time signing tool — generates signing keys, signs binaries |
| `scripts/build-fingerprint.sh` | Build orchestration — key gen → embed → build → sign |
| `Makefile` (`fingerprint-*` targets) | Convenience targets wrapping the build script |

## Build

```bash
# Quick dev build (no tamper check)
go build -o device-fingerprint ./cmd/device-fingerprint

# Production build (signed + tamper-proof)
bash scripts/build-fingerprint.sh
# or
make fingerprint-build

# Output as JSON
./device-fingerprint --json
```

## Authentication modes

1. **Proof-key identity** (`device-fingerprint`, SDK clients, or `licensing-server device-fingerprint`): Binds identity to an Ed25519 or TPM/RSA key pair stored on the device. Fingerprint format: `fp:v2:<algorithm>:<sha256(pubkey)>`. This is the canonical server-side device identity and must be proven with challenge-response on activation, verification, and trials.

2. **Hardware diagnostics**: The same output may include `hardware_fingerprint` in `hw:v1:<sha256>` format, derived from stable hardware identifiers such as DMI UUID, machine-id, and board serials. This is diagnostic/risk metadata only and is not accepted as the primary activation identity.

The standalone `./device-fingerprint` binary and `go run ./cmd device-fingerprint` intentionally use the same proof-key identity path, so their primary `Fingerprint` values should match when they use the same config directory and device key file.

## Tamper-proof architecture

The binary signs itself at build time and verifies the signature at startup. Any modification to the binary — patching bytes, appending data, modifying the embedded public key — causes verification to fail and the binary to exit with code 1.

### Build-time (signing)

```
┌──────────────────────────────────────────────────┐
│ 1. Generate Ed25519 key pair (one-time)          │
│    scripts/sign-fingerprint.go -gen-key         │
└──────────────┬───────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────┐
│ 2. Build binary with embedded public key         │
│    go build -ldflags "-X main.embeddedPubKeyHex=…"│
└──────────────┬───────────────────────────────────┘
               │
               ▼
┌──────────────────────────────────────────────────┐
│ 3. Hash the built binary (SHA-256)               │
│ 4. Sign hash with Ed25519 private key             │
│ 5. Append signature footer to binary              │
│    64-byte Ed25519 signature + magic marker       │
└──────────────────────────────────────────────────┘
```

### Runtime verification

```
┌──────────────────────────────────────────────────┐
│ 1. Read own executable path (os.Executable)      │
│ 2. Open binary, read signed footer                │
│ 3. Verify footer magic marker                     │
│ 4. Hash remaining content (SHA-256)               │
│ 5. Verify hash + signature against embedded pubkey │
│ 6. Fail → exit 1 with "SECURITY FAILURE"          │
│    Pass → continue to fingerprint collection       │
└──────────────────────────────────────────────────┘
```

## Making it secure

### 1. Protect the signing key

The Ed25519 private key is the root of trust. If compromised, anyone can sign modified binaries.

- Store in a hardware security module (HSM) or key management service (KMS)
- In CI/CD: use encrypted secrets (GitHub Actions secrets, HashiCorp Vault, etc.)
- Never commit the signing key to version control
- Rotate keys periodically — generate a new pair, redeploy with the new public key

### 2. Secure the build pipeline

```bash
# CI/CD build (example)
SIGNING_KEY=$(vault read -field=private_key secret/device-fingerprint-signing-key)
echo "$SIGNING_KEY" > /tmp/signing-key.pem
chmod 600 /tmp/signing-key.pem
bash scripts/build-fingerprint.sh
rm -f /tmp/signing-key.pem
```

- Run the build in ephemeral, isolated CI containers
- Sign immediately after build, before any additional tooling touches the binary
- Verify the signature as a CI step: `./device-fingerprint --json`

### 3. Verify at critical points

The binary self-verifies on every execution. For additional defense-in-depth:

- **Package verification**: Checksum the distributed binary and verify before execution
- **Runtime integrity monitoring**: Periodic checks from a separate process
- **Build reproducibility**: Pin Go version and module hashes in `go.sum`

### 4. Binary distribution hardening

- Distribute over HTTPS with certificate pinning
- Sign release artifacts with a separate GPG or Sigstore key
- Provide checksums in a detached signature file (`.sha256sum.sig`)
- Consider embedding a Notary or Sigstore attestation in CI

### 5. Key management for device keys

When using the proof-key mode (`device-keygen`):

- The device private key (`device_ed25519.pem`) should never leave the device
- On first run, register the public key fingerprint with the licensing server
- If the device key is lost, the device must re-register (consider backup policies)
- For containers: mount a persistent volume for the key file; bind to a stable path

## Binary size

| Variant | Size | Notes |
|---------|------|-------|
| Dev build | ~3.4 MB | Includes debug symbols |
| Stripped (`-s -w`) | ~2.3 MB | Debug info removed |
| Stripped + UPX | ~700 KB | Requires `upx --best` |
| TinyGo | sub-MB | Limited stdlib support; test first |

To get the smallest binary:

```bash
go build -ldflags "-s -w" -o device-fingerprint ./cmd/device-fingerprint
upx --best device-fingerprint
```

## Threat model

The signed-footer approach detects:

- Binary patching (modifying instructions or data)
- Checksum bypass (modifying the self-verify logic or embedded key)
- Accidental or repeated signing mistakes (the signer replaces an existing footer)

It does **not** prevent:

- Running the binary in a debugger after verification passes
- LD_PRELOAD / DLL injection at the OS level
- Filesystem-level modification of the binary followed by running a separate verifier
- Full memory dumping after startup
- Compromise of the signing private key or build pipeline

Defense-in-depth (runtime monitoring, OS-level controls, TPM-backed storage) should be layered on for high-security deployments.
