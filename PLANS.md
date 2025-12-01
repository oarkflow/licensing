# Secretr Pricing Plans

Secretr is a **local-first, offline-capable** secret management tool designed for developers, teams, and enterprises. All data stays on your device with military-grade encryption.

---

## Common Features (All Plans)

These core features are included in every plan:

### 🔐 Security & Encryption
- AES-256-GCM encryption at rest
- Argon2id key derivation (NIST SP 800-57)
- Device fingerprint binding
- Brute-force protection & rate limiting

### 📦 Core Secrets Management
- Secret CRUD operations (get, set, delete, list)
- Nested keys with dot notation
- JSON value parsing & pretty-printing
- Copy secrets to clipboard

### 📁 Basic File Vault
- Encrypted file upload/download
- File metadata (MIME type, size, timestamps)

### 🔑 Basic SSH Management
- SSH key storage (add, edit, delete, reveal)
- SSH key copy to clipboard

### ⚡ Basic Generators
- Password/passphrase generation
- PIN generation
- Random string generation

### 🌐 Basic Environment Integration
- Export secret as environment variable
- Copy secrets to `.env` files

### 📤 Basic Import
- Import from `.env` files

### 🖥️ CLI Experience
- Direct command execution
- Silent mode for automation
- Clipboard integration
- Build/version info commands

---

## Personal - $19/device/year (min 1 device)

**Best for:** Individual developers managing personal secrets

### Storage
- 500 MB encrypted vault storage

### Features
Everything in Common Features plus:

### 🔐 Enhanced Security
- Vault integrity verification (HMAC-SHA256)
- Emergency vault lock
- Security policy configuration

### 📦 Enhanced Secrets
- Secret soft delete & restore
- Secret metadata (tags, properties, timestamps)
- Secret expiration (TTL-based auto-cleanup)

### 📁 Enhanced File Vault
- Password protection (per-file)
- File expiration (TTL-based)
- Corruption detection (SHA-256 checksums)

### 🔑 Enhanced SSH
- SSH key generation (RSA, ECDSA, Ed25519)
- SSH connection profiles
- SSH session execution

### ⚡ Enhanced Generators
- JWT signing secret generation
- API key generation (prefix, segments, checksum)
- Symmetric encryption key generation
- Custom encoding (base64, base64url, hex)

### 🌐 Enhanced Environment
- Load environment variables into vault
- Enrich process environment with secrets
- Copy secrets to JSON config files

### 📤 Enhanced Import & Export
- Import from JSON
- Import from YAML
- Manual encrypted backup & restore
- Backup listing

### 🖥️ Enhanced CLI & GUI
- Interactive REPL mode
- Cross-platform desktop GUI (Fyne)
- Login gate with master key
- Tabbed secret management
- License status display

### 📊 Basic Observability
- Health status check
- Vault metrics (secrets count, files count)
- JSON output format

---

## Solo - $49/device/year (min 3 devices)

**Best for:** Power users and freelancers with multiple workstations

### Storage
- 2 GB encrypted vault storage

### Features
Everything from Personal plus:

### 🔐 Advanced Authentication
- Two-Factor Authentication (TOTP)
- Passkey/WebAuthn authentication
- Shamir Secret Sharing for master key

### 📦 Advanced Secrets
- Per-secret password protection
- Secret rollback (version history)
- Secret lease metadata & expiry
- Dynamic/ephemeral secrets with TTL

### 📁 Advanced File Vault
- File tagging & custom properties
- File preview/render in CLI

### 🔑 Advanced SSH & Certificates
- Bastion/jump host support
- X.509 certificate generation
- Custom certificate durations
- RSA keypair generation (up to 4096-bit)
- EC/ECDSA keypair generation (P256/P384/P521)

### 📝 Scratchpad
- Encrypted notes (scratchpads)
- Scratchpad password protection
- Scratchpad expiration (TTL-based)
- Secret ranges in scratchpads

### 📤 Advanced Import & Export
- Import from CSV/TSV
- Selective export (secrets, files, SSH)
- Custom backup paths

### 📊 Audit Logging
- HMAC-signed audit logs with hash chain
- Audit log viewing
- Audit log filtering (actor, time range)

### 🖼️ Enhanced GUI
- File manager with toolbar
- SSH key management dialogs
- Certificate management UI
- Avatar badges & customization

---

## Professional - $99/device/year (min 10 devices)

**Best for:** Small teams collaborating on projects

### Storage
- 5 GB encrypted vault storage

### Features
Everything from Solo plus:

### 🔐 Team Security
- Tampering detection & auto-response
- File export restrictions
- Emergency vault wipe (DoD 5220.22-M)
- Process allowlisting verification

### 📦 Templates & Automation
- Secret templates (DB, API, AWS credentials)
- Custom template definitions (JSON/YAML)
- Template field validation (regex)
- Template application with prefixes

### 🔄 Rotation Policies
- Rotation policies (interval-based)
- Password/API key generators for rotation
- Rotation history tracking

### 📁 Bundle Management
- Encrypted bundle import/export
- Bundle passphrase protection
- Nested JSON flattening for ENV export

### 🗂️ Organization
- Namespace-based secret organization
- Vault storage compaction
- Hard reset with backup

### 🤝 P2P Sharing (LAN)
- Secrets/Files/Scratchpad sharing on LAN
- End-to-end encrypted P2P (ECDH + AES-GCM)
- Peer discovery (mDNS + UDP)
- P2P user alias for discovery
- Duplicate resolution on receive
- Share notifications

---

## Team - $149/device/year (min 25 devices)

**Best for:** Growing organizations with centralized secret management needs

### Storage
- 10 GB encrypted vault storage

### Features
Everything from Professional plus:

### 🔐 Access Control
- ACL-based secret grants/revokes
- Share request/approval workflows
- Share link generation with expiry
- Principal-based access control
- Role-based access control (admin, write, read)

### 🔄 Advanced Rotation
- Dual-key overlap windows
- Automated rotation execution
- Rotation notification hooks
- Bundle expiry windows

### 💾 Advanced Backup
- Automated backup scheduling
- Backup replication

### 🌐 HTTP API Server (Pro Mode)
- HTTP/JSON API server with TLS
- Secret CRUD endpoints
- File upload/download endpoints
- Image rendering endpoint
- Backup/restore endpoints
- `/healthz` liveness probe
- `/readyz` readiness probe
- Rate limiting middleware
- CSRF protection
- Security headers (X-Frame-Options, CSP)

### 👥 User Management
- User management (create, list, update, delete)
- CSV/JSON/SQLite-backed user authentication
- Session management with JWT
- Session introspection & revocation
- API key management per user
- Scoped API keys (fine-grained permissions)
- API key expiration

### 📊 Enhanced Observability
- `/metrics` Prometheus endpoint
- HTTP request metrics
- Vault operation metrics
- User operation metrics

---

## Startup - $249/device/year (min 50 devices)

**Best for:** Fast-growing companies with security-first culture

### Storage
- Unlimited encrypted vault storage

### Features
Everything from Team plus:

### 🏢 Multi-Tenant Support
- Tenant management (create, list, delete)
- Per-tenant admin keys
- Tenant-scoped secret storage
- Cross-tenant isolation
- Tenant-scoped exports

### 🔐 Enterprise Security
- Threat model handlers (10 vectors)
- Mutual TLS (mTLS) support
- IAM policy engine
- Security levels (Basic, Hardened, Isolated, Maximum)

### 🔗 Secret Engines
- Transit encryption/decryption endpoints
- Transit data key generation
- Dynamic database credentials (Postgres, MySQL)
- Dynamic cloud tokens (AWS, Azure, GCP)
- Response wrapping/unwrapping
- KV secret rollback endpoint

### 📋 Data Retention
- Data retention policies
- Retention enforcement (4 modes: warn, soft_delete, hard_delete, crypto_erase)
- Cryptographic erasure
- Retention violation checking

### 🐳 Secure Sandbox (Linux)
- Config file substitution with secret injection
- Command execution with injected secrets
- Sandbox command with environment enrichment
- Format-aware secret injection (ENV, JSON, YAML)
- Working directory isolation

---

## Enterprise - Contact Sales

**Best for:** Organizations with strict compliance and governance requirements

### Storage
- Unlimited encrypted vault storage
- Custom SLAs
- Dedicated support
- On-premises deployment assistance

### Features
Everything from Startup plus:

### 🐳 Advanced Container Runtime (Linux)
- Namespace container isolation
- PID, Mount, Network, IPC namespaces
- Cgroups resource limits (memory, CPU)
- Seccomp system call filtering
- Capability dropping & no-new-privs
- Secret injection into containers
- Security breach detection & auto-shutdown
- Landlock filesystem sandboxing
- Core dump prevention
- Memory locking (prevents swap)
- Ptrace blocking

### 📋 Compliance & Governance
- SOC 2 Type II Compliance
- PCI DSS v4.0 Compliance
- HIPAA Security Rule Compliance
- GDPR Compliance
- ISO 27001/27002 Compliance
- NIST Cybersecurity Framework 2.0
- Compliance assessment & gap analysis
- Compliance reporting (JSON/text)
- Compliance status monitoring

### 🔐 FIPS 140-2/140-3 Compliance Mode
- FIPS-validated cryptographic algorithms
- PBKDF2 key derivation (FIPS alternative)
- FIPS Power-on self-test (POST)
- Algorithm validation
- Key size validation
- Curve validation for EC operations
- Violation tracking for audit

### 🏷️ Data Classification
- Data classification (7 levels: public → restricted)
- Auto-classification (12+ pattern rules)
- Manual data classification
- Data inventory (GDPR Article 30)
- Classification reporting

### 🚨 Breach Detection & Reporting
- Breach incident tracking
- Breach severity levels
- Breach notification (72hr GDPR, 60d HIPAA)
- Notification recipient tracking
- Breach timeline reporting

### 👥 Access Review
- Access review workflow (quarterly/annual)
- Access matrix export (CSV/JSON)
- Review approval/revocation with justification
- Access review completion tracking
- Reviewer assignment

### 🔍 Advanced Audit
- Enhanced audit logs with full context
- Audit log export
- Compliance-specific audit trails

### 🔬 Security Audit & Pen Testing
- Container security audit tools
- Container penetration testing tools

### 🔑 HSM Integration
- Hardware Security Module integration (PKCS#11)

---

## Runtime Modes

| Mode | Description |
|------|-------------|
| **Standard** (default) | Local CLI experience with all offline features. HTTP server disabled for minimal attack surface. |
| **Pro** (Team+) | Unlocks HTTP/JSON API, observability endpoints, and web assets for service deployment. |

Switch modes with `-mode=pro` or `-mode=standard` CLI flag.

---

## Feature Comparison Matrix

| Category | Personal | Solo | Professional | Team | Startup | Enterprise |
|----------|:--------:|:----:|:------------:|:----:|:-------:|:----------:|
| **Price** | $19/dev/yr | $49/dev/yr | $99/dev/yr | $149/dev/yr | $249/dev/yr | Custom |
| **Min Devices** | 1 | 3 | 10 | 25 | 50 | — |
| **Min ACV** | $19 | $147 | $990 | $3,725 | $12,450 | Custom |
| **Storage** | 500 MB | 2 GB | 5 GB | 10 GB | Unlimited | Unlimited |
| **Secret Expiration** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **2FA/Passkey** | — | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Scratchpads** | — | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Audit Logs** | — | ✅ | ✅ | ✅ | ✅ | ✅ |
| **Templates & Rotation** | — | — | ✅ | ✅ | ✅ | ✅ |
| **P2P Sharing** | — | — | ✅ | ✅ | ✅ | ✅ |
| **Bundle Export** | — | — | ✅ | ✅ | ✅ | ✅ |
| **Access Control (ACL)** | — | — | — | ✅ | ✅ | ✅ |
| **HTTP API Server** | — | — | — | ✅ | ✅ | ✅ |
| **User Management** | — | — | — | ✅ | ✅ | ✅ |
| **Multi-Tenant** | — | — | — | — | ✅ | ✅ |
| **Secret Engines** | — | — | — | — | ✅ | ✅ |
| **Data Retention** | — | — | — | — | ✅ | ✅ |
| **Secure Sandbox** | — | — | — | — | ✅ | ✅ |
| **Container Runtime** | — | — | — | — | — | ✅ |
| **Compliance Mgmt** | — | — | — | — | — | ✅ |
| **FIPS Mode** | — | — | — | — | — | ✅ |
| **Data Classification** | — | — | — | — | — | ✅ |
| **Access Review** | — | — | — | — | — | ✅ |
| **Breach Mgmt** | — | — | — | — | — | ✅ |
| **HSM Integration** | — | — | — | — | — | ✅ |

---

## Upgrade Triggers

| When you need... | Upgrade to |
|------------------|------------|
| 2FA, Passkeys, or Scratchpads | **Solo** |
| Templates, Rotation, or Team Sharing | **Professional** |
| HTTP API, User Management, or ACLs | **Team** |
| Multi-Tenant, Secret Engines, or Retention | **Startup** |
| Compliance, FIPS, Classification, or HSM | **Enterprise** |

---

## Security Architecture

1. **Encryption at Rest** - All data encrypted with AES-256-GCM
2. **Key Derivation** - Argon2id with NIST-compliant parameters (PBKDF2 in FIPS mode)
3. **Device Binding** - Hardware fingerprint prevents vault copying
4. **Audit Trail** - HMAC-signed logs with hash chains for tamper detection
5. **Zero Trust** - No cloud dependencies, fully offline capable
6. **Shamir Shares** - Distributed master key for disaster recovery (Solo+)

---

## Volume Discounts

| Devices | Discount |
|---------|----------|
| 50-99 | 10% off |
| 100-249 | 15% off |
| 250-499 | 20% off |
| 500+ | Contact sales |

---

## Why This Pricing?

### vs. Cloud-Based Solutions
- **No per-user fees** - Pay per device, not per team member
- **No recurring API costs** - Unlimited operations included
- **No data egress fees** - Everything stays local
- **No vendor lock-in** - Your data, your control

### vs. Self-Hosted Solutions
- **Zero infrastructure costs** - No servers to maintain
- **No DevOps overhead** - Works out of the box
- **Simpler pricing** - No complex licensing tiers

### Total Cost of Ownership (Example)
| Scenario | Secretr (Team) | Cloud-Based (Typical) | Self-Hosted Enterprise |
|----------|----------------|----------------------|------------------------|
| 25 developers, 1 year | $3,725 | $5,000-8,000 | ~$15,000-20,000+ |
| 50 developers, 1 year | $6,705* | $10,000-15,000 | ~$30,000-40,000+ |
| 100 developers, 1 year | $12,665* | $20,000-30,000 | ~$60,000-80,000+ |

*With volume discount applied
