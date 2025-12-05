# Complete Entitlement Feature Scopes for Secretr

This document defines the complete entitlement structure covering all CLI commands, API endpoints, and GUI features in the Secretr project.

## Plan Overview

| Plan | Price | Min Devices | Storage | Key Features |
|------|-------|-------------|---------|--------------|
| **Trial** | $0 (7 days) | 1 | Unlimited | All features unlocked |
| **Personal** | $25/device/yr | 1 | 1 GB | Core secrets, SSH, generators, GUI |
| **Solo** | $60/device/yr | 2 | 5 GB | + 2FA, P2P sharing, audit, versioning |
| **Team** | $90/device/yr | 5 | 25 GB | + Scratchpads, templates, rotation, bundles |
| **Business** | $180/device/yr | 15 | Unlimited | + API server, user mgmt, ACL, multi-tenant, sandbox |
| **Enterprise** | Custom | 50+ | Unlimited | + Compliance, FIPS, containers, HSM |

## License Data Structure

```json
{
  "entitlements": {
    "product_id": "prod_secretr_001",
    "product_slug": "secretr",
    "plan_id": "plan_team_001",
    "plan_slug": "team",
    "features": {
      "cli": { ... },
      "gui": { ... },
      "api": { ... }
    }
  }
}
```

---

## 1. CLI Feature Scopes

The `cli` feature controls command-line interface access.

### Feature Definition

```json
{
  "feature_id": "feat_cli_001",
  "feature_slug": "cli",
  "category": "interface",
  "enabled": true,
  "scopes": { ... }
}
```

### CLI Scopes (Commands)

#### Basic Operations
```json
{
  "get": { "scope_id": "cli_s001", "scope_slug": "get", "permission": "allow" },
  "set": { "scope_id": "cli_s002", "scope_slug": "set", "permission": "allow" },
  "list": { "scope_id": "cli_s003", "scope_slug": "list", "permission": "allow" },
  "delete": { "scope_id": "cli_s004", "scope_slug": "delete", "permission": "allow" },
  "copy": { "scope_id": "cli_s005", "scope_slug": "copy", "permission": "allow" },
  "secret-password": { "scope_id": "cli_s006", "scope_slug": "secret-password", "permission": "allow" }
}
```

#### SSH Management
```json
{
  "ssh": { "scope_id": "cli_s007", "scope_slug": "ssh", "permission": "allow" },
  "ssh-key": { "scope_id": "cli_s008", "scope_slug": "ssh-key", "permission": "allow" },
  "ssh-profile": { "scope_id": "cli_s009", "scope_slug": "ssh-profile", "permission": "allow" }
}
```

#### File Management
```json
{
  "files": { "scope_id": "cli_s010", "scope_slug": "files", "permission": "allow" }
}
```

#### Sharing & Collaboration
```json
{
  "share": { "scope_id": "cli_s011", "scope_slug": "share", "permission": "allow", "min_plan": "business" },
  "p2p-share": { "scope_id": "cli_s012", "scope_slug": "p2p-share", "permission": "allow", "min_plan": "solo" },
  "p2p": { "scope_id": "cli_s013", "scope_slug": "p2p", "permission": "allow", "min_plan": "solo" }
}
```
*Note: P2P sharing requires Solo plan or higher. ACL-based sharing requires Business plan or higher*

#### Container Security
```json
{
  "container": { "scope_id": "cli_s014", "scope_slug": "container", "permission": "deny", "min_plan": "enterprise" }
}
```
*Note: Container operations restricted to Enterprise plan*

#### Backup & Recovery
```json
{
  "backup": { "scope_id": "cli_s015", "scope_slug": "backup", "permission": "allow" },
  "export": { "scope_id": "cli_s016", "scope_slug": "export", "permission": "allow" },
  "import": { "scope_id": "cli_s017", "scope_slug": "import", "permission": "allow" }
}
```

#### Generators
```json
{
  "gen-jwt": { "scope_id": "cli_s018", "scope_slug": "gen-jwt", "permission": "allow" },
  "gen-apikey": { "scope_id": "cli_s019", "scope_slug": "gen-apikey", "permission": "allow" },
  "gen-keypair": { "scope_id": "cli_s020", "scope_slug": "gen-keypair", "permission": "allow" },
  "gen-symkey": { "scope_id": "cli_s021", "scope_slug": "gen-symkey", "permission": "allow" },
  "dynamic": { "scope_id": "cli_s022", "scope_slug": "dynamic", "permission": "allow" }
}
```

#### Templates
```json
{
  "template": { "scope_id": "cli_s023", "scope_slug": "template", "permission": "allow", "min_plan": "team" }
}
```
*Note: Templates require Team plan or higher*

#### Secret Rotation
```json
{
  "rotate": { "scope_id": "cli_s024", "scope_slug": "rotate", "permission": "allow", "min_plan": "team" }
}
```
*Note: Rotation requires Team plan or higher*

#### Tenant Management
```json
{
  "tenant": { "scope_id": "cli_s025", "scope_slug": "tenant", "permission": "deny", "min_plan": "business" }
}
```
*Note: Multi-tenancy requires Business plan or higher*

#### Import/Export Advanced
```json
{
  "from-file": { "scope_id": "cli_s026", "scope_slug": "from-file", "permission": "allow" },
  "to-file": { "scope_id": "cli_s027", "scope_slug": "to-file", "permission": "allow" },
  "pull": { "scope_id": "cli_s028", "scope_slug": "pull", "permission": "allow" },
  "push": { "scope_id": "cli_s029", "scope_slug": "push", "permission": "allow" },
  "server-export": { "scope_id": "cli_s030", "scope_slug": "server-export", "permission": "allow" }
}
```

#### Scratchpad
```json
{
  "scratchpad": { "scope_id": "cli_s031", "scope_slug": "scratchpad", "permission": "allow", "min_plan": "team" }
}
```
*Note: Scratchpads require Team plan or higher*

#### Environment
```json
{
  "printenv": { "scope_id": "cli_s032", "scope_slug": "printenv", "permission": "allow" },
  "env": { "scope_id": "cli_s033", "scope_slug": "env", "permission": "allow" },
  "enrich": { "scope_id": "cli_s034", "scope_slug": "enrich", "permission": "allow" }
}
```

#### Cryptography
```json
{
  "certificate": { "scope_id": "cli_s035", "scope_slug": "certificate", "permission": "allow" },
  "sign": { "scope_id": "cli_s036", "scope_slug": "sign", "permission": "allow" },
  "verify": { "scope_id": "cli_s037", "scope_slug": "verify", "permission": "allow" },
  "hash": { "scope_id": "cli_s038", "scope_slug": "hash", "permission": "allow" }
}
```

#### Versioning
```json
{
  "listkv": { "scope_id": "cli_s039", "scope_slug": "listkv", "permission": "allow", "min_plan": "solo" },
  "rollbackkv": { "scope_id": "cli_s040", "scope_slug": "rollbackkv", "permission": "allow", "min_plan": "solo" },
  "vcs": { "scope_id": "cli_s072", "scope_slug": "vcs", "permission": "allow", "min_plan": "solo" }
}
```
*Note: Version control features require Solo plan or higher*

#### Security Sandbox
```json
{
  "sandbox": { "scope_id": "cli_s041", "scope_slug": "sandbox", "permission": "deny", "min_plan": "business" },
  "secure-sandbox": { "scope_id": "cli_s042", "scope_slug": "secure-sandbox", "permission": "deny", "min_plan": "business" },
  "ssb": { "scope_id": "cli_s043", "scope_slug": "ssb", "permission": "deny", "min_plan": "business" }
}
```
*Note: Sandbox features require Business plan or higher*

#### Security Policy
```json
{
  "security-policy": { "scope_id": "cli_s044", "scope_slug": "security-policy", "permission": "allow" },
  "sec-policy": { "scope_id": "cli_s045", "scope_slug": "sec-policy", "permission": "allow" }
}
```

#### Vault Security
```json
{
  "vault-security": { "scope_id": "cli_s046", "scope_slug": "vault-security", "permission": "allow" },
  "vsec": { "scope_id": "cli_s047", "scope_slug": "vsec", "permission": "allow" }
}
```

#### Observability
```json
{
  "observability": { "scope_id": "cli_s048", "scope_slug": "observability", "permission": "allow" },
  "obs": { "scope_id": "cli_s049", "scope_slug": "obs", "permission": "allow" }
}
```

#### Interactive Log Viewers
```json
{
  "view": { "scope_id": "cli_s090", "scope_slug": "view", "permission": "allow", "min_plan": "team" },
  "view_audit-logs": { "scope_id": "cli_s091", "scope_slug": "view_audit-logs", "permission": "allow", "min_plan": "team" },
  "view_access-logs": { "scope_id": "cli_s092", "scope_slug": "view_access-logs", "permission": "allow", "min_plan": "team" }
}
```
*Note: Interactive log viewers require Team plan or higher due to the enhanced browser UI.*

#### FIPS Compliance
```json
{
  "fips": { "scope_id": "cli_s050", "scope_slug": "fips", "permission": "deny" },
  "fips-140": { "scope_id": "cli_s051", "scope_slug": "fips-140", "permission": "deny" }
}
```
*Note: FIPS mode typically restricted to enterprise plans with compliance requirements*

#### Compliance Frameworks
```json
{
  "compliance": { "scope_id": "cli_s052", "scope_slug": "compliance", "permission": "deny" },
  "comp": { "scope_id": "cli_s053", "scope_slug": "comp", "permission": "deny" }
}
```
*Note: Compliance features typically restricted to enterprise plans*

#### Data Classification
```json
{
  "classify": { "scope_id": "cli_s054", "scope_slug": "classify", "permission": "deny" },
  "data-classification": { "scope_id": "cli_s055", "scope_slug": "data-classification", "permission": "deny" },
  "dc": { "scope_id": "cli_s056", "scope_slug": "dc", "permission": "deny" }
}
```

#### Data Retention
```json
{
  "retention": { "scope_id": "cli_s057", "scope_slug": "retention", "permission": "deny" },
  "ret": { "scope_id": "cli_s058", "scope_slug": "ret", "permission": "deny" }
}
```

#### Breach Management
```json
{
  "breach": { "scope_id": "cli_s059", "scope_slug": "breach", "permission": "deny" },
  "breach-notification": { "scope_id": "cli_s060", "scope_slug": "breach-notification", "permission": "deny" }
}
```

#### Access Review
```json
{
  "access-review": { "scope_id": "cli_s061", "scope_slug": "access-review", "permission": "deny" },
  "ar": { "scope_id": "cli_s062", "scope_slug": "ar", "permission": "deny" },
  "access-reviews": { "scope_id": "cli_s063", "scope_slug": "access-reviews", "permission": "deny" }
}
```

#### Authentication
```json
{
  "enable-2fa": { "scope_id": "cli_s064", "scope_slug": "enable-2fa", "permission": "allow" },
  "disable-2fa": { "scope_id": "cli_s065", "scope_slug": "disable-2fa", "permission": "allow" },
  "enable-passkey": { "scope_id": "cli_s066", "scope_slug": "enable-passkey", "permission": "allow" },
  "disable-passkey": { "scope_id": "cli_s067", "scope_slug": "disable-passkey", "permission": "allow" },
  "enable-share-prompts": { "scope_id": "cli_s068", "scope_slug": "enable-share-prompts", "permission": "allow" }
}
```

#### System Commands
```json
{
  "server": { "scope_id": "cli_s069", "scope_slug": "server", "permission": "deny", "min_plan": "team" },
  "kds": { "scope_id": "cli_s070", "scope_slug": "kds", "permission": "deny", "min_plan": "team" },
  "server-config": { "scope_id": "cli_s071", "scope_slug": "server-config", "permission": "deny", "min_plan": "team" }
}
```
*Note: Server mode and server-config require Team plan or higher*

#### Vault Storage & Compaction
```json
{
  "compact": { "scope_id": "cli_s073", "scope_slug": "compact", "permission": "allow", "min_plan": "professional" },
  "vault-compact": { "scope_id": "cli_s074", "scope_slug": "vault-compact", "permission": "allow", "min_plan": "professional" }
}
```
*Note: Vault compaction requires Professional plan or higher*

#### Shamir Secret Sharing
```json
{
  "shamir": { "scope_id": "cli_s075", "scope_slug": "shamir", "permission": "allow", "min_plan": "solo" },
  "shamir-split": { "scope_id": "cli_s076", "scope_slug": "shamir-split", "permission": "allow", "min_plan": "solo" },
  "shamir-combine": { "scope_id": "cli_s077", "scope_slug": "shamir-combine", "permission": "allow", "min_plan": "solo" }
}
```
*Note: Shamir secret sharing requires Solo plan or higher*

#### Audit Logs
```json
{
  "audit": { "scope_id": "cli_s078", "scope_slug": "audit", "permission": "allow", "min_plan": "solo" },
  "audit-log": { "scope_id": "cli_s079", "scope_slug": "audit-log", "permission": "allow", "min_plan": "solo" }
}
```
*Note: Audit logging requires Solo plan or higher*

#### Config Injection
```json
{
  "inject": { "scope_id": "cli_s080", "scope_slug": "inject", "permission": "allow", "min_plan": "startup" },
  "config-inject": { "scope_id": "cli_s081", "scope_slug": "config-inject", "permission": "allow", "min_plan": "startup" }
}
```
*Note: Config injection requires Startup plan or higher*

#### Transfer System
```json
{
  "transfer": { "scope_id": "cli_s084", "scope_slug": "transfer", "permission": "allow", "min_plan": "business" },
  "transfer-devices": { "scope_id": "cli_s085", "scope_slug": "transfer-devices", "permission": "allow", "min_plan": "business" },
  "transfer-devices-list": { "scope_id": "cli_s086", "scope_slug": "transfer-devices-list", "permission": "allow", "min_plan": "business" },
  "transfer-devices-add": { "scope_id": "cli_s087", "scope_slug": "transfer-devices-add", "permission": "allow", "min_plan": "business" },
  "transfer-devices-remove": { "scope_id": "cli_s088", "scope_slug": "transfer-devices-remove", "permission": "allow", "min_plan": "business" },
  "transfer-devices-verify": { "scope_id": "cli_s089", "scope_slug": "transfer-devices-verify", "permission": "allow", "min_plan": "business" },
  "transfer-send": { "scope_id": "cli_s090", "scope_slug": "transfer-send", "permission": "allow", "min_plan": "business" },
  "transfer-upload": { "scope_id": "cli_s091", "scope_slug": "transfer-upload", "permission": "allow", "min_plan": "business" },
  "transfer-download": { "scope_id": "cli_s092", "scope_slug": "transfer-download", "permission": "allow", "min_plan": "business" },
  "transfer-bundle": { "scope_id": "cli_s093", "scope_slug": "transfer-bundle", "permission": "allow", "min_plan": "business" },
  "transfer-bundle-create": { "scope_id": "cli_s094", "scope_slug": "transfer-bundle-create", "permission": "allow", "min_plan": "business" },
  "transfer-bundle-import": { "scope_id": "cli_s095", "scope_slug": "transfer-bundle-import", "permission": "allow", "min_plan": "business" },
  "transfer-bundle-qr": { "scope_id": "cli_s096", "scope_slug": "transfer-bundle-qr", "permission": "allow", "min_plan": "business" },
  "transfer-schedule": { "scope_id": "cli_s097", "scope_slug": "transfer-schedule", "permission": "allow", "min_plan": "business" },
  "transfer-schedule-list": { "scope_id": "cli_s098", "scope_slug": "transfer-schedule-list", "permission": "allow", "min_plan": "business" },
  "transfer-schedule-add": { "scope_id": "cli_s099", "scope_slug": "transfer-schedule-add", "permission": "allow", "min_plan": "business" },
  "transfer-schedule-pause": { "scope_id": "cli_s100", "scope_slug": "transfer-schedule-pause", "permission": "allow", "min_plan": "business" },
  "transfer-schedule-resume": { "scope_id": "cli_s101", "scope_slug": "transfer-schedule-resume", "permission": "allow", "min_plan": "business" },
  "transfer-schedule-run": { "scope_id": "cli_s102", "scope_slug": "transfer-schedule-run", "permission": "allow", "min_plan": "business" }
}
```
*Note: Transfer system requires Business plan or higher*

#### Container Security Audit
```json
{
  "container-audit": { "scope_id": "cli_s103", "scope_slug": "container-audit", "permission": "deny", "min_plan": "enterprise" },
  "csa": { "scope_id": "cli_s104", "scope_slug": "csa", "permission": "deny", "min_plan": "enterprise" }
}
```
*Note: Container security audit requires Enterprise plan*

---

## 2. GUI Feature Scopes

The `gui` feature controls desktop GUI application access.

### Feature Definition

```json
{
  "feature_id": "feat_gui_001",
  "feature_slug": "gui",
  "category": "interface",
  "enabled": true,
  "scopes": { ... }
}
```

### GUI Scopes (Actions & Views)

#### CRUD Operations
```json
{
  "view": { "scope_id": "gui_s001", "scope_slug": "view", "permission": "allow" },
  "list": { "scope_id": "gui_s002", "scope_slug": "list", "permission": "allow" },
  "create": { "scope_id": "gui_s003", "scope_slug": "create", "permission": "allow" },
  "update": { "scope_id": "gui_s004", "scope_slug": "update", "permission": "allow" },
  "delete": { "scope_id": "gui_s005", "scope_slug": "delete", "permission": "allow" },
  "edit": { "scope_id": "gui_s006", "scope_slug": "edit", "permission": "allow" }
}
```

#### Secret Management Views
```json
{
  "secret_manager": { "scope_id": "gui_s007", "scope_slug": "secret_manager", "permission": "allow" },
  "secret_search": { "scope_id": "gui_s008", "scope_slug": "secret_search", "permission": "allow" },
  "secret_filter": { "scope_id": "gui_s009", "scope_slug": "secret_filter", "permission": "allow" },
  "password_protection": { "scope_id": "gui_s010", "scope_slug": "password_protection", "permission": "allow" }
}
```

#### File Management Views
```json
{
  "file_manager": { "scope_id": "gui_s011", "scope_slug": "file_manager", "permission": "allow" },
  "file_upload": { "scope_id": "gui_s012", "scope_slug": "file_upload", "permission": "allow" },
  "file_download": { "scope_id": "gui_s013", "scope_slug": "file_download", "permission": "allow" }
}
```

#### Generator Views
```json
{
  "password_generator": { "scope_id": "gui_s014", "scope_slug": "password_generator", "permission": "allow" },
  "ssh_key_generator": { "scope_id": "gui_s015", "scope_slug": "ssh_key_generator", "permission": "allow" },
  "certificate_generator": { "scope_id": "gui_s016", "scope_slug": "certificate_generator", "permission": "allow" },
  "hash_generator": { "scope_id": "gui_s017", "scope_slug": "hash_generator", "permission": "allow" }
}
```

#### SSH Management Views
```json
{
  "ssh_profiles": { "scope_id": "gui_s018", "scope_slug": "ssh_profiles", "permission": "allow" },
  "ssh_terminal": { "scope_id": "gui_s019", "scope_slug": "ssh_terminal", "permission": "allow" },
  "ssh_import": { "scope_id": "gui_s020", "scope_slug": "ssh_import", "permission": "allow" }
}
```

#### P2P Sharing Views
```json
{
  "p2p_share": { "scope_id": "gui_s021", "scope_slug": "p2p_share", "permission": "allow" },
  "p2p_discover": { "scope_id": "gui_s022", "scope_slug": "p2p_discover", "permission": "allow" },
  "p2p_receive": { "scope_id": "gui_s023", "scope_slug": "p2p_receive", "permission": "allow" }
}
```

#### Cryptographic Operations Views
```json
{
  "sign_data": { "scope_id": "gui_s024", "scope_slug": "sign_data", "permission": "allow" },
  "verify_signature": { "scope_id": "gui_s025", "scope_slug": "verify_signature", "permission": "allow" }
}
```

#### Management Views
```json
{
  "templates": { "scope_id": "gui_s026", "scope_slug": "templates", "permission": "allow" },
  "rotation": { "scope_id": "gui_s027", "scope_slug": "rotation", "permission": "allow" },
  "backup_restore": { "scope_id": "gui_s028", "scope_slug": "backup_restore", "permission": "allow" },
  "scratchpad": { "scope_id": "gui_s029", "scope_slug": "scratchpad", "permission": "allow" }
}
```

#### Compliance Views
```json
{
  "compliance_dashboard": { "scope_id": "gui_s030", "scope_slug": "compliance_dashboard", "permission": "deny" },
  "data_classification": { "scope_id": "gui_s031", "scope_slug": "data_classification", "permission": "deny" },
  "data_retention": { "scope_id": "gui_s032", "scope_slug": "data_retention", "permission": "deny" },
  "breach_notification": { "scope_id": "gui_s033", "scope_slug": "breach_notification", "permission": "deny" },
  "access_reviews": { "scope_id": "gui_s034", "scope_slug": "access_reviews", "permission": "deny" },
  "fips_compliance": { "scope_id": "gui_s035", "scope_slug": "fips_compliance", "permission": "deny" }
}
```

#### Transfer System Views
```json
{
  "transfer_dashboard": { "scope_id": "gui_s038", "scope_slug": "transfer_dashboard", "permission": "allow", "min_plan": "business" },
  "transfer_devices": { "scope_id": "gui_s039", "scope_slug": "transfer_devices", "permission": "allow", "min_plan": "business" },
  "transfer_devices_manage": { "scope_id": "gui_s040", "scope_slug": "transfer_devices_manage", "permission": "allow", "min_plan": "business" },
  "transfer_send": { "scope_id": "gui_s041", "scope_slug": "transfer_send", "permission": "allow", "min_plan": "business" },
  "transfer_receive": { "scope_id": "gui_s042", "scope_slug": "transfer_receive", "permission": "allow", "min_plan": "business" },
  "transfer_cloud": { "scope_id": "gui_s043", "scope_slug": "transfer_cloud", "permission": "allow", "min_plan": "business" },
  "transfer_cloud_upload": { "scope_id": "gui_s044", "scope_slug": "transfer_cloud_upload", "permission": "allow", "min_plan": "business" },
  "transfer_cloud_download": { "scope_id": "gui_s045", "scope_slug": "transfer_cloud_download", "permission": "allow", "min_plan": "business" },
  "transfer_airgap": { "scope_id": "gui_s046", "scope_slug": "transfer_airgap", "permission": "allow", "min_plan": "business" },
  "transfer_bundle_create": { "scope_id": "gui_s047", "scope_slug": "transfer_bundle_create", "permission": "allow", "min_plan": "business" },
  "transfer_bundle_import": { "scope_id": "gui_s048", "scope_slug": "transfer_bundle_import", "permission": "allow", "min_plan": "business" },
  "transfer_bundle_qr": { "scope_id": "gui_s049", "scope_slug": "transfer_bundle_qr", "permission": "allow", "min_plan": "business" },
  "transfer_schedule": { "scope_id": "gui_s050", "scope_slug": "transfer_schedule", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_manage": { "scope_id": "gui_s051", "scope_slug": "transfer_schedule_manage", "permission": "allow", "min_plan": "business" },
  "transfer_history": { "scope_id": "gui_s052", "scope_slug": "transfer_history", "permission": "allow", "min_plan": "business" },
  "transfer_audit": { "scope_id": "gui_s053", "scope_slug": "transfer_audit", "permission": "allow", "min_plan": "business" }
}
```
*Note: Transfer system views require Business plan or higher*

#### Security Views
```json
{
  "two_factor_auth": { "scope_id": "gui_s054", "scope_slug": "two_factor_auth", "permission": "allow" },
  "vault_lock": { "scope_id": "gui_s055", "scope_slug": "vault_lock", "permission": "allow" }
}
```

---

## 3. API Feature Scopes

The `api` feature controls HTTP API access.

### Feature Definition

```json
{
  "feature_id": "feat_api_001",
  "feature_slug": "api",
  "category": "integration",
  "enabled": true,
  "scopes": { ... }
}
```

### API Scopes (Endpoints)

#### Setup & Configuration
```json
{
  "setup_check": { "scope_id": "api_s001", "scope_slug": "setup_check", "permission": "allow" },
  "setup_complete": { "scope_id": "api_s002", "scope_slug": "setup_complete", "permission": "allow" },
  "admin_regenerate_key": { "scope_id": "api_s003", "scope_slug": "admin_regenerate_key", "permission": "allow" }
}
```

#### Authentication
```json
{
  "auth_login": { "scope_id": "api_s004", "scope_slug": "auth_login", "permission": "allow" },
  "auth_sessions_list": { "scope_id": "api_s005", "scope_slug": "auth_sessions_list", "permission": "allow" },
  "auth_sessions_revoke": { "scope_id": "api_s006", "scope_slug": "auth_sessions_revoke", "permission": "allow" }
}
```

#### Two-Factor Authentication
```json
{
  "2fa_status": { "scope_id": "api_s007", "scope_slug": "2fa_status", "permission": "allow" },
  "2fa_setup_start": { "scope_id": "api_s008", "scope_slug": "2fa_setup_start", "permission": "allow" },
  "2fa_setup_verify": { "scope_id": "api_s009", "scope_slug": "2fa_setup_verify", "permission": "allow" },
  "2fa_verify": { "scope_id": "api_s010", "scope_slug": "2fa_verify", "permission": "allow" },
  "2fa_disable": { "scope_id": "api_s011", "scope_slug": "2fa_disable", "permission": "allow" },
  "2fa_backup_code": { "scope_id": "api_s012", "scope_slug": "2fa_backup_code", "permission": "allow" }
}
```

#### Secrets Management
```json
{
  "secrets_read": { "scope_id": "api_s013", "scope_slug": "secrets_read", "permission": "allow" },
  "secrets_write": { "scope_id": "api_s014", "scope_slug": "secrets_write", "permission": "allow" },
  "secrets_delete": { "scope_id": "api_s015", "scope_slug": "secrets_delete", "permission": "allow" },
  "secrets_list": { "scope_id": "api_s016", "scope_slug": "secrets_list", "permission": "allow" }
}
```

#### KV Versioning
```json
{
  "kv_versions_list": { "scope_id": "api_s017", "scope_slug": "kv_versions_list", "permission": "allow" },
  "kv_rollback": { "scope_id": "api_s018", "scope_slug": "kv_rollback", "permission": "allow" }
}
```

#### Transit Engine (Encryption/Decryption)
```json
{
  "transit_encrypt": { "scope_id": "api_s019", "scope_slug": "transit_encrypt", "permission": "allow" },
  "transit_decrypt": { "scope_id": "api_s020", "scope_slug": "transit_decrypt", "permission": "allow" }
}
```

#### Dynamic Engines
```json
{
  "dynamic_database": { "scope_id": "api_s021", "scope_slug": "dynamic_database", "permission": "allow" },
  "dynamic_cloud": { "scope_id": "api_s022", "scope_slug": "dynamic_cloud", "permission": "allow" },
  "dynamic_verify": { "scope_id": "api_s023", "scope_slug": "dynamic_verify", "permission": "allow" }
}
```

#### Response Wrapping
```json
{
  "wrap_response": { "scope_id": "api_s024", "scope_slug": "wrap_response", "permission": "allow" },
  "unwrap_response": { "scope_id": "api_s025", "scope_slug": "unwrap_response", "permission": "allow" }
}
```

#### File Management
```json
{
  "files_list": { "scope_id": "api_s026", "scope_slug": "files_list", "permission": "allow" },
  "files_upload": { "scope_id": "api_s027", "scope_slug": "files_upload", "permission": "allow" },
  "files_download": { "scope_id": "api_s028", "scope_slug": "files_download", "permission": "allow" },
  "files_delete": { "scope_id": "api_s029", "scope_slug": "files_delete", "permission": "allow" },
  "files_render": { "scope_id": "api_s030", "scope_slug": "files_render", "permission": "allow" }
}
```

#### SSH Management
```json
{
  "ssh_keys_get": { "scope_id": "api_s031", "scope_slug": "ssh_keys_get", "permission": "allow" },
  "ssh_keys_create": { "scope_id": "api_s032", "scope_slug": "ssh_keys_create", "permission": "allow" },
  "ssh_keys_delete": { "scope_id": "api_s033", "scope_slug": "ssh_keys_delete", "permission": "allow" },
  "ssh_keys_list": { "scope_id": "api_s034", "scope_slug": "ssh_keys_list", "permission": "allow" },
  "ssh_profiles_get": { "scope_id": "api_s035", "scope_slug": "ssh_profiles_get", "permission": "allow" },
  "ssh_profiles_create": { "scope_id": "api_s036", "scope_slug": "ssh_profiles_create", "permission": "allow" },
  "ssh_profiles_delete": { "scope_id": "api_s037", "scope_slug": "ssh_profiles_delete", "permission": "allow" },
  "ssh_profiles_list": { "scope_id": "api_s038", "scope_slug": "ssh_profiles_list", "permission": "allow" }
}
```

#### Certificate Management
```json
{
  "certificate_generate": { "scope_id": "api_s039", "scope_slug": "certificate_generate", "permission": "allow" }
}
```

#### Key Generation
```json
{
  "generate_jwt": { "scope_id": "api_s040", "scope_slug": "generate_jwt", "permission": "allow" },
  "generate_apikey": { "scope_id": "api_s041", "scope_slug": "generate_apikey", "permission": "allow" },
  "generate_keypair": { "scope_id": "api_s042", "scope_slug": "generate_keypair", "permission": "allow" },
  "generate_symkey": { "scope_id": "api_s043", "scope_slug": "generate_symkey", "permission": "allow" }
}
```

#### Managed Keys
```json
{
  "managed_keys_list": { "scope_id": "api_s044", "scope_slug": "managed_keys_list", "permission": "allow" },
  "managed_keys_create": { "scope_id": "api_s045", "scope_slug": "managed_keys_create", "permission": "allow" },
  "managed_keys_rotate": { "scope_id": "api_s046", "scope_slug": "managed_keys_rotate", "permission": "allow" },
  "managed_keys_archive": { "scope_id": "api_s047", "scope_slug": "managed_keys_archive", "permission": "allow" },
  "managed_keys_destroy": { "scope_id": "api_s048", "scope_slug": "managed_keys_destroy", "permission": "allow" }
}
```

#### User Management
```json
{
  "users_scopes_list": { "scope_id": "api_s049", "scope_slug": "users_scopes_list", "permission": "deny" },
  "users_list": { "scope_id": "api_s050", "scope_slug": "users_list", "permission": "deny" },
  "users_create": { "scope_id": "api_s051", "scope_slug": "users_create", "permission": "deny" },
  "users_get": { "scope_id": "api_s052", "scope_slug": "users_get", "permission": "deny" },
  "users_update": { "scope_id": "api_s053", "scope_slug": "users_update", "permission": "deny" },
  "users_delete": { "scope_id": "api_s054", "scope_slug": "users_delete", "permission": "deny" },
  "users_apikeys_list": { "scope_id": "api_s055", "scope_slug": "users_apikeys_list", "permission": "deny" },
  "users_apikeys_create": { "scope_id": "api_s056", "scope_slug": "users_apikeys_create", "permission": "deny" },
  "users_apikeys_get": { "scope_id": "api_s057", "scope_slug": "users_apikeys_get", "permission": "deny" },
  "users_apikeys_update": { "scope_id": "api_s058", "scope_slug": "users_apikeys_update", "permission": "deny" },
  "users_apikeys_revoke": { "scope_id": "api_s059", "scope_slug": "users_apikeys_revoke", "permission": "deny" }
}
```

#### Tenant Management
```json
{
  "tenants_add": { "scope_id": "api_s060", "scope_slug": "tenants_add", "permission": "deny" },
  "tenants_list": { "scope_id": "api_s061", "scope_slug": "tenants_list", "permission": "deny" },
  "tenants_setkey": { "scope_id": "api_s062", "scope_slug": "tenants_setkey", "permission": "deny" },
  "tenants_getkey": { "scope_id": "api_s063", "scope_slug": "tenants_getkey", "permission": "deny" },
  "tenants_set_secret": { "scope_id": "api_s064", "scope_slug": "tenants_set_secret", "permission": "deny" },
  "tenants_get_secret": { "scope_id": "api_s065", "scope_slug": "tenants_get_secret", "permission": "deny" }
}
```

#### Groups & Namespaces
```json
{
  "groups_add": { "scope_id": "api_s066", "scope_slug": "groups_add", "permission": "allow" },
  "groups_generate_secret": { "scope_id": "api_s067", "scope_slug": "groups_generate_secret", "permission": "allow" }
}
```

#### Transfer System
```json
{
  "transfer_devices_list": { "scope_id": "api_s070", "scope_slug": "transfer_devices_list", "permission": "allow", "min_plan": "business" },
  "transfer_devices_add": { "scope_id": "api_s071", "scope_slug": "transfer_devices_add", "permission": "allow", "min_plan": "business" },
  "transfer_devices_remove": { "scope_id": "api_s072", "scope_slug": "transfer_devices_remove", "permission": "allow", "min_plan": "business" },
  "transfer_devices_verify": { "scope_id": "api_s073", "scope_slug": "transfer_devices_verify", "permission": "allow", "min_plan": "business" },
  "transfer_send": { "scope_id": "api_s074", "scope_slug": "transfer_send", "permission": "allow", "min_plan": "business" },
  "transfer_receive": { "scope_id": "api_s075", "scope_slug": "transfer_receive", "permission": "allow", "min_plan": "business" },
  "transfer_status": { "scope_id": "api_s076", "scope_slug": "transfer_status", "permission": "allow", "min_plan": "business" },
  "transfer_cancel": { "scope_id": "api_s077", "scope_slug": "transfer_cancel", "permission": "allow", "min_plan": "business" },
  "transfer_cloud_upload": { "scope_id": "api_s078", "scope_slug": "transfer_cloud_upload", "permission": "allow", "min_plan": "business" },
  "transfer_cloud_download": { "scope_id": "api_s079", "scope_slug": "transfer_cloud_download", "permission": "allow", "min_plan": "business" },
  "transfer_cloud_list": { "scope_id": "api_s080", "scope_slug": "transfer_cloud_list", "permission": "allow", "min_plan": "business" },
  "transfer_bundle_create": { "scope_id": "api_s081", "scope_slug": "transfer_bundle_create", "permission": "allow", "min_plan": "business" },
  "transfer_bundle_import": { "scope_id": "api_s082", "scope_slug": "transfer_bundle_import", "permission": "allow", "min_plan": "business" },
  "transfer_bundle_qr_generate": { "scope_id": "api_s083", "scope_slug": "transfer_bundle_qr_generate", "permission": "allow", "min_plan": "business" },
  "transfer_bundle_qr_scan": { "scope_id": "api_s084", "scope_slug": "transfer_bundle_qr_scan", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_list": { "scope_id": "api_s085", "scope_slug": "transfer_schedule_list", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_create": { "scope_id": "api_s086", "scope_slug": "transfer_schedule_create", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_update": { "scope_id": "api_s087", "scope_slug": "transfer_schedule_update", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_delete": { "scope_id": "api_s088", "scope_slug": "transfer_schedule_delete", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_pause": { "scope_id": "api_s089", "scope_slug": "transfer_schedule_pause", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_resume": { "scope_id": "api_s090", "scope_slug": "transfer_schedule_resume", "permission": "allow", "min_plan": "business" },
  "transfer_schedule_run": { "scope_id": "api_s091", "scope_slug": "transfer_schedule_run", "permission": "allow", "min_plan": "business" },
  "transfer_history": { "scope_id": "api_s092", "scope_slug": "transfer_history", "permission": "allow", "min_plan": "business" },
  "transfer_audit": { "scope_id": "api_s093", "scope_slug": "transfer_audit", "permission": "allow", "min_plan": "business" },
  "transfer_manifest_get": { "scope_id": "api_s094", "scope_slug": "transfer_manifest_get", "permission": "allow", "min_plan": "business" },
  "transfer_manifest_verify": { "scope_id": "api_s095", "scope_slug": "transfer_manifest_verify", "permission": "allow", "min_plan": "business" }
}
```
*Note: Transfer system API endpoints require Business plan or higher*

#### Export/Import
```json
{
  "export_all": { "scope_id": "api_s096", "scope_slug": "export_all", "permission": "allow" },
  "import_all": { "scope_id": "api_s097", "scope_slug": "import_all", "permission": "allow" }
}
```

---

## 4. Plan-Based Feature Matrix

### Trial Plan (7 days)
```json
{
  "cli": {
    "enabled": true,
    "scopes": {}
  },
  "gui": {
    "enabled": true,
    "scopes": {}
  },
  "api": {
    "enabled": true,
    "scopes": {}
  }
}
```
*Note: Empty scopes = all features unlocked during trial*

### Personal Plan ($25/device/year, min 1 device)
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
      "p2p-share": { "permission": "deny" },
      "p2p": { "permission": "deny" },
      "share": { "permission": "deny" },
      "scratchpad": { "permission": "deny" },
      "template": { "permission": "deny" },
      "rotate": { "permission": "deny" },
      "container": { "permission": "deny" },
      "sandbox": { "permission": "deny" },
      "secure-sandbox": { "permission": "deny" },
      "tenant": { "permission": "deny" },
      "server": { "permission": "deny" },
      "compliance": { "permission": "deny" },
      "fips": { "permission": "deny" },
      "classify": { "permission": "deny" },
      "retention": { "permission": "deny" },
      "breach": { "permission": "deny" },
      "access-review": { "permission": "deny" },
      "listkv": { "permission": "deny" },
      "rollbackkv": { "permission": "deny" },
      "vcs": { "permission": "deny" },
      "enable-2fa": { "permission": "deny" },
      "disable-2fa": { "permission": "deny" },
      "enable-passkey": { "permission": "deny" },
      "disable-passkey": { "permission": "deny" },
      "shamir": { "permission": "deny" },
      "shamir-split": { "permission": "deny" },
      "shamir-combine": { "permission": "deny" },
      "audit": { "permission": "deny" },
      "audit-log": { "permission": "deny" },
      "transfer": { "permission": "deny" },
      "transfer-devices": { "permission": "deny" },
      "transfer-devices-list": { "permission": "deny" },
      "transfer-devices-add": { "permission": "deny" },
      "transfer-devices-remove": { "permission": "deny" },
      "transfer-devices-verify": { "permission": "deny" },
      "transfer-send": { "permission": "deny" },
      "transfer-upload": { "permission": "deny" },
      "transfer-download": { "permission": "deny" },
      "transfer-bundle": { "permission": "deny" },
      "transfer-bundle-create": { "permission": "deny" },
      "transfer-bundle-import": { "permission": "deny" },
      "transfer-bundle-qr": { "permission": "deny" },
      "transfer-schedule": { "permission": "deny" },
      "transfer-schedule-list": { "permission": "deny" },
      "transfer-schedule-add": { "permission": "deny" },
      "transfer-schedule-pause": { "permission": "deny" },
      "transfer-schedule-resume": { "permission": "deny" },
      "transfer-schedule-run": { "permission": "deny" }
    }
  },
  "gui": {
    "enabled": true,
    "scopes": {
      "p2p_share": { "permission": "deny" },
      "p2p_discover": { "permission": "deny" },
      "p2p_receive": { "permission": "deny" },
      "scratchpad": { "permission": "deny" },
      "templates": { "permission": "deny" },
      "rotation": { "permission": "deny" },
      "two_factor_auth": { "permission": "deny" },
      "shamir_sharing": { "permission": "deny" },
      "audit_log": { "permission": "deny" },
      "compliance_dashboard": { "permission": "deny" },
      "data_classification": { "permission": "deny" },
      "data_retention": { "permission": "deny" },
      "breach_notification": { "permission": "deny" },
      "access_reviews": { "permission": "deny" },
      "fips_compliance": { "permission": "deny" },
      "transfer_dashboard": { "permission": "deny" },
      "transfer_devices": { "permission": "deny" },
      "transfer_devices_manage": { "permission": "deny" },
      "transfer_send": { "permission": "deny" },
      "transfer_receive": { "permission": "deny" },
      "transfer_cloud": { "permission": "deny" },
      "transfer_cloud_upload": { "permission": "deny" },
      "transfer_cloud_download": { "permission": "deny" },
      "transfer_airgap": { "permission": "deny" },
      "transfer_bundle_create": { "permission": "deny" },
      "transfer_bundle_import": { "permission": "deny" },
      "transfer_bundle_qr": { "permission": "deny" },
      "transfer_schedule": { "permission": "deny" },
      "transfer_schedule_manage": { "permission": "deny" },
      "transfer_history": { "permission": "deny" },
      "transfer_audit": { "permission": "deny" }
    }
  },
  "api": {
    "enabled": false
  }
}
```

### Solo Plan ($60/device/year, min 2 devices)
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
      "scratchpad": { "permission": "deny" },
      "template": { "permission": "deny" },
      "rotate": { "permission": "deny" },
      "share": { "permission": "deny" },
      "container": { "permission": "deny" },
      "sandbox": { "permission": "deny" },
      "secure-sandbox": { "permission": "deny" },
      "tenant": { "permission": "deny" },
      "server": { "permission": "deny" },
      "compliance": { "permission": "deny" },
      "fips": { "permission": "deny" },
      "classify": { "permission": "deny" },
      "retention": { "permission": "deny" },
      "breach": { "permission": "deny" },
      "access-review": { "permission": "deny" },
      "inject": { "permission": "deny" },
      "config-inject": { "permission": "deny" },
      "transfer": { "permission": "deny" },
      "transfer-devices": { "permission": "deny" },
      "transfer-devices-list": { "permission": "deny" },
      "transfer-devices-add": { "permission": "deny" },
      "transfer-devices-remove": { "permission": "deny" },
      "transfer-devices-verify": { "permission": "deny" },
      "transfer-send": { "permission": "deny" },
      "transfer-upload": { "permission": "deny" },
      "transfer-download": { "permission": "deny" },
      "transfer-bundle": { "permission": "deny" },
      "transfer-bundle-create": { "permission": "deny" },
      "transfer-bundle-import": { "permission": "deny" },
      "transfer-bundle-qr": { "permission": "deny" },
      "transfer-schedule": { "permission": "deny" },
      "transfer-schedule-list": { "permission": "deny" },
      "transfer-schedule-add": { "permission": "deny" },
      "transfer-schedule-pause": { "permission": "deny" },
      "transfer-schedule-resume": { "permission": "deny" },
      "transfer-schedule-run": { "permission": "deny" }
    }
  },
  "gui": {
    "enabled": true,
    "scopes": {
      "scratchpad": { "permission": "deny" },
      "templates": { "permission": "deny" },
      "rotation": { "permission": "deny" },
      "compliance_dashboard": { "permission": "deny" },
      "data_classification": { "permission": "deny" },
      "data_retention": { "permission": "deny" },
      "breach_notification": { "permission": "deny" },
      "access_reviews": { "permission": "deny" },
      "fips_compliance": { "permission": "deny" },
      "transfer_dashboard": { "permission": "deny" },
      "transfer_devices": { "permission": "deny" },
      "transfer_devices_manage": { "permission": "deny" },
      "transfer_send": { "permission": "deny" },
      "transfer_receive": { "permission": "deny" },
      "transfer_cloud": { "permission": "deny" },
      "transfer_cloud_upload": { "permission": "deny" },
      "transfer_cloud_download": { "permission": "deny" },
      "transfer_airgap": { "permission": "deny" },
      "transfer_bundle_create": { "permission": "deny" },
      "transfer_bundle_import": { "permission": "deny" },
      "transfer_bundle_qr": { "permission": "deny" },
      "transfer_schedule": { "permission": "deny" },
      "transfer_schedule_manage": { "permission": "deny" },
      "transfer_history": { "permission": "deny" },
      "transfer_audit": { "permission": "deny" }
    }
  },
  "api": {
    "enabled": false
  }
}
```

### Team Plan ($90/device/year, min 5 devices)
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
      "share": { "permission": "deny" },
      "container": { "permission": "deny" },
      "sandbox": { "permission": "deny" },
      "secure-sandbox": { "permission": "deny" },
      "tenant": { "permission": "deny" },
      "server": { "permission": "deny" },
      "compliance": { "permission": "deny" },
      "fips": { "permission": "deny" },
      "classify": { "permission": "deny" },
      "retention": { "permission": "deny" },
      "breach": { "permission": "deny" },
      "access-review": { "permission": "deny" },
      "inject": { "permission": "deny" },
      "config-inject": { "permission": "deny" }
    }
  },
  "gui": {
    "enabled": true,
    "scopes": {
      "compliance_dashboard": { "permission": "deny" },
      "data_classification": { "permission": "deny" },
      "data_retention": { "permission": "deny" },
      "breach_notification": { "permission": "deny" },
      "access_reviews": { "permission": "deny" },
      "fips_compliance": { "permission": "deny" }
    }
  },
  "api": {
    "enabled": false
  }
}
```

### Business Plan ($180/device/year, min 15 devices)
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
      "container": { "permission": "deny" },
      "compliance": { "permission": "deny" },
      "fips": { "permission": "deny" },
      "classify": { "permission": "deny" },
      "breach": { "permission": "deny" },
      "access-review": { "permission": "deny" },
      "container-audit": { "permission": "deny" },
      "csa": { "permission": "deny" }
    }
  },
  "gui": {
    "enabled": true,
    "scopes": {
      "compliance_dashboard": { "permission": "deny" },
      "data_classification": { "permission": "deny" },
      "breach_notification": { "permission": "deny" },
      "access_reviews": { "permission": "deny" },
      "fips_compliance": { "permission": "deny" }
    }
  },
  "api": {
    "enabled": true,
    "scopes": {}
  }
}
```
*Note: API enabled with unlimited access, no rate limits*

### Enterprise Plan (Custom, min 50+ devices)
```json
{
  "cli": {
    "enabled": true,
    "scopes": {}
  },
  "gui": {
    "enabled": true,
    "scopes": {}
  },
  "api": {
    "enabled": true,
    "scopes": {}
  }
}
```
*Note: Empty scopes object means all actions are allowed with unlimited access*

---

## 5. Complete License Data Example

### Personal Plan Example ($25/device/year, 1 device min)
```json
{
  "entitlements": {
    "product_id": "prod_secretr_001",
    "product_slug": "secretr",
    "plan_id": "plan_personal_001",
    "plan_slug": "personal",
    "min_devices": 1,
    "max_devices": 1,
    "storage_limit_bytes": 1073741824,
    "storage_limit_display": "1 GB",
    "features": {
      "cli": {
        "feature_id": "feat_cli_001",
        "feature_slug": "cli",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "get": { "permission": "allow" },
          "set": { "permission": "allow" },
          "list": { "permission": "allow" },
          "delete": { "permission": "allow" },
          "copy": { "permission": "allow" },
          "ssh": { "permission": "allow" },
          "ssh-key": { "permission": "allow" },
          "files": { "permission": "allow" },
          "backup": { "permission": "allow" },
          "generate": { "permission": "allow" },
          "policy": { "permission": "allow" },
          "seal": { "permission": "allow" },
          "metrics": { "permission": "allow" },
          "share": { "permission": "deny" },
          "scratchpad": { "permission": "deny" },
          "template": { "permission": "deny" },
          "rotation": { "permission": "deny" },
          "2fa": { "permission": "deny" },
          "passkey": { "permission": "deny" },
          "listkv": { "permission": "deny" },
          "audit": { "permission": "deny" },
          "sandbox": { "permission": "deny" },
          "tenant": { "permission": "deny" },
          "server": { "permission": "deny" },
          "container": { "permission": "deny" },
          "compliance": { "permission": "deny" },
          "fips": { "permission": "deny" }
        }
      },
      "gui": {
        "feature_id": "feat_gui_001",
        "feature_slug": "gui",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "view": { "permission": "allow" },
          "list": { "permission": "allow" },
          "create": { "permission": "allow" },
          "update": { "permission": "allow" },
          "delete": { "permission": "allow" },
          "secret_manager": { "permission": "allow" },
          "file_manager": { "permission": "allow" },
          "generators": { "permission": "allow" },
          "p2p_discovery": { "permission": "deny" },
          "compliance_dashboard": { "permission": "deny" }
        }
      },
      "api": {
        "feature_id": "feat_api_001",
        "feature_slug": "api",
        "category": "integration",
        "enabled": false,
        "scopes": {}
      }
    }
  }
}
```

### Business Plan Example ($180/device/year, 15 device min)
```json
{
  "entitlements": {
    "product_id": "prod_secretr_001",
    "product_slug": "secretr",
    "plan_id": "plan_business_001",
    "plan_slug": "business",
    "min_devices": 15,
    "max_devices": -1,
    "storage_limit_bytes": -1,
    "storage_limit_display": "Unlimited",
    "features": {
      "cli": {
        "feature_id": "feat_cli_001",
        "feature_slug": "cli",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "container": { "permission": "deny" },
          "compliance": { "permission": "deny" },
          "fips": { "permission": "deny" },
          "classify": { "permission": "deny" },
          "breach": { "permission": "deny" },
          "access-review": { "permission": "deny" }
        }
      },
      "gui": {
        "feature_id": "feat_gui_001",
        "feature_slug": "gui",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "compliance_dashboard": { "permission": "deny" },
          "data_classification": { "permission": "deny" },
          "fips_compliance": { "permission": "deny" }
        }
      },
      "api": {
        "feature_id": "feat_api_001",
        "feature_slug": "api",
        "category": "integration",
        "enabled": true,
        "scopes": {
          "container_inject": { "permission": "deny" },
          "container_extract": { "permission": "deny" },
          "compliance_check": { "permission": "deny" },
          "fips_validate": { "permission": "deny" }
        }
      }
    }
  }
}
```
*Note: Business plan shows deny-list approach - only explicitly denied scopes are listed*

### Enterprise Plan Example (Custom pricing, 50+ devices)
```json
{
  "entitlements": {
    "product_id": "prod_secretr_001",
    "product_slug": "secretr",
    "plan_id": "plan_enterprise_001",
    "plan_slug": "enterprise",
    "min_devices": 50,
    "max_devices": -1,
    "storage_limit_bytes": -1,
    "storage_limit_display": "Unlimited",
    "features": {
      "cli": {
        "feature_id": "feat_cli_001",
        "feature_slug": "cli",
        "category": "interface",
        "enabled": true,
        "scopes": {}
      },
      "gui": {
        "feature_id": "feat_gui_001",
        "feature_slug": "gui",
        "category": "interface",
        "enabled": true,
        "scopes": {}
      },
      "api": {
        "feature_id": "feat_api_001",
        "feature_slug": "api",
        "category": "integration",
        "enabled": true,
        "scopes": {}
      }
    }
  }
}
```
*Note: Empty scopes object means all actions are allowed with unlimited access*

---

## 6. Storage Limits by Plan

```json
{
  "trial": {
    "storage_limit_bytes": -1,
    "storage_limit_display": "Unlimited",
    "duration_days": 14
  },
  "personal": {
    "storage_limit_bytes": 1073741824,
    "storage_limit_display": "1 GB"
  },
  "solo": {
    "storage_limit_bytes": 5368709120,
    "storage_limit_display": "5 GB"
  },
  "team": {
    "storage_limit_bytes": 26843545600,
    "storage_limit_display": "25 GB"
  },
  "business": {
    "storage_limit_bytes": -1,
    "storage_limit_display": "Unlimited"
  },
  "enterprise": {
    "storage_limit_bytes": -1,
    "storage_limit_display": "Unlimited"
  }
}
```

---

## 7. Implementation Notes

### Checking Entitlements in Code

```go
// Check if CLI command is allowed
if !entitlementManager.IsCommandAllowed("container") {
    return fmt.Errorf("%s", entitlementManager.GetCommandDeniedMessage("container"))
}

// Check if GUI action is allowed
if !guiEntitlementManager.IsGUIActionAllowed("compliance_dashboard") {
    // Hide navigation item or show denial message
}

// Check if API endpoint is allowed
if !entitlementManager.IsAPIActionAllowed("tenants_add") {
    return http.StatusForbidden, "This API endpoint requires a Business or Enterprise plan"
}
```

### Permission Types

- **allow**: Operation is permitted
- **deny**: Operation is blocked
- **limit**: Operation is rate-limited (requires `limit` field with integer value)

### Default Behavior

When `scopes` is an empty object `{}`, all operations within that feature are allowed. This is used for Enterprise plans to grant unrestricted access.

---

## 8. Scope Categories Summary

| Category | Scope Count | Typical Restriction |
|----------|-------------|---------------------|
| CLI Basic Operations | 6 | All plans |
| CLI SSH Management | 3 | Personal+ |
| CLI File Operations | 1 | All plans |
| CLI Sharing | 3 | Solo+ (P2P requires 2 devices) |
| CLI Container Security | 1 | Enterprise |
| CLI Backup/Import/Export | 7 | Personal+ |
| CLI Generators | 5 | Personal+ |
| CLI Templates | 1 | Team+ |
| CLI Rotation | 1 | Team+ |
| CLI Tenant Management | 1 | Business+ |
| CLI Sandbox | 3 | Business+ |
| CLI Security Policy | 2 | Personal+ |
| CLI Vault Security | 2 | Personal+ |
| CLI Observability | 2 | Personal+ |
| CLI Versioning (listkv, rollbackkv, vcs) | 3 | Solo+ |
| CLI Shamir | 3 | Solo+ |
| CLI Audit | 2 | Solo+ |
| CLI FIPS Compliance | 2 | Enterprise |
| CLI Compliance Frameworks | 2 | Enterprise |
| CLI Data Classification | 3 | Enterprise |
| CLI Data Retention | 2 | Business+ |
| CLI Breach Management | 2 | Enterprise |
| CLI Access Review | 3 | Enterprise |
| CLI Authentication (2FA/Passkey) | 5 | Solo+ |
| CLI System Commands (Server) | 3 | Business+ |
| CLI Vault Compaction | 2 | Team+ |
| CLI Config Injection | 2 | Business+ |
| CLI Container Security Audit | 2 | Enterprise |
| CLI Transfer System | 19 | Business+ |
| **Total CLI Scopes** | **102** | |
| | | |
| GUI CRUD Operations | 6 | All plans |
| GUI Secret Management | 4 | Personal+ |
| GUI File Management | 3 | All plans |
| GUI Generators | 4 | Personal+ |
| GUI SSH Management | 3 | Personal+ |
| GUI P2P Sharing | 3 | Solo+ |
| GUI Cryptographic Ops | 2 | Solo+ |
| GUI Management Views | 4 | Solo+ |
| GUI Transfer System Views | 17 | Business+ |
| GUI Compliance Views | 6 | Enterprise |
| GUI Security Views | 2 | Solo+ |
| **Total GUI Scopes** | **54** | |
| | | |
| API Setup & Config | 3 | Business+ (requires HTTP API) |
| API Authentication | 3 | Business+ |
| API Two-Factor Auth | 6 | Solo+ |
| API Secrets Management | 4 | Business+ |
| API KV Versioning | 2 | Solo+ |
| API Transit Engine | 2 | Business+ |
| API Dynamic Engines | 3 | Solo+ |
| API Response Wrapping | 2 | Business+ |
| API File Management | 5 | Business+ |
| API SSH Management | 8 | Business+ |
| API Certificate Mgmt | 1 | Solo+ |
| API Key Generation | 4 | Personal+ |
| API Managed Keys | 5 | Business+ |
| API User Management | 11 | Business+ |
| API Tenant Management | 6 | Business+ |
| API Groups/Namespaces | 2 | Business+ |
| API Transfer System | 26 | Business+ |
| API Export/Import | 2 | Personal+ |
| **Total API Scopes** | **95** | |
| | | |
| **Grand Total** | **251** | |

---

## 9. Next Steps for Implementation

1. **Update License Server**: Configure these scopes in your licensing backend
2. **Update Plan Definitions**: Map each plan to its allowed scope set
3. **Test Enforcement**: Verify entitlement checks in CLI, GUI, and API
4. **Update Documentation**: User-facing plan comparison tables
5. **Add Telemetry**: Track usage of gated features for plan upgrades
