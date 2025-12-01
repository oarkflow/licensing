# Complete Entitlement Feature Scopes for Secretr

This document defines the complete entitlement structure covering all CLI commands, API endpoints, and GUI features in the Secretr project.

## License Data Structure

```json
{
  "entitlements": {
    "product_id": "prod_secretr_001",
    "product_slug": "secretr",
    "plan_id": "plan_professional_001",
    "plan_slug": "professional",
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
  "share": { "scope_id": "cli_s011", "scope_slug": "share", "permission": "allow" },
  "p2p-share": { "scope_id": "cli_s012", "scope_slug": "p2p-share", "permission": "allow" },
  "p2p": { "scope_id": "cli_s013", "scope_slug": "p2p", "permission": "allow" }
}
```

#### Container Security
```json
{
  "container": { "scope_id": "cli_s014", "scope_slug": "container", "permission": "deny" }
}
```
*Note: Container operations typically restricted to enterprise plans*

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
  "template": { "scope_id": "cli_s023", "scope_slug": "template", "permission": "allow" }
}
```

#### Secret Rotation
```json
{
  "rotate": { "scope_id": "cli_s024", "scope_slug": "rotate", "permission": "allow" }
}
```

#### Tenant Management
```json
{
  "tenant": { "scope_id": "cli_s025", "scope_slug": "tenant", "permission": "deny" }
}
```
*Note: Multi-tenancy typically restricted to team/enterprise plans*

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
  "scratchpad": { "scope_id": "cli_s031", "scope_slug": "scratchpad", "permission": "allow" }
}
```

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
  "listkv": { "scope_id": "cli_s039", "scope_slug": "listkv", "permission": "allow" },
  "rollbackkv": { "scope_id": "cli_s040", "scope_slug": "rollbackkv", "permission": "allow" }
}
```

#### Security Sandbox
```json
{
  "sandbox": { "scope_id": "cli_s041", "scope_slug": "sandbox", "permission": "deny" },
  "secure-sandbox": { "scope_id": "cli_s042", "scope_slug": "secure-sandbox", "permission": "deny" },
  "ssb": { "scope_id": "cli_s043", "scope_slug": "ssb", "permission": "deny" }
}
```
*Note: Sandbox features typically restricted to professional/enterprise plans*

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
  "server": { "scope_id": "cli_s069", "scope_slug": "server", "permission": "deny" },
  "kds": { "scope_id": "cli_s070", "scope_slug": "kds", "permission": "deny" },
  "server-config": { "scope_id": "cli_s071", "scope_slug": "server-config", "permission": "deny" }
}
```
*Note: Server mode and server-config typically restricted to team/enterprise plans*

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

#### Security Views
```json
{
  "two_factor_auth": { "scope_id": "gui_s036", "scope_slug": "two_factor_auth", "permission": "allow" },
  "vault_lock": { "scope_id": "gui_s037", "scope_slug": "vault_lock", "permission": "allow" }
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

#### Export/Import
```json
{
  "export_all": { "scope_id": "api_s068", "scope_slug": "export_all", "permission": "allow" },
  "import_all": { "scope_id": "api_s069", "scope_slug": "import_all", "permission": "allow" }
}
```

---

## 4. Plan-Based Feature Matrix

### Personal Plan
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
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
      "access-review": { "permission": "deny" }
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

### Starter Plan
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
      "container": { "permission": "deny" },
      "sandbox": { "permission": "deny" },
      "tenant": { "permission": "deny" },
      "server": { "permission": "deny" },
      "compliance": { "permission": "deny" },
      "fips": { "permission": "deny" },
      "classify": { "permission": "deny" },
      "retention": { "permission": "deny" },
      "breach": { "permission": "deny" },
      "access-review": { "permission": "deny" }
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
    "enabled": true,
    "scopes": {
      "users_list": { "permission": "deny" },
      "users_create": { "permission": "deny" },
      "tenants_add": { "permission": "deny" }
    }
  }
}
```

### Professional Plan
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
      "sandbox": { "permission": "allow" },
      "secure-sandbox": { "permission": "allow" },
      "tenant": { "permission": "deny" },
      "server": { "permission": "deny" },
      "compliance": { "permission": "deny" },
      "fips": { "permission": "deny" },
      "classify": { "permission": "deny" },
      "retention": { "permission": "deny" },
      "breach": { "permission": "deny" },
      "access-review": { "permission": "deny" }
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
    "enabled": true,
    "scopes": {
      "users_list": { "permission": "allow" },
      "users_create": { "permission": "allow" },
      "tenants_add": { "permission": "deny" }
    }
  }
}
```

### Team Plan
```json
{
  "cli": {
    "enabled": true,
    "scopes": {
      "sandbox": { "permission": "allow" },
      "secure-sandbox": { "permission": "allow" },
      "container": { "permission": "allow" },
      "tenant": { "permission": "allow" },
      "server": { "permission": "allow" },
      "server-config": { "permission": "allow" },
      "compliance": { "permission": "deny" },
      "fips": { "permission": "deny" },
      "classify": { "permission": "deny" },
      "retention": { "permission": "deny" },
      "breach": { "permission": "deny" },
      "access-review": { "permission": "deny" }
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
    "enabled": true,
    "scopes": {
      "users_list": { "permission": "allow" },
      "users_create": { "permission": "allow" },
      "tenants_add": { "permission": "allow" }
    }
  }
}
```

### Enterprise Plan
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
*Note: Empty scopes object means all actions are allowed*

---

## 5. Complete License Data Example

### Personal Plan Example
```json
{
  "entitlements": {
    "product_id": "prod_secretr_001",
    "product_slug": "secretr",
    "plan_id": "plan_personal_001",
    "plan_slug": "personal",
    "features": {
      "cli": {
        "feature_id": "feat_cli_001",
        "feature_slug": "cli",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "get": { "scope_id": "cli_s001", "scope_slug": "get", "permission": "allow" },
          "set": { "scope_id": "cli_s002", "scope_slug": "set", "permission": "allow" },
          "list": { "scope_id": "cli_s003", "scope_slug": "list", "permission": "allow" },
          "delete": { "scope_id": "cli_s004", "scope_slug": "delete", "permission": "allow" },
          "copy": { "scope_id": "cli_s005", "scope_slug": "copy", "permission": "allow" },
          "ssh": { "scope_id": "cli_s007", "scope_slug": "ssh", "permission": "allow" },
          "ssh-key": { "scope_id": "cli_s008", "scope_slug": "ssh-key", "permission": "allow" },
          "files": { "scope_id": "cli_s010", "scope_slug": "files", "permission": "allow" },
          "share": { "scope_id": "cli_s011", "scope_slug": "share", "permission": "allow" },
          "backup": { "scope_id": "cli_s015", "scope_slug": "backup", "permission": "allow" },
          "container": { "scope_id": "cli_s014", "scope_slug": "container", "permission": "deny" },
          "sandbox": { "scope_id": "cli_s041", "scope_slug": "sandbox", "permission": "deny" },
          "tenant": { "scope_id": "cli_s025", "scope_slug": "tenant", "permission": "deny" },
          "server": { "scope_id": "cli_s069", "scope_slug": "server", "permission": "deny" },
          "compliance": { "scope_id": "cli_s052", "scope_slug": "compliance", "permission": "deny" },
          "fips": { "scope_id": "cli_s050", "scope_slug": "fips", "permission": "deny" },
          "classify": { "scope_id": "cli_s054", "scope_slug": "classify", "permission": "deny" },
          "retention": { "scope_id": "cli_s057", "scope_slug": "retention", "permission": "deny" },
          "breach": { "scope_id": "cli_s059", "scope_slug": "breach", "permission": "deny" },
          "access-review": { "scope_id": "cli_s061", "scope_slug": "access-review", "permission": "deny" }
        }
      },
      "gui": {
        "feature_id": "feat_gui_001",
        "feature_slug": "gui",
        "category": "interface",
        "enabled": true,
        "scopes": {
          "view": { "scope_id": "gui_s001", "scope_slug": "view", "permission": "allow" },
          "list": { "scope_id": "gui_s002", "scope_slug": "list", "permission": "allow" },
          "create": { "scope_id": "gui_s003", "scope_slug": "create", "permission": "allow" },
          "update": { "scope_id": "gui_s004", "scope_slug": "update", "permission": "allow" },
          "delete": { "scope_id": "gui_s005", "scope_slug": "delete", "permission": "allow" },
          "secret_manager": { "scope_id": "gui_s007", "scope_slug": "secret_manager", "permission": "allow" },
          "file_manager": { "scope_id": "gui_s011", "scope_slug": "file_manager", "permission": "allow" },
          "ssh_profiles": { "scope_id": "gui_s018", "scope_slug": "ssh_profiles", "permission": "allow" },
          "compliance_dashboard": { "scope_id": "gui_s030", "scope_slug": "compliance_dashboard", "permission": "deny" },
          "data_classification": { "scope_id": "gui_s031", "scope_slug": "data_classification", "permission": "deny" },
          "fips_compliance": { "scope_id": "gui_s035", "scope_slug": "fips_compliance", "permission": "deny" }
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

### Enterprise Plan Example (All Features)
```json
{
  "entitlements": {
    "product_id": "prod_secretr_001",
    "product_slug": "secretr",
    "plan_id": "plan_enterprise_001",
    "plan_slug": "enterprise",
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

---

## 6. Storage Limits by Plan

```json
{
  "personal": {
    "storage_limit_bytes": 524288000,
    "storage_limit_display": "500 MB"
  },
  "starter": {
    "storage_limit_bytes": 524288000,
    "storage_limit_display": "500 MB"
  },
  "professional": {
    "storage_limit_bytes": 2147483648,
    "storage_limit_display": "2 GB"
  },
  "team": {
    "storage_limit_bytes": 5368709120,
    "storage_limit_display": "5 GB"
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
    return http.StatusForbidden, "This API endpoint requires a Team or Enterprise plan"
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
| CLI Basic Operations | 6 | Always allowed |
| CLI SSH Management | 3 | Always allowed |
| CLI File Operations | 1 | Always allowed |
| CLI Sharing | 3 | Always allowed |
| CLI Container Security | 1 | Professional+ |
| CLI Backup/Import/Export | 7 | Always allowed |
| CLI Generators | 5 | Always allowed |
| CLI Templates | 1 | Always allowed |
| CLI Rotation | 1 | Always allowed |
| CLI Tenant Management | 1 | Team+ |
| CLI Sandbox | 3 | Professional+ |
| CLI Security Policy | 2 | Always allowed |
| CLI Vault Security | 2 | Always allowed |
| CLI Observability | 2 | Always allowed |
| CLI FIPS Compliance | 2 | Enterprise |
| CLI Compliance Frameworks | 2 | Enterprise |
| CLI Data Classification | 3 | Enterprise |
| CLI Data Retention | 2 | Enterprise |
| CLI Breach Management | 2 | Enterprise |
| CLI Access Review | 3 | Enterprise |
| CLI Authentication | 5 | Always allowed |
| CLI System Commands | 3 | Team+ |
| **Total CLI Scopes** | **71** | |
| | | |
| GUI CRUD Operations | 6 | Always allowed |
| GUI Secret Management | 4 | Always allowed |
| GUI File Management | 3 | Always allowed |
| GUI Generators | 4 | Always allowed |
| GUI SSH Management | 3 | Always allowed |
| GUI P2P Sharing | 3 | Always allowed |
| GUI Cryptographic Ops | 2 | Always allowed |
| GUI Management Views | 4 | Always allowed |
| GUI Compliance Views | 6 | Enterprise |
| GUI Security Views | 2 | Always allowed |
| **Total GUI Scopes** | **37** | |
| | | |
| API Setup & Config | 3 | Always allowed |
| API Authentication | 3 | Always allowed |
| API Two-Factor Auth | 6 | Always allowed |
| API Secrets Management | 4 | Always allowed |
| API KV Versioning | 2 | Always allowed |
| API Transit Engine | 2 | Always allowed |
| API Dynamic Engines | 3 | Always allowed |
| API Response Wrapping | 2 | Always allowed |
| API File Management | 5 | Always allowed |
| API SSH Management | 8 | Always allowed |
| API Certificate Mgmt | 1 | Always allowed |
| API Key Generation | 4 | Always allowed |
| API Managed Keys | 5 | Always allowed |
| API User Management | 11 | Team+ |
| API Tenant Management | 6 | Team+ |
| API Groups/Namespaces | 2 | Always allowed |
| API Export/Import | 2 | Always allowed |
| **Total API Scopes** | **69** | |
| | | |
| **Grand Total** | **177** | |

---

## 9. Next Steps for Implementation

1. **Update License Server**: Configure these scopes in your licensing backend
2. **Update Plan Definitions**: Map each plan to its allowed scope set
3. **Test Enforcement**: Verify entitlement checks in CLI, GUI, and API
4. **Update Documentation**: User-facing plan comparison tables
5. **Add Telemetry**: Track usage of gated features for plan upgrades
