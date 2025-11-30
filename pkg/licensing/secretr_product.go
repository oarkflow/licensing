package licensing

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

const (
	secretrProductID   = "secretr"
	secretrProductSlug = "secretr"
	defaultTrialDays   = 7
)

// SecretrCatalogSnapshot captures the canonical product, plan, and feature
// metadata that gets synchronized into storage.
type SecretrCatalogSnapshot struct {
	Product  *Product
	Plans    map[string]*Plan    // keyed by plan slug
	Features map[string]*Feature // keyed by feature slug
}

type secretrFeatureDefinition struct {
	ID           string
	Name         string
	Slug         string
	Category     string
	Description  string
	CLIActions   []string
	GUIActions   []string
	APIEndpoints []string
}

type scopeChannel string

const (
	scopeChannelCLI scopeChannel = "cli"
	scopeChannelGUI scopeChannel = "gui"
	scopeChannelAPI scopeChannel = "api"
)

type secretrPlanDefinition struct {
	ID               string
	Name             string
	Slug             string
	Description      string
	Price            int64
	BillingCycle     string
	TrialDays        int
	IsTrial          bool
	DisplayOrder     int
	Metadata         map[string]string
	FeatureAdditions []string
	IsActive         bool
}

var commonFeatureSlugs = []string{
	"aes-256-gcm-encryption",
	"device-fingerprint-binding",
	"basic-environment-integration",
	"basic-file-vault",
	"basic-generators",
	"basic-import",
	"secret-crud",
	"basic-ssh-management",
}

var personalFeatureAdditions = []string{
	"desktop-gui",
	"environment-enrichment",
	"file-password-protection",
	"enhanced-generators",
	"hash-operations",
	"enhanced-import-export",
	"basic-observability",
	"secret-expiration",
	"secret-metadata",
	"secret-password-protection",
	"security-policy",
	"vault-integrity",
	"ssh-connection-profiles",
}

var soloFeatureAdditions = []string{
	"audit-logs",
	"file-tagging",
	"ec-ecdsa-keygen",
	"rsa-keygen",
	"csv-tsv-import",
	"encrypted-scratchpads",
	"dynamic-secrets",
	"secret-version-history",
	"passkey-webauthn",
	"password-reset-email",
	"shamir-secret-sharing",
	"two-factor-auth",
	"ssh-bastion",
	"x509-certificates",
}

var professionalFeatureAdditions = []string{
	"vault-compaction",
	"file-export-restrictions",
	"bundle-management",
	"rotation-policies",
	"namespace-organization",
	"emergency-vault-wipe",
	"process-allowlisting",
	"tampering-detection",
	"p2p-sharing",
	"secret-templates",
}

var teamFeatureAdditions = []string{
	"backup-replication",
	"scheduled-backups",
	"prometheus-metrics",
	"advanced-rotation",
	"access-control",
	"api-health",
	"http-api-server",
	"share-link-generation",
	"share-request-approval",
	"tenant-management",
	"session-management",
	"user-management",
}

var startupFeatureAdditions = []string{
	"data-retention",
	"config-file-injection",
	"secure-sandbox",
	"response-wrapping",
	"secret-engines",
	"iam-policy-engine",
	"mutual-tls",
	"security-levels",
	"threat-model-handlers",
	"multi-tenant-support",
}

var enterpriseFeatureAdditions = []string{
	"enhanced-audit-logs",
	"disaster-recovery",
	"access-review",
	"breach-management",
	"compliance-frameworks",
	"data-classification",
	"fips-mode",
	"container-isolation",
	"container-registry",
	"container-runtime",
	"container-security-audit",
	"priority-support",
	"hsm-integration",
	"managed-encryption-keys",
	"penetration-testing-tools",
	"sso-integration",
	"transit-encryption",
}

var secretrPlanOrder = []string{"personal", "solo", "professional", "team", "startup", "enterprise"}

var secretrPlanFeatureAdditions = map[string][]string{
	"personal":     personalFeatureAdditions,
	"solo":         soloFeatureAdditions,
	"professional": professionalFeatureAdditions,
	"team":         teamFeatureAdditions,
	"startup":      startupFeatureAdditions,
	"enterprise":   enterpriseFeatureAdditions,
}

var secretrPlanDefinitions = []secretrPlanDefinition{
	{
		ID:           "plan_secretr_trial",
		Name:         "Secretr Trial",
		Slug:         "trial",
		Description:  "7-day full Personal experience for evaluations",
		Price:        0,
		BillingCycle: "trial",
		TrialDays:    defaultTrialDays,
		IsTrial:      true,
		DisplayOrder: 0,
		Metadata: map[string]string{
			"tier":        "trial",
			"min_devices": "1",
			"storage_cap": "500MB",
			"notes":       "Automatically expires unless converted to paid plan",
		},
		IsActive: true,
	},
	{
		ID:           "plan_secretr_personal",
		Name:         "Personal",
		Slug:         "personal",
		Description:  "Local-first vault for individual developers",
		Price:        1900,
		BillingCycle: "yearly",
		TrialDays:    0,
		DisplayOrder: 1,
		Metadata: map[string]string{
			"tier":        "personal",
			"min_devices": "1",
			"storage_cap": "500MB",
			"price_model": "per_device",
		},
		FeatureAdditions: personalFeatureAdditions,
		IsActive:         true,
	},
	{
		ID:           "plan_secretr_solo",
		Name:         "Solo",
		Slug:         "solo",
		Description:  "Power-user tier with audit logs, scratchpads, and MFA",
		Price:        4900,
		BillingCycle: "yearly",
		DisplayOrder: 2,
		Metadata: map[string]string{
			"tier":        "solo",
			"min_devices": "3",
			"storage_cap": "2GB",
			"price_model": "per_device",
		},
		FeatureAdditions: soloFeatureAdditions,
		IsActive:         true,
	},
	{
		ID:           "plan_secretr_professional",
		Name:         "Professional",
		Slug:         "professional",
		Description:  "Team-ready vaults with rotation policies and templates",
		Price:        9900,
		BillingCycle: "yearly",
		DisplayOrder: 3,
		Metadata: map[string]string{
			"tier":        "professional",
			"min_devices": "10",
			"storage_cap": "5GB",
			"price_model": "per_device",
		},
		FeatureAdditions: professionalFeatureAdditions,
		IsActive:         true,
	},
	{
		ID:           "plan_secretr_team",
		Name:         "Team",
		Slug:         "team",
		Description:  "Growing orgs with API server, ACLs, and backups",
		Price:        14900,
		BillingCycle: "yearly",
		DisplayOrder: 4,
		Metadata: map[string]string{
			"tier":        "team",
			"min_devices": "25",
			"storage_cap": "10GB",
			"price_model": "per_device",
		},
		FeatureAdditions: teamFeatureAdditions,
		IsActive:         true,
	},
	{
		ID:           "plan_secretr_startup",
		Name:         "Startup",
		Slug:         "startup",
		Description:  "Security-first companies needing multi-tenant controls",
		Price:        24900,
		BillingCycle: "yearly",
		DisplayOrder: 5,
		Metadata: map[string]string{
			"tier":        "startup",
			"min_devices": "50",
			"storage_cap": "unlimited",
			"price_model": "per_device",
		},
		FeatureAdditions: startupFeatureAdditions,
		IsActive:         true,
	},
	{
		ID:           "plan_secretr_enterprise",
		Name:         "Enterprise",
		Slug:         "enterprise",
		Description:  "Compliance-focused deployment with isolation and FIPS",
		Price:        0,
		BillingCycle: "yearly",
		DisplayOrder: 6,
		Metadata: map[string]string{
			"tier":        "enterprise",
			"min_devices": "50+",
			"storage_cap": "unlimited",
			"price_model": "custom",
			"price_notes": "Contact sales",
		},
		FeatureAdditions: enterpriseFeatureAdditions,
		IsActive:         true,
	},
}

var secretrFeatureCatalog = []secretrFeatureDefinition{
	// Common (All Plans)
	{
		ID:          "feat_aes-256-gcm-encryption",
		Name:        "AES-256-GCM Encryption",
		Slug:        "aes-256-gcm-encryption",
		Category:    "core",
		Description: "Encrypts every vault record at rest using AES-256-GCM.",
	},
	{
		ID:          "feat_device-fingerprint-binding",
		Name:        "Device Fingerprint Binding",
		Slug:        "device-fingerprint-binding",
		Category:    "core",
		Description: "Binds vault access to machine fingerprints for offline trust.",
	},
	{
		ID:          "feat_basic-environment-integration",
		Name:        "Basic Environment Integration",
		Slug:        "basic-environment-integration",
		Category:    "environment",
		Description: "Export secrets into env vars or inspect runtime variables.",
		CLIActions:  []string{"printenv", "env"},
	},
	{
		ID:           "feat_basic-file-vault",
		Name:         "Basic File Vault",
		Slug:         "basic-file-vault",
		Category:     "files",
		Description:  "Upload, download, and manage encrypted files.",
		CLIActions:   []string{"files"},
		GUIActions:   []string{"file_manager", "file_upload", "file_download"},
		APIEndpoints: []string{"files_list", "files_upload", "files_download", "files_delete"},
	},
	{
		ID:          "feat_basic-generators",
		Name:        "Basic Generators",
		Slug:        "basic-generators",
		Category:    "generators",
		Description: "Generate passwords, pins, and random strings.",
		CLIActions:  []string{"gen-password", "gen-pin"},
		GUIActions:  []string{"password_generator"},
	},
	{
		ID:          "feat_basic-import",
		Name:        "Basic Import",
		Slug:        "basic-import",
		Category:    "import_export",
		Description: "Seed vaults from .env and simple text files.",
		CLIActions:  []string{"from-file"},
	},
	{
		ID:           "feat_secret-crud",
		Name:         "Secret CRUD Operations",
		Slug:         "secret-crud",
		Category:     "secrets",
		Description:  "Create, read, update, delete, and copy secrets.",
		CLIActions:   []string{"get", "set", "delete", "list", "copy"},
		GUIActions:   []string{"view", "list", "create", "update", "delete", "secret_manager"},
		APIEndpoints: []string{"secrets_read", "secrets_write", "secrets_delete", "secrets_list"},
	},
	{
		ID:           "feat_basic-ssh-management",
		Name:         "Basic SSH Management",
		Slug:         "basic-ssh-management",
		Category:     "ssh",
		Description:  "Store and retrieve SSH keys.",
		CLIActions:   []string{"ssh-key"},
		GUIActions:   []string{"ssh_import"},
		APIEndpoints: []string{"ssh_keys_get", "ssh_keys_create", "ssh_keys_delete", "ssh_keys_list"},
	},

	// Personal
	{
		ID:          "feat_desktop-gui",
		Name:        "Desktop GUI",
		Slug:        "desktop-gui",
		Category:    "core",
		Description: "Unlocks the cross-platform desktop interface.",
		GUIActions:  []string{"settings"},
	},
	{
		ID:          "feat_environment-enrichment",
		Name:        "Environment Enrichment",
		Slug:        "environment-enrichment",
		Category:    "environment",
		Description: "Inject secrets into process env blocks on demand.",
		CLIActions:  []string{"enrich"},
	},
	{
		ID:          "feat_file-password-protection",
		Name:        "File Password Protection",
		Slug:        "file-password-protection",
		Category:    "files",
		Description: "Add per-file passphrases and corruption checks.",
	},
	{
		ID:           "feat_enhanced-generators",
		Name:         "Enhanced Generators",
		Slug:         "enhanced-generators",
		Category:     "generators",
		Description:  "Generate JWT secrets, API keys, asymmetric pairs, and more.",
		CLIActions:   []string{"gen-jwt", "gen-apikey", "gen-keypair", "gen-symkey"},
		GUIActions:   []string{"ssh_key_generator", "certificate_generator", "hash_generator"},
		APIEndpoints: []string{"generate_jwt", "generate_apikey", "generate_keypair", "generate_symkey"},
	},
	{
		ID:          "feat_hash-operations",
		Name:        "Hash Operations",
		Slug:        "hash-operations",
		Category:    "generators",
		Description: "Hash arbitrary content for verification workflows.",
		CLIActions:  []string{"hash"},
	},
	{
		ID:           "feat_enhanced-import-export",
		Name:         "Enhanced Import/Export",
		Slug:         "enhanced-import-export",
		Category:     "import_export",
		Description:  "Import JSON/YAML and run encrypted backups.",
		CLIActions:   []string{"import", "export", "backup"},
		GUIActions:   []string{"backup_restore"},
		APIEndpoints: []string{"export_all", "import_all"},
	},
	{
		ID:          "feat_basic-observability",
		Name:        "Basic Observability",
		Slug:        "basic-observability",
		Category:    "observability",
		Description: "Quick CLI health insights for local vaults.",
		CLIActions:  []string{"observability", "obs"},
	},
	{
		ID:          "feat_secret-expiration",
		Name:        "Secret Expiration",
		Slug:        "secret-expiration",
		Category:    "secrets",
		Description: "Apply TTL-based clean-up on sensitive entries.",
	},
	{
		ID:          "feat_secret-metadata",
		Name:        "Secret Metadata",
		Slug:        "secret-metadata",
		Category:    "secrets",
		Description: "Tag secrets with custom properties and timestamps.",
	},
	{
		ID:          "feat_secret-password-protection",
		Name:        "Secret Password Protection",
		Slug:        "secret-password-protection",
		Category:    "secrets",
		Description: "Add passphrases to high-value secrets before viewing.",
		CLIActions:  []string{"secret-password", "password", "pw"},
		GUIActions:  []string{"password_protection"},
	},
	{
		ID:          "feat_security-policy",
		Name:        "Security Policy Configuration",
		Slug:        "security-policy",
		Category:    "security",
		Description: "Enforce org-wide security knobs for vault usage.",
		CLIActions:  []string{"security-policy", "sec-policy"},
		GUIActions:  []string{"security_policy"},
	},
	{
		ID:          "feat_vault-integrity",
		Name:        "Vault Integrity Verification",
		Slug:        "vault-integrity",
		Category:    "security",
		Description: "Run tamper checks and emergency vault locks.",
		CLIActions:  []string{"vault-security", "vsec"},
		GUIActions:  []string{"vault_lock"},
	},
	{
		ID:           "feat_ssh-connection-profiles",
		Name:         "SSH Connection Profiles",
		Slug:         "ssh-connection-profiles",
		Category:     "ssh",
		Description:  "Store SSH hosts, bastions, and terminal presets.",
		CLIActions:   []string{"ssh", "ssh-profile"},
		GUIActions:   []string{"ssh_profiles", "ssh_terminal"},
		APIEndpoints: []string{"ssh_profiles_get", "ssh_profiles_create", "ssh_profiles_delete", "ssh_profiles_list"},
	},

	// Solo
	{
		ID:           "feat_audit-logs",
		Name:         "Audit Logs",
		Slug:         "audit-logs",
		Category:     "audit",
		Description:  "Immutable, signed audit trails with filtering.",
		CLIActions:   []string{"audit", "audit-log"},
		GUIActions:   []string{"audit_log"},
		APIEndpoints: []string{"audit_query", "audit_stats"},
	},
	{
		ID:          "feat_file-tagging",
		Name:        "File Tagging & Properties",
		Slug:        "file-tagging",
		Category:    "files",
		Description: "Assign tags and inspect metadata before download.",
		GUIActions:  []string{"file_properties", "file_preview"},
	},
	{
		ID:          "feat_ec-ecdsa-keygen",
		Name:        "EC/ECDSA Keypair Generation",
		Slug:        "ec-ecdsa-keygen",
		Category:    "generators",
		Description: "Generate elliptic curve keypairs for TLS and SSH.",
	},
	{
		ID:          "feat_rsa-keygen",
		Name:        "RSA Keypair Generation",
		Slug:        "rsa-keygen",
		Category:    "generators",
		Description: "Generate up to 4096-bit RSA keypairs.",
	},
	{
		ID:          "feat_csv-tsv-import",
		Name:        "CSV/TSV Import",
		Slug:        "csv-tsv-import",
		Category:    "import_export",
		Description: "Bulk-import data from spreadsheets and CSV exports.",
	},
	{
		ID:          "feat_encrypted-scratchpads",
		Name:        "Encrypted Scratchpads",
		Slug:        "encrypted-scratchpads",
		Category:    "scratchpad",
		Description: "Secure temporary notes with TTLs and masking.",
		CLIActions:  []string{"scratchpad"},
		GUIActions:  []string{"scratchpad"},
	},
	{
		ID:           "feat_dynamic-secrets",
		Name:         "Dynamic Secrets",
		Slug:         "dynamic-secrets",
		Category:     "secrets",
		Description:  "Broker ephemeral DB and cloud credentials on demand.",
		CLIActions:   []string{"dynamic"},
		APIEndpoints: []string{"dynamic_database", "dynamic_cloud", "dynamic_verify"},
	},
	{
		ID:           "feat_secret-version-history",
		Name:         "Secret Version History",
		Slug:         "secret-version-history",
		Category:     "secrets",
		Description:  "List and roll back prior secret revisions.",
		CLIActions:   []string{"listkv", "rollbackkv"},
		APIEndpoints: []string{"kv_versions_list", "kv_rollback"},
	},
	{
		ID:          "feat_passkey-webauthn",
		Name:        "Passkey/WebAuthn Authentication",
		Slug:        "passkey-webauthn",
		Category:    "security",
		Description: "Guard sign-in with FIDO2/WebAuthn factors.",
		CLIActions:  []string{"enable-passkey", "disable-passkey"},
	},
	{
		ID:          "feat_password-reset-email",
		Name:        "Password Reset via Email",
		Slug:        "password-reset-email",
		Category:    "security",
		Description: "Allow SMTP-backed password reset flows.",
		CLIActions:  []string{"reset-password", "password-reset"},
	},
	{
		ID:          "feat_shamir-secret-sharing",
		Name:        "Shamir Secret Sharing",
		Slug:        "shamir-secret-sharing",
		Category:    "security",
		Description: "Split master keys into shares for recovery.",
		CLIActions:  []string{"shamir", "shamir-split", "shamir-combine"},
		GUIActions:  []string{"shamir_sharing"},
	},
	{
		ID:           "feat_two-factor-auth",
		Name:         "Two-Factor Authentication",
		Slug:         "two-factor-auth",
		Category:     "security",
		Description:  "Enable/disable TOTP and recovery codes per operator.",
		CLIActions:   []string{"enable-2fa", "disable-2fa"},
		GUIActions:   []string{"two_factor_auth"},
		APIEndpoints: []string{"2fa_status", "2fa_setup_start", "2fa_setup_verify", "2fa_verify", "2fa_disable", "2fa_backup_code"},
	},
	{
		ID:          "feat_ssh-bastion",
		Name:        "SSH Bastion/Jump Host",
		Slug:        "ssh-bastion",
		Category:    "ssh",
		Description: "Model bastions and jump hosts for layered SSH access.",
	},
	{
		ID:           "feat_x509-certificates",
		Name:         "X.509 Certificates",
		Slug:         "x509-certificates",
		Category:     "ssh",
		Description:  "Sign and verify leaf certificates for services.",
		CLIActions:   []string{"certificate", "sign", "verify"},
		GUIActions:   []string{"sign_data", "verify_signature"},
		APIEndpoints: []string{"certificate_generate"},
	},

	// Professional
	{
		ID:          "feat_vault-compaction",
		Name:        "Vault Storage Compaction",
		Slug:        "vault-compaction",
		Category:    "core",
		Description: "Defragment and compact vault storage for long-lived nodes.",
		CLIActions:  []string{"compact", "vault-compact"},
	},
	{
		ID:          "feat_file-export-restrictions",
		Name:        "File Export Restrictions",
		Slug:        "file-export-restrictions",
		Category:    "files",
		Description: "Restrict downloads and egress per workspace.",
	},
	{
		ID:          "feat_bundle-management",
		Name:        "Bundle Management",
		Slug:        "bundle-management",
		Category:    "import_export",
		Description: "Maintain encrypted bundles for migrations and handoffs.",
	},
	{
		ID:          "feat_rotation-policies",
		Name:        "Rotation Policies",
		Slug:        "rotation-policies",
		Category:    "rotation",
		Description: "Define rotation cadences with audit-ready history.",
		CLIActions:  []string{"rotate"},
		GUIActions:  []string{"rotation"},
	},
	{
		ID:          "feat_namespace-organization",
		Name:        "Namespace Organization",
		Slug:        "namespace-organization",
		Category:    "secrets",
		Description: "Segment vaults via namespaces for large teams.",
	},
	{
		ID:          "feat_emergency-vault-wipe",
		Name:        "Emergency Vault Wipe",
		Slug:        "emergency-vault-wipe",
		Category:    "security",
		Description: "Execute DoD-style wipes triggered by policy.",
		CLIActions:  []string{"wipe", "emergency-wipe"},
		GUIActions:  []string{"emergency_wipe"},
	},
	{
		ID:          "feat_process-allowlisting",
		Name:        "Process Allowlisting",
		Slug:        "process-allowlisting",
		Category:    "security",
		Description: "Limit vault integrations to approved binaries.",
	},
	{
		ID:          "feat_tampering-detection",
		Name:        "Tampering Detection",
		Slug:        "tampering-detection",
		Category:    "security",
		Description: "Monitor for tamper events and trigger mitigations.",
	},
	{
		ID:          "feat_p2p-sharing",
		Name:        "P2P Sharing",
		Slug:        "p2p-sharing",
		Category:    "sharing",
		Description: "LAN-based encrypted sharing flows for secrets/files.",
		CLIActions:  []string{"p2p-share", "p2p"},
		GUIActions:  []string{"p2p_share", "p2p_discover", "p2p_receive"},
	},
	{
		ID:          "feat_secret-templates",
		Name:        "Secret Templates",
		Slug:        "secret-templates",
		Category:    "templates",
		Description: "Blueprints for DB creds, API tokens, and cloud configs.",
		CLIActions:  []string{"template"},
		GUIActions:  []string{"templates"},
	},

	// Team
	{
		ID:          "feat_backup-replication",
		Name:        "Backup Replication",
		Slug:        "backup-replication",
		Category:    "backup",
		Description: "Replicate encrypted backups across regions.",
	},
	{
		ID:          "feat_scheduled-backups",
		Name:        "Scheduled Backups",
		Slug:        "scheduled-backups",
		Category:    "backup",
		Description: "Automate backups on defined cadences.",
		CLIActions:  []string{"backup"},
		GUIActions:  []string{"backup_restore"},
	},
	{
		ID:           "feat_prometheus-metrics",
		Name:         "Prometheus Metrics",
		Slug:         "prometheus-metrics",
		Category:     "observability",
		Description:  "Expose Prometheus-friendly metrics endpoints.",
		APIEndpoints: []string{"metrics"},
	},
	{
		ID:          "feat_advanced-rotation",
		Name:        "Advanced Rotation",
		Slug:        "advanced-rotation",
		Category:    "rotation",
		Description: "Dual-key overlaps and automated rotation hooks.",
	},
	{
		ID:          "feat_access-control",
		Name:        "Access Control (ACL)",
		Slug:        "access-control",
		Category:    "security",
		Description: "Fine-grained, ACL-based shared secret governance.",
		CLIActions:  []string{"share", "share grant", "share revoke", "share list", "enable-share-prompts"},
	},
	{
		ID:           "feat_api-health",
		Name:         "API Health Endpoints",
		Slug:         "api-health",
		Category:     "server",
		Description:  "Expose /healthz and /readyz endpoints.",
		APIEndpoints: []string{"healthz", "readyz"},
	},
	{
		ID:          "feat_http-api-server",
		Name:        "HTTP API Server",
		Slug:        "http-api-server",
		Category:    "server",
		Description: "Enable JSON API, rate limits, and service mode.",
		CLIActions:  []string{"server", "kds", "server-config"},
	},
	{
		ID:          "feat_share-link-generation",
		Name:        "Share Link Generation",
		Slug:        "share-link-generation",
		Category:    "sharing",
		Description: "Create time-bound share links for external partners.",
		CLIActions:  []string{"share link", "share link create", "share link list", "share link revoke", "share link redeem"},
		GUIActions:  []string{"share_link"},
	},
	{
		ID:          "feat_share-request-approval",
		Name:        "Share Request/Approval",
		Slug:        "share-request-approval",
		Category:    "sharing",
		Description: "Handle approvals within the admin experience.",
		CLIActions:  []string{"share request", "share approve", "share deny", "share requests", "share notifications"},
		GUIActions:  []string{"share_requests", "share_approvals"},
	},
	{
		ID:           "feat_tenant-management",
		Name:         "Tenant Management",
		Slug:         "tenant-management",
		Category:     "tenants",
		Description:  "CRUD operations for per-tenant isolation keys.",
		CLIActions:   []string{"tenant"},
		APIEndpoints: []string{"tenants_add", "tenants_list", "tenants_setkey", "tenants_getkey", "tenants_set_secret", "tenants_get_secret"},
	},
	{
		ID:           "feat_session-management",
		Name:         "Session Management",
		Slug:         "session-management",
		Category:     "user_management",
		Description:  "Audit and revoke active user sessions.",
		APIEndpoints: []string{"auth_login", "auth_sessions_list", "auth_sessions_revoke"},
	},
	{
		ID:           "feat_user-management",
		Name:         "User Management",
		Slug:         "user-management",
		Category:     "user_management",
		Description:  "Full CRUD APIs for admin, writer, and reader roles.",
		APIEndpoints: []string{"users_scopes_list", "users_list", "users_create", "users_get", "users_update", "users_delete", "users_apikeys_list", "users_apikeys_create", "users_apikeys_get", "users_apikeys_update", "users_apikeys_revoke"},
	},

	// Startup
	{
		ID:          "feat_data-retention",
		Name:        "Data Retention",
		Slug:        "data-retention",
		Category:    "compliance",
		Description: "Automate retention enforcement with crypto erase.",
		CLIActions:  []string{"retention", "ret"},
		GUIActions:  []string{"data_retention"},
	},
	{
		ID:          "feat_config-file-injection",
		Name:        "Config File Injection",
		Slug:        "config-file-injection",
		Category:    "container",
		Description: "Inject secrets into config templates at runtime.",
		CLIActions:  []string{"inject", "config-inject"},
	},
	{
		ID:          "feat_secure-sandbox",
		Name:        "Secure Sandbox",
		Slug:        "secure-sandbox",
		Category:    "container",
		Description: "Execute commands with isolated secret injection.",
		CLIActions:  []string{"sandbox", "secure-sandbox", "ssb"},
	},
	{
		ID:           "feat_response-wrapping",
		Name:         "Response Wrapping",
		Slug:         "response-wrapping",
		Category:     "secrets",
		Description:  "Wrap API responses for secure handoffs.",
		APIEndpoints: []string{"wrap_response", "unwrap_response"},
	},
	{
		ID:           "feat_secret-engines",
		Name:         "Secret Engines",
		Slug:         "secret-engines",
		Category:     "secrets",
		Description:  "Transit encryption/decryption and dynamic tokens.",
		APIEndpoints: []string{"transit_encrypt", "transit_decrypt", "wrap_response", "unwrap_response"},
	},
	{
		ID:          "feat_iam-policy-engine",
		Name:        "IAM Policy Engine",
		Slug:        "iam-policy-engine",
		Category:    "security",
		Description: "Advanced policy evaluation for service accounts.",
	},
	{
		ID:          "feat_mutual-tls",
		Name:        "Mutual TLS (mTLS)",
		Slug:        "mutual-tls",
		Category:    "security",
		Description: "Require client certificates for service mode.",
	},
	{
		ID:          "feat_security-levels",
		Name:        "Security Levels",
		Slug:        "security-levels",
		Category:    "security",
		Description: "Predefined hardening profiles (basic → isolated).",
	},
	{
		ID:          "feat_threat-model-handlers",
		Name:        "Threat Model Handlers",
		Slug:        "threat-model-handlers",
		Category:    "security",
		Description: "Automated mitigations for the top ten threat vectors.",
	},
	{
		ID:          "feat_multi-tenant-support",
		Name:        "Multi-Tenant Support",
		Slug:        "multi-tenant-support",
		Category:    "tenants",
		Description: "Hard isolation with tenant-scoped exports and admins.",
	},

	// Enterprise
	{
		ID:           "feat_enhanced-audit-logs",
		Name:         "Enhanced Audit Logs",
		Slug:         "enhanced-audit-logs",
		Category:     "audit",
		Description:  "Export-ready, compliance-specific audit bundles.",
		CLIActions:   []string{"audit-export", "audit-advanced"},
		GUIActions:   []string{"enhanced_audit"},
		APIEndpoints: []string{"audit_export", "audit_full"},
	},
	{
		ID:          "feat_disaster-recovery",
		Name:        "Disaster Recovery",
		Slug:        "disaster-recovery",
		Category:    "backup",
		Description: "Failover playbooks and recovery automation.",
		CLIActions:  []string{"dr", "disaster-recovery"},
		GUIActions:  []string{"disaster_recovery"},
	},
	{
		ID:          "feat_access-review",
		Name:        "Access Review",
		Slug:        "access-review",
		Category:    "compliance",
		Description: "Quarterly/annual access certifications.",
		CLIActions:  []string{"access-review", "ar", "access-reviews"},
		GUIActions:  []string{"access_reviews"},
	},
	{
		ID:          "feat_breach-management",
		Name:        "Breach Management",
		Slug:        "breach-management",
		Category:    "compliance",
		Description: "Track breaches, severity, and notifications.",
		CLIActions:  []string{"breach", "breach-notification"},
		GUIActions:  []string{"breach_notification"},
	},
	{
		ID:          "feat_compliance-frameworks",
		Name:        "Compliance Frameworks",
		Slug:        "compliance-frameworks",
		Category:    "compliance",
		Description: "SOC2, PCI, HIPAA, GDPR, ISO workflows.",
		CLIActions:  []string{"compliance", "comp"},
		GUIActions:  []string{"compliance_dashboard"},
	},
	{
		ID:          "feat_data-classification",
		Name:        "Data Classification",
		Slug:        "data-classification",
		Category:    "compliance",
		Description: "Auto/manual classification with reporting.",
		CLIActions:  []string{"classify", "data-classification", "dc"},
		GUIActions:  []string{"data_classification"},
	},
	{
		ID:          "feat_fips-mode",
		Name:        "FIPS 140-2/140-3 Mode",
		Slug:        "fips-mode",
		Category:    "compliance",
		Description: "Run vault operations with FIPS-validated crypto.",
		CLIActions:  []string{"fips", "fips-140"},
		GUIActions:  []string{"fips_compliance"},
	},
	{
		ID:          "feat_container-isolation",
		Name:        "Container Isolation",
		Slug:        "container-isolation",
		Category:    "container",
		Description: "Namespace isolation and hardened runtime defaults.",
		CLIActions:  []string{"isolation", "container-isolate"},
	},
	{
		ID:          "feat_container-registry",
		Name:        "Container Registry",
		Slug:        "container-registry",
		Category:    "container",
		Description: "Manage hardened container releases inside Secretr.",
		CLIActions:  []string{"registry", "cr-registry"},
	},
	{
		ID:          "feat_container-runtime",
		Name:        "Container Runtime",
		Slug:        "container-runtime",
		Category:    "container",
		Description: "Run secrets-aware workloads in secure containers.",
		CLIActions:  []string{"container"},
	},
	{
		ID:          "feat_container-security-audit",
		Name:        "Container Security Audit",
		Slug:        "container-security-audit",
		Category:    "container",
		Description: "Audit containers for drift, syscalls, and compliance.",
		CLIActions:  []string{"container-audit", "csa"},
	},
	{
		ID:          "feat_priority-support",
		Name:        "Priority Support",
		Slug:        "priority-support",
		Category:    "core",
		Description: "Escalated SLAs and dedicated support engineers.",
	},
	{
		ID:          "feat_hsm-integration",
		Name:        "HSM Integration",
		Slug:        "hsm-integration",
		Category:    "security",
		Description: "Back signing keys with external HSM providers.",
	},
	{
		ID:           "feat_managed-encryption-keys",
		Name:         "Managed Encryption Keys",
		Slug:         "managed-encryption-keys",
		Category:     "security",
		Description:  "Lifecycle management for organization-managed CMKs.",
		APIEndpoints: []string{"managed_keys", "cmek"},
	},
	{
		ID:          "feat_penetration-testing-tools",
		Name:        "Penetration Testing Tools",
		Slug:        "penetration-testing-tools",
		Category:    "security",
		Description: "Embed pentest and security scanning automations.",
		CLIActions:  []string{"pentest", "security-scan"},
	},
	{
		ID:           "feat_sso-integration",
		Name:         "SSO Integration",
		Slug:         "sso-integration",
		Category:     "security",
		Description:  "SAML and OIDC single-sign-on providers.",
		GUIActions:   []string{"sso_settings"},
		APIEndpoints: []string{"sso_saml", "sso_oidc"},
	},
	{
		ID:           "feat_transit-encryption",
		Name:         "Transit Encryption",
		Slug:         "transit-encryption",
		Category:     "security",
		Description:  "Expose transit encrypt/decrypt APIs for workloads.",
		APIEndpoints: []string{"transit_encrypt", "transit_decrypt"},
	},
}

// BootstrapSecretrProduct ensures the Secretr product, plans, features, and
// plan-feature mappings exist inside the configured storage backend.
func BootstrapSecretrProduct(ctx context.Context, storage Storage) (*SecretrCatalogSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	product := &Product{
		ID:          secretrProductID,
		Name:        "Secretr",
		Slug:        secretrProductSlug,
		Description: "Local-first, offline-capable secret management suite",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	persistedProduct, err := upsertProduct(ctx, storage, product)
	if err != nil {
		return nil, fmt.Errorf("bootstrap product: %w", err)
	}

	featureMap, err := seedSecretrFeatures(ctx, storage, persistedProduct.ID, now)
	if err != nil {
		return nil, fmt.Errorf("bootstrap features: %w", err)
	}

	planMap, err := seedSecretrPlans(ctx, storage, persistedProduct, featureMap, now)
	if err != nil {
		return nil, fmt.Errorf("bootstrap plans: %w", err)
	}

	// Build snapshot for callers
	snapshot := &SecretrCatalogSnapshot{
		Product:  cloneProduct(persistedProduct),
		Plans:    make(map[string]*Plan, len(planMap)),
		Features: make(map[string]*Feature, len(featureMap)),
	}
	for slug, plan := range planMap {
		snapshot.Plans[slug] = clonePlan(plan)
	}
	for slug, feature := range featureMap {
		snapshot.Features[slug] = cloneFeature(feature)
	}

	return snapshot, nil
}

func seedSecretrFeatures(ctx context.Context, storage Storage, productID string, ts time.Time) (map[string]*Feature, error) {
	result := make(map[string]*Feature, len(secretrFeatureCatalog))
	for _, def := range secretrFeatureCatalog {
		feature := &Feature{
			ID:          def.ID,
			ProductID:   productID,
			Name:        def.Name,
			Slug:        def.Slug,
			Description: def.Description,
			Category:    def.Category,
			CreatedAt:   ts,
			UpdatedAt:   ts,
		}
		persisted, err := upsertFeature(ctx, storage, feature)
		if err != nil {
			return nil, err
		}
		result[def.Slug] = persisted

		scopes := buildScopeDefinitions(def, persisted.ID, ts)
		for _, scope := range scopes {
			if err := upsertFeatureScope(ctx, storage, scope); err != nil {
				return nil, err
			}
		}
	}
	return result, nil
}

func seedSecretrPlans(ctx context.Context, storage Storage, product *Product, featureMap map[string]*Feature, ts time.Time) (map[string]*Plan, error) {
	accumulatedFeatures := buildSecretrPlanFeatureSets()
	planSnapshot := make(map[string]*Plan)

	for _, def := range secretrPlanDefinitions {
		plan := &Plan{
			ID:           def.ID,
			ProductID:    product.ID,
			Name:         def.Name,
			Slug:         def.Slug,
			Description:  def.Description,
			Price:        def.Price,
			Currency:     "USD",
			BillingCycle: def.BillingCycle,
			TrialDays:    def.TrialDays,
			IsTrial:      def.IsTrial,
			IsActive:     def.IsActive,
			DisplayOrder: def.DisplayOrder,
			Metadata:     copyStringMap(def.Metadata),
			CreatedAt:    ts,
			UpdatedAt:    ts,
		}

		persistedPlan, err := upsertPlan(ctx, storage, plan)
		if err != nil {
			return nil, err
		}
		planSnapshot[persistedPlan.Slug] = persistedPlan

		featureSlugs := accumulatedFeatures[persistedPlan.Slug]
		if persistedPlan.IsTrial {
			featureSlugs = accumulatedFeatures["personal"]
		}
		if len(featureSlugs) == 0 {
			continue
		}

		if err := ensurePlanFeatures(ctx, storage, persistedPlan, featureSlugs, featureMap, ts); err != nil {
			return nil, err
		}
	}

	return planSnapshot, nil
}

func ensurePlanFeatures(ctx context.Context, storage Storage, plan *Plan, featureSlugs []string, featureMap map[string]*Feature, ts time.Time) error {
	for _, slug := range featureSlugs {
		feature, ok := featureMap[slug]
		if !ok {
			return fmt.Errorf("missing feature %s for plan %s", slug, plan.Slug)
		}
		pf := &PlanFeature{
			ID:        fmt.Sprintf("pf_%s_%s", plan.ID, feature.ID),
			PlanID:    plan.ID,
			FeatureID: feature.ID,
			Enabled:   true,
			CreatedAt: ts,
			UpdatedAt: ts,
		}
		if err := upsertPlanFeature(ctx, storage, pf); err != nil {
			return err
		}
	}
	return nil
}

func buildScopeDefinitions(def secretrFeatureDefinition, featureID string, ts time.Time) []*FeatureScope {
	channels := []struct {
		kind  scopeChannel
		items []string
	}{
		{scopeChannelCLI, def.CLIActions},
		{scopeChannelGUI, def.GUIActions},
		{scopeChannelAPI, def.APIEndpoints},
	}

	scopes := make([]*FeatureScope, 0, len(channels))
	for _, ch := range channels {
		if len(ch.items) == 0 {
			continue
		}
		metadata := map[string]string{
			"channel": string(ch.kind),
			"items":   strings.Join(ch.items, ","),
		}
		scope := &FeatureScope{
			ID:         fmt.Sprintf("scope_%s_%s", def.Slug, ch.kind),
			FeatureID:  featureID,
			Name:       fmt.Sprintf("%s Access", strings.ToUpper(string(ch.kind))),
			Slug:       string(ch.kind),
			Permission: ScopePermissionAllow,
			Metadata:   metadata,
			CreatedAt:  ts,
			UpdatedAt:  ts,
		}
		scopes = append(scopes, scope)
	}

	// Ensure deterministic order to keep plan diff stable.
	sort.Slice(scopes, func(i, j int) bool {
		return scopes[i].ID < scopes[j].ID
	})
	return scopes
}

func buildSecretrPlanFeatureSets() map[string][]string {
	result := make(map[string][]string)
	cumulative := append([]string{}, commonFeatureSlugs...)
	seen := make(map[string]struct{}, len(commonFeatureSlugs))
	for _, slug := range commonFeatureSlugs {
		seen[slug] = struct{}{}
	}

	for _, planSlug := range secretrPlanOrder {
		additions := secretrPlanFeatureAdditions[planSlug]
		for _, slug := range additions {
			if _, exists := seen[slug]; !exists {
				cumulative = append(cumulative, slug)
				seen[slug] = struct{}{}
			}
		}
		snapshot := append([]string(nil), cumulative...)
		result[planSlug] = snapshot
	}
	return result
}

func upsertProduct(ctx context.Context, storage Storage, desired *Product) (*Product, error) {
	existing, err := storage.GetProductBySlug(ctx, desired.Slug)
	if err == nil {
		updated := false
		if existing.Name != desired.Name {
			existing.Name = desired.Name
			updated = true
		}
		if desired.Description != "" && existing.Description != desired.Description {
			existing.Description = desired.Description
			updated = true
		}
		if desired.LogoURL != "" && existing.LogoURL != desired.LogoURL {
			existing.LogoURL = desired.LogoURL
			updated = true
		}
		if updated {
			existing.UpdatedAt = time.Now()
			if err := storage.UpdateProduct(ctx, existing); err != nil {
				return nil, err
			}
		}
		return existing, nil
	}
	if !errors.Is(err, errProductMissing) {
		return nil, err
	}
	if err := storage.SaveProduct(ctx, desired); err != nil {
		return nil, err
	}
	return desired, nil
}

func upsertPlan(ctx context.Context, storage Storage, desired *Plan) (*Plan, error) {
	existing, err := storage.GetPlanBySlug(ctx, desired.ProductID, desired.Slug)
	if err == nil {
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
		desired.UpdatedAt = time.Now()
		if desired.Metadata == nil {
			desired.Metadata = existing.Metadata
		}
		if err := storage.UpdatePlan(ctx, desired); err != nil {
			return nil, err
		}
		return desired, nil
	}
	if !errors.Is(err, errPlanMissing) {
		return nil, err
	}
	if err := storage.SavePlan(ctx, desired); err != nil {
		return nil, err
	}
	return desired, nil
}

func upsertFeature(ctx context.Context, storage Storage, desired *Feature) (*Feature, error) {
	existing, err := storage.GetFeatureBySlug(ctx, desired.ProductID, desired.Slug)
	if err == nil {
		desired.ID = existing.ID
		desired.CreatedAt = existing.CreatedAt
		desired.UpdatedAt = time.Now()
		if err := storage.UpdateFeature(ctx, desired); err != nil {
			return nil, err
		}
		return desired, nil
	}
	if !errors.Is(err, errFeatureMissing) {
		return nil, err
	}
	if err := storage.SaveFeature(ctx, desired); err != nil {
		return nil, err
	}
	return desired, nil
}

func upsertFeatureScope(ctx context.Context, storage Storage, desired *FeatureScope) error {
	if err := storage.SaveFeatureScope(ctx, desired); err != nil {
		if errors.Is(err, errFeatureScopeExists) {
			existing, getErr := storage.GetFeatureScope(ctx, desired.ID)
			if getErr != nil {
				return getErr
			}
			desired.CreatedAt = existing.CreatedAt
			desired.UpdatedAt = time.Now()
			return storage.UpdateFeatureScope(ctx, desired)
		}
		return err
	}
	return nil
}

func upsertPlanFeature(ctx context.Context, storage Storage, desired *PlanFeature) error {
	if err := storage.SavePlanFeature(ctx, desired); err != nil {
		if errors.Is(err, errPlanFeatureExists) {
			existing, getErr := storage.GetPlanFeature(ctx, desired.PlanID, desired.FeatureID)
			if getErr != nil {
				return getErr
			}
			existing.Enabled = desired.Enabled
			existing.ScopeOverrides = desired.ScopeOverrides
			existing.UpdatedAt = time.Now()
			return storage.UpdatePlanFeature(ctx, existing)
		}
		return err
	}
	return nil
}

func copyStringMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	dup := make(map[string]string, len(input))
	for k, v := range input {
		dup[k] = v
	}
	return dup
}
