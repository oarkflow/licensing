package licensing

import (
	"context"
	"errors"
	"fmt"
	"sort"
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

// ==================== Plan Definitions ====================
// Based on PLANS.md pricing structure

type secretrPlanDefinition struct {
	ID             string
	Name           string
	Slug           string
	Description    string
	PricePerDevice int64  // cents per device per year
	MinDevices     int    // minimum devices required
	StorageLimit   string // storage limit description
	BillingCycle   string
	TrialDays      int
	IsTrial        bool
	DisplayOrder   int
	IsActive       bool
}

var secretrPlanDefinitions = []secretrPlanDefinition{
	{
		ID:             "plan_secretr_trial",
		Name:           "Trial",
		Slug:           "trial",
		Description:    "7-day full Personal experience for evaluations",
		PricePerDevice: 0,
		MinDevices:     1,
		StorageLimit:   "500 MB",
		BillingCycle:   "trial",
		TrialDays:      defaultTrialDays,
		IsTrial:        true,
		DisplayOrder:   0,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_personal",
		Name:           "Personal",
		Slug:           "personal",
		Description:    "Best for: Individual developers managing personal secrets",
		PricePerDevice: 1900, // $19/device/year
		MinDevices:     1,
		StorageLimit:   "500 MB",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   1,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_solo",
		Name:           "Solo",
		Slug:           "solo",
		Description:    "Best for: Power users and freelancers with multiple workstations",
		PricePerDevice: 4900, // $49/device/year
		MinDevices:     3,
		StorageLimit:   "2 GB",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   2,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_professional",
		Name:           "Professional",
		Slug:           "professional",
		Description:    "Best for: Small teams collaborating on projects",
		PricePerDevice: 9900, // $99/device/year
		MinDevices:     10,
		StorageLimit:   "5 GB",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   3,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_team",
		Name:           "Team",
		Slug:           "team",
		Description:    "Best for: Growing organizations with centralized secret management needs",
		PricePerDevice: 14900, // $149/device/year
		MinDevices:     25,
		StorageLimit:   "10 GB",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   4,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_startup",
		Name:           "Startup",
		Slug:           "startup",
		Description:    "Best for: Fast-growing companies with security-first culture",
		PricePerDevice: 24900, // $249/device/year
		MinDevices:     50,
		StorageLimit:   "Unlimited",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   5,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_enterprise",
		Name:           "Enterprise",
		Slug:           "enterprise",
		Description:    "Best for: Organizations with strict compliance and governance requirements",
		PricePerDevice: 0, // Custom pricing - contact sales
		MinDevices:     50,
		StorageLimit:   "Unlimited",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   6,
		IsActive:       true,
	},
}

// Plan tier order for cumulative feature inheritance
var secretrPlanOrder = []string{"personal", "solo", "professional", "team", "startup", "enterprise"}

// ==================== Feature Definitions ====================
// Based on ENTITLEMENT_SCOPES.md - 3 main features: CLI, GUI, API

type secretrFeatureDefinition struct {
	ID          string
	Name        string
	Slug        string
	Category    string
	Description string
	Scopes      []secretrScopeDefinition
}

type secretrScopeDefinition struct {
	ID          string
	Name        string
	Slug        string
	Description string
	// Plan restrictions: maps plan slug to permission (allow/deny)
	// If not specified, defaults to "allow"
	PlanRestrictions map[string]ScopePermission
}

// Scope permission constants for plan restrictions
const (
	permAllow = ScopePermissionAllow
	permDeny  = ScopePermissionDeny
)

// Helper to create restriction maps
func denyBefore(planSlug string) map[string]ScopePermission {
	order := map[string]int{
		"personal":     0,
		"solo":         1,
		"professional": 2,
		"team":         3,
		"startup":      4,
		"enterprise":   5,
	}
	threshold := order[planSlug]
	result := make(map[string]ScopePermission)
	for plan, idx := range order {
		if idx < threshold {
			result[plan] = permDeny
		}
	}
	return result
}

func enterpriseOnly() map[string]ScopePermission {
	return map[string]ScopePermission{
		"personal":     permDeny,
		"solo":         permDeny,
		"professional": permDeny,
		"team":         permDeny,
		"startup":      permDeny,
	}
}

func startupAndUp() map[string]ScopePermission {
	return denyBefore("startup")
}

func teamAndUp() map[string]ScopePermission {
	return denyBefore("team")
}

func professionalAndUp() map[string]ScopePermission {
	return denyBefore("professional")
}

func soloAndUp() map[string]ScopePermission {
	return denyBefore("solo")
}

// CLI Feature with all 71 scopes from ENTITLEMENT_SCOPES.md
var cliFeature = secretrFeatureDefinition{
	ID:          "feat_cli_001",
	Name:        "CLI",
	Slug:        "cli",
	Category:    "interface",
	Description: "Command-line interface access for Secretr operations",
	Scopes: []secretrScopeDefinition{
		// Basic Operations (All Plans)
		{ID: "cli_s001", Name: "Get Secret", Slug: "get", Description: "Get a secret value"},
		{ID: "cli_s002", Name: "Set Secret", Slug: "set", Description: "Set a secret value"},
		{ID: "cli_s003", Name: "List Secrets", Slug: "list", Description: "List all secrets"},
		{ID: "cli_s004", Name: "Delete Secret", Slug: "delete", Description: "Delete a secret"},
		{ID: "cli_s005", Name: "Copy Secret", Slug: "copy", Description: "Copy secret to clipboard"},
		{ID: "cli_s006", Name: "Secret Password", Slug: "secret-password", Description: "Manage secret passwords"},

		// SSH Management (All Plans)
		{ID: "cli_s007", Name: "SSH", Slug: "ssh", Description: "SSH operations"},
		{ID: "cli_s008", Name: "SSH Key", Slug: "ssh-key", Description: "Manage SSH keys"},
		{ID: "cli_s009", Name: "SSH Profile", Slug: "ssh-profile", Description: "Manage SSH profiles"},

		// File Management (All Plans)
		{ID: "cli_s010", Name: "Files", Slug: "files", Description: "File vault operations"},

		// Sharing & Collaboration (Professional+)
		{ID: "cli_s011", Name: "Share", Slug: "share", Description: "Share secrets", PlanRestrictions: professionalAndUp()},
		{ID: "cli_s012", Name: "P2P Share", Slug: "p2p-share", Description: "P2P sharing on LAN", PlanRestrictions: professionalAndUp()},
		{ID: "cli_s013", Name: "P2P", Slug: "p2p", Description: "P2P operations", PlanRestrictions: professionalAndUp()},

		// Container Security (Enterprise only)
		{ID: "cli_s014", Name: "Container", Slug: "container", Description: "Container operations", PlanRestrictions: enterpriseOnly()},

		// Backup & Recovery (All Plans)
		{ID: "cli_s015", Name: "Backup", Slug: "backup", Description: "Backup operations"},
		{ID: "cli_s016", Name: "Export", Slug: "export", Description: "Export data"},
		{ID: "cli_s017", Name: "Import", Slug: "import", Description: "Import data"},

		// Generators (Personal+)
		{ID: "cli_s018", Name: "Generate JWT", Slug: "gen-jwt", Description: "Generate JWT secrets"},
		{ID: "cli_s019", Name: "Generate API Key", Slug: "gen-apikey", Description: "Generate API keys"},
		{ID: "cli_s020", Name: "Generate Keypair", Slug: "gen-keypair", Description: "Generate keypairs"},
		{ID: "cli_s021", Name: "Generate Symmetric Key", Slug: "gen-symkey", Description: "Generate symmetric keys"},
		{ID: "cli_s022", Name: "Dynamic Secrets", Slug: "dynamic", Description: "Dynamic secret generation", PlanRestrictions: soloAndUp()},

		// Templates (Professional+)
		{ID: "cli_s023", Name: "Template", Slug: "template", Description: "Secret templates", PlanRestrictions: professionalAndUp()},

		// Secret Rotation (Professional+)
		{ID: "cli_s024", Name: "Rotate", Slug: "rotate", Description: "Secret rotation", PlanRestrictions: professionalAndUp()},

		// Tenant Management (Team+)
		{ID: "cli_s025", Name: "Tenant", Slug: "tenant", Description: "Tenant management", PlanRestrictions: teamAndUp()},

		// Import/Export Advanced (All Plans)
		{ID: "cli_s026", Name: "From File", Slug: "from-file", Description: "Import from file"},
		{ID: "cli_s027", Name: "To File", Slug: "to-file", Description: "Export to file"},
		{ID: "cli_s028", Name: "Pull", Slug: "pull", Description: "Pull secrets"},
		{ID: "cli_s029", Name: "Push", Slug: "push", Description: "Push secrets"},
		{ID: "cli_s030", Name: "Server Export", Slug: "server-export", Description: "Server export operations"},

		// Scratchpad (Solo+)
		{ID: "cli_s031", Name: "Scratchpad", Slug: "scratchpad", Description: "Encrypted scratchpads", PlanRestrictions: soloAndUp()},

		// Environment (All Plans)
		{ID: "cli_s032", Name: "Print Env", Slug: "printenv", Description: "Print environment variables"},
		{ID: "cli_s033", Name: "Env", Slug: "env", Description: "Environment operations"},
		{ID: "cli_s034", Name: "Enrich", Slug: "enrich", Description: "Enrich process environment"},

		// Cryptography (All Plans)
		{ID: "cli_s035", Name: "Certificate", Slug: "certificate", Description: "Certificate operations"},
		{ID: "cli_s036", Name: "Sign", Slug: "sign", Description: "Sign data"},
		{ID: "cli_s037", Name: "Verify", Slug: "verify", Description: "Verify signatures"},
		{ID: "cli_s038", Name: "Hash", Slug: "hash", Description: "Hash operations"},

		// Versioning (Solo+)
		{ID: "cli_s039", Name: "List KV Versions", Slug: "listkv", Description: "List KV versions", PlanRestrictions: soloAndUp()},
		{ID: "cli_s040", Name: "Rollback KV", Slug: "rollbackkv", Description: "Rollback KV versions", PlanRestrictions: soloAndUp()},

		// Security Sandbox (Startup+)
		{ID: "cli_s041", Name: "Sandbox", Slug: "sandbox", Description: "Sandbox execution", PlanRestrictions: startupAndUp()},
		{ID: "cli_s042", Name: "Secure Sandbox", Slug: "secure-sandbox", Description: "Secure sandbox execution", PlanRestrictions: startupAndUp()},
		{ID: "cli_s043", Name: "SSB", Slug: "ssb", Description: "Secure sandbox shorthand", PlanRestrictions: startupAndUp()},

		// Security Policy (Personal+)
		{ID: "cli_s044", Name: "Security Policy", Slug: "security-policy", Description: "Security policy configuration"},
		{ID: "cli_s045", Name: "Sec Policy", Slug: "sec-policy", Description: "Security policy shorthand"},

		// Vault Security (Personal+)
		{ID: "cli_s046", Name: "Vault Security", Slug: "vault-security", Description: "Vault security operations"},
		{ID: "cli_s047", Name: "VSec", Slug: "vsec", Description: "Vault security shorthand"},

		// Observability (Personal+)
		{ID: "cli_s048", Name: "Observability", Slug: "observability", Description: "Observability commands"},
		{ID: "cli_s049", Name: "Obs", Slug: "obs", Description: "Observability shorthand"},

		// FIPS Compliance (Enterprise only)
		{ID: "cli_s050", Name: "FIPS", Slug: "fips", Description: "FIPS mode operations", PlanRestrictions: enterpriseOnly()},
		{ID: "cli_s051", Name: "FIPS-140", Slug: "fips-140", Description: "FIPS 140 compliance", PlanRestrictions: enterpriseOnly()},

		// Compliance Frameworks (Enterprise only)
		{ID: "cli_s052", Name: "Compliance", Slug: "compliance", Description: "Compliance framework operations", PlanRestrictions: enterpriseOnly()},
		{ID: "cli_s053", Name: "Comp", Slug: "comp", Description: "Compliance shorthand", PlanRestrictions: enterpriseOnly()},

		// Data Classification (Enterprise only)
		{ID: "cli_s054", Name: "Classify", Slug: "classify", Description: "Data classification", PlanRestrictions: enterpriseOnly()},
		{ID: "cli_s055", Name: "Data Classification", Slug: "data-classification", Description: "Data classification full", PlanRestrictions: enterpriseOnly()},
		{ID: "cli_s056", Name: "DC", Slug: "dc", Description: "Data classification shorthand", PlanRestrictions: enterpriseOnly()},

		// Data Retention (Startup+)
		{ID: "cli_s057", Name: "Retention", Slug: "retention", Description: "Data retention policies", PlanRestrictions: startupAndUp()},
		{ID: "cli_s058", Name: "Ret", Slug: "ret", Description: "Retention shorthand", PlanRestrictions: startupAndUp()},

		// Breach Management (Enterprise only)
		{ID: "cli_s059", Name: "Breach", Slug: "breach", Description: "Breach management", PlanRestrictions: enterpriseOnly()},
		{ID: "cli_s060", Name: "Breach Notification", Slug: "breach-notification", Description: "Breach notifications", PlanRestrictions: enterpriseOnly()},

		// Access Review (Enterprise only)
		{ID: "cli_s061", Name: "Access Review", Slug: "access-review", Description: "Access review workflow", PlanRestrictions: enterpriseOnly()},
		{ID: "cli_s062", Name: "AR", Slug: "ar", Description: "Access review shorthand", PlanRestrictions: enterpriseOnly()},
		{ID: "cli_s063", Name: "Access Reviews", Slug: "access-reviews", Description: "Access reviews list", PlanRestrictions: enterpriseOnly()},

		// Authentication (Solo+)
		{ID: "cli_s064", Name: "Enable 2FA", Slug: "enable-2fa", Description: "Enable two-factor auth", PlanRestrictions: soloAndUp()},
		{ID: "cli_s065", Name: "Disable 2FA", Slug: "disable-2fa", Description: "Disable two-factor auth", PlanRestrictions: soloAndUp()},
		{ID: "cli_s066", Name: "Enable Passkey", Slug: "enable-passkey", Description: "Enable passkey auth", PlanRestrictions: soloAndUp()},
		{ID: "cli_s067", Name: "Disable Passkey", Slug: "disable-passkey", Description: "Disable passkey auth", PlanRestrictions: soloAndUp()},
		{ID: "cli_s068", Name: "Enable Share Prompts", Slug: "enable-share-prompts", Description: "Enable share prompts"},

		// System Commands (Team+)
		{ID: "cli_s069", Name: "Server", Slug: "server", Description: "Server mode operations", PlanRestrictions: teamAndUp()},
		{ID: "cli_s070", Name: "KDS", Slug: "kds", Description: "Key distribution server", PlanRestrictions: teamAndUp()},
		{ID: "cli_s071", Name: "Server Config", Slug: "server-config", Description: "Server configuration", PlanRestrictions: teamAndUp()},
	},
}

// GUI Feature with all 37 scopes from ENTITLEMENT_SCOPES.md
var guiFeature = secretrFeatureDefinition{
	ID:          "feat_gui_001",
	Name:        "GUI",
	Slug:        "gui",
	Category:    "interface",
	Description: "Desktop GUI application access",
	Scopes: []secretrScopeDefinition{
		// CRUD Operations (All Plans)
		{ID: "gui_s001", Name: "View", Slug: "view", Description: "View secrets and data"},
		{ID: "gui_s002", Name: "List", Slug: "list", Description: "List items"},
		{ID: "gui_s003", Name: "Create", Slug: "create", Description: "Create new items"},
		{ID: "gui_s004", Name: "Update", Slug: "update", Description: "Update existing items"},
		{ID: "gui_s005", Name: "Delete", Slug: "delete", Description: "Delete items"},
		{ID: "gui_s006", Name: "Edit", Slug: "edit", Description: "Edit items"},

		// Secret Management Views (All Plans)
		{ID: "gui_s007", Name: "Secret Manager", Slug: "secret_manager", Description: "Secret management interface"},
		{ID: "gui_s008", Name: "Secret Search", Slug: "secret_search", Description: "Search secrets"},
		{ID: "gui_s009", Name: "Secret Filter", Slug: "secret_filter", Description: "Filter secrets"},
		{ID: "gui_s010", Name: "Password Protection", Slug: "password_protection", Description: "Password protection for secrets"},

		// File Management Views (All Plans)
		{ID: "gui_s011", Name: "File Manager", Slug: "file_manager", Description: "File management interface"},
		{ID: "gui_s012", Name: "File Upload", Slug: "file_upload", Description: "Upload files"},
		{ID: "gui_s013", Name: "File Download", Slug: "file_download", Description: "Download files"},

		// Generator Views (All Plans)
		{ID: "gui_s014", Name: "Password Generator", Slug: "password_generator", Description: "Generate passwords"},
		{ID: "gui_s015", Name: "SSH Key Generator", Slug: "ssh_key_generator", Description: "Generate SSH keys"},
		{ID: "gui_s016", Name: "Certificate Generator", Slug: "certificate_generator", Description: "Generate certificates"},
		{ID: "gui_s017", Name: "Hash Generator", Slug: "hash_generator", Description: "Generate hashes"},

		// SSH Management Views (All Plans)
		{ID: "gui_s018", Name: "SSH Profiles", Slug: "ssh_profiles", Description: "SSH profile management"},
		{ID: "gui_s019", Name: "SSH Terminal", Slug: "ssh_terminal", Description: "SSH terminal interface"},
		{ID: "gui_s020", Name: "SSH Import", Slug: "ssh_import", Description: "Import SSH keys"},

		// P2P Sharing Views (Professional+)
		{ID: "gui_s021", Name: "P2P Share", Slug: "p2p_share", Description: "P2P sharing interface", PlanRestrictions: professionalAndUp()},
		{ID: "gui_s022", Name: "P2P Discover", Slug: "p2p_discover", Description: "Discover P2P peers", PlanRestrictions: professionalAndUp()},
		{ID: "gui_s023", Name: "P2P Receive", Slug: "p2p_receive", Description: "Receive P2P shares", PlanRestrictions: professionalAndUp()},

		// Cryptographic Operations Views (All Plans)
		{ID: "gui_s024", Name: "Sign Data", Slug: "sign_data", Description: "Data signing interface"},
		{ID: "gui_s025", Name: "Verify Signature", Slug: "verify_signature", Description: "Signature verification"},

		// Management Views
		{ID: "gui_s026", Name: "Templates", Slug: "templates", Description: "Template management", PlanRestrictions: professionalAndUp()},
		{ID: "gui_s027", Name: "Rotation", Slug: "rotation", Description: "Secret rotation management", PlanRestrictions: professionalAndUp()},
		{ID: "gui_s028", Name: "Backup Restore", Slug: "backup_restore", Description: "Backup and restore interface"},
		{ID: "gui_s029", Name: "Scratchpad", Slug: "scratchpad", Description: "Scratchpad interface", PlanRestrictions: soloAndUp()},

		// Compliance Views (Enterprise only)
		{ID: "gui_s030", Name: "Compliance Dashboard", Slug: "compliance_dashboard", Description: "Compliance dashboard", PlanRestrictions: enterpriseOnly()},
		{ID: "gui_s031", Name: "Data Classification", Slug: "data_classification", Description: "Data classification interface", PlanRestrictions: enterpriseOnly()},
		{ID: "gui_s032", Name: "Data Retention", Slug: "data_retention", Description: "Data retention interface", PlanRestrictions: startupAndUp()},
		{ID: "gui_s033", Name: "Breach Notification", Slug: "breach_notification", Description: "Breach notification interface", PlanRestrictions: enterpriseOnly()},
		{ID: "gui_s034", Name: "Access Reviews", Slug: "access_reviews", Description: "Access reviews interface", PlanRestrictions: enterpriseOnly()},
		{ID: "gui_s035", Name: "FIPS Compliance", Slug: "fips_compliance", Description: "FIPS compliance interface", PlanRestrictions: enterpriseOnly()},

		// Security Views (Solo+)
		{ID: "gui_s036", Name: "Two Factor Auth", Slug: "two_factor_auth", Description: "2FA management", PlanRestrictions: soloAndUp()},
		{ID: "gui_s037", Name: "Vault Lock", Slug: "vault_lock", Description: "Vault lock controls"},
	},
}

// API Feature with all 69 scopes from ENTITLEMENT_SCOPES.md
var apiFeature = secretrFeatureDefinition{
	ID:          "feat_api_001",
	Name:        "API",
	Slug:        "api",
	Category:    "integration",
	Description: "HTTP API access (requires Team+ plan)",
	Scopes: []secretrScopeDefinition{
		// Setup & Configuration (Team+)
		{ID: "api_s001", Name: "Setup Check", Slug: "setup_check", Description: "Check setup status", PlanRestrictions: teamAndUp()},
		{ID: "api_s002", Name: "Setup Complete", Slug: "setup_complete", Description: "Complete setup", PlanRestrictions: teamAndUp()},
		{ID: "api_s003", Name: "Admin Regenerate Key", Slug: "admin_regenerate_key", Description: "Regenerate admin key", PlanRestrictions: teamAndUp()},

		// Authentication (Team+)
		{ID: "api_s004", Name: "Auth Login", Slug: "auth_login", Description: "Authenticate user", PlanRestrictions: teamAndUp()},
		{ID: "api_s005", Name: "Auth Sessions List", Slug: "auth_sessions_list", Description: "List active sessions", PlanRestrictions: teamAndUp()},
		{ID: "api_s006", Name: "Auth Sessions Revoke", Slug: "auth_sessions_revoke", Description: "Revoke sessions", PlanRestrictions: teamAndUp()},

		// Two-Factor Authentication (Team+)
		{ID: "api_s007", Name: "2FA Status", Slug: "2fa_status", Description: "Get 2FA status", PlanRestrictions: teamAndUp()},
		{ID: "api_s008", Name: "2FA Setup Start", Slug: "2fa_setup_start", Description: "Start 2FA setup", PlanRestrictions: teamAndUp()},
		{ID: "api_s009", Name: "2FA Setup Verify", Slug: "2fa_setup_verify", Description: "Verify 2FA setup", PlanRestrictions: teamAndUp()},
		{ID: "api_s010", Name: "2FA Verify", Slug: "2fa_verify", Description: "Verify 2FA code", PlanRestrictions: teamAndUp()},
		{ID: "api_s011", Name: "2FA Disable", Slug: "2fa_disable", Description: "Disable 2FA", PlanRestrictions: teamAndUp()},
		{ID: "api_s012", Name: "2FA Backup Code", Slug: "2fa_backup_code", Description: "Get backup codes", PlanRestrictions: teamAndUp()},

		// Secrets Management (Team+)
		{ID: "api_s013", Name: "Secrets Read", Slug: "secrets_read", Description: "Read secrets via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s014", Name: "Secrets Write", Slug: "secrets_write", Description: "Write secrets via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s015", Name: "Secrets Delete", Slug: "secrets_delete", Description: "Delete secrets via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s016", Name: "Secrets List", Slug: "secrets_list", Description: "List secrets via API", PlanRestrictions: teamAndUp()},

		// KV Versioning (Team+)
		{ID: "api_s017", Name: "KV Versions List", Slug: "kv_versions_list", Description: "List KV versions", PlanRestrictions: teamAndUp()},
		{ID: "api_s018", Name: "KV Rollback", Slug: "kv_rollback", Description: "Rollback KV version", PlanRestrictions: teamAndUp()},

		// Transit Engine (Startup+)
		{ID: "api_s019", Name: "Transit Encrypt", Slug: "transit_encrypt", Description: "Transit encryption", PlanRestrictions: startupAndUp()},
		{ID: "api_s020", Name: "Transit Decrypt", Slug: "transit_decrypt", Description: "Transit decryption", PlanRestrictions: startupAndUp()},

		// Dynamic Engines (Startup+)
		{ID: "api_s021", Name: "Dynamic Database", Slug: "dynamic_database", Description: "Dynamic database credentials", PlanRestrictions: startupAndUp()},
		{ID: "api_s022", Name: "Dynamic Cloud", Slug: "dynamic_cloud", Description: "Dynamic cloud tokens", PlanRestrictions: startupAndUp()},
		{ID: "api_s023", Name: "Dynamic Verify", Slug: "dynamic_verify", Description: "Verify dynamic credentials", PlanRestrictions: startupAndUp()},

		// Response Wrapping (Startup+)
		{ID: "api_s024", Name: "Wrap Response", Slug: "wrap_response", Description: "Wrap API response", PlanRestrictions: startupAndUp()},
		{ID: "api_s025", Name: "Unwrap Response", Slug: "unwrap_response", Description: "Unwrap API response", PlanRestrictions: startupAndUp()},

		// File Management (Team+)
		{ID: "api_s026", Name: "Files List", Slug: "files_list", Description: "List files via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s027", Name: "Files Upload", Slug: "files_upload", Description: "Upload files via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s028", Name: "Files Download", Slug: "files_download", Description: "Download files via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s029", Name: "Files Delete", Slug: "files_delete", Description: "Delete files via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s030", Name: "Files Render", Slug: "files_render", Description: "Render files via API", PlanRestrictions: teamAndUp()},

		// SSH Management (Team+)
		{ID: "api_s031", Name: "SSH Keys Get", Slug: "ssh_keys_get", Description: "Get SSH keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s032", Name: "SSH Keys Create", Slug: "ssh_keys_create", Description: "Create SSH keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s033", Name: "SSH Keys Delete", Slug: "ssh_keys_delete", Description: "Delete SSH keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s034", Name: "SSH Keys List", Slug: "ssh_keys_list", Description: "List SSH keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s035", Name: "SSH Profiles Get", Slug: "ssh_profiles_get", Description: "Get SSH profiles", PlanRestrictions: teamAndUp()},
		{ID: "api_s036", Name: "SSH Profiles Create", Slug: "ssh_profiles_create", Description: "Create SSH profiles", PlanRestrictions: teamAndUp()},
		{ID: "api_s037", Name: "SSH Profiles Delete", Slug: "ssh_profiles_delete", Description: "Delete SSH profiles", PlanRestrictions: teamAndUp()},
		{ID: "api_s038", Name: "SSH Profiles List", Slug: "ssh_profiles_list", Description: "List SSH profiles", PlanRestrictions: teamAndUp()},

		// Certificate Management (Team+)
		{ID: "api_s039", Name: "Certificate Generate", Slug: "certificate_generate", Description: "Generate certificates", PlanRestrictions: teamAndUp()},

		// Key Generation (Team+)
		{ID: "api_s040", Name: "Generate JWT", Slug: "generate_jwt", Description: "Generate JWT secrets", PlanRestrictions: teamAndUp()},
		{ID: "api_s041", Name: "Generate API Key", Slug: "generate_apikey", Description: "Generate API keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s042", Name: "Generate Keypair", Slug: "generate_keypair", Description: "Generate keypairs", PlanRestrictions: teamAndUp()},
		{ID: "api_s043", Name: "Generate Symmetric Key", Slug: "generate_symkey", Description: "Generate symmetric keys", PlanRestrictions: teamAndUp()},

		// Managed Keys (Team+)
		{ID: "api_s044", Name: "Managed Keys List", Slug: "managed_keys_list", Description: "List managed keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s045", Name: "Managed Keys Create", Slug: "managed_keys_create", Description: "Create managed keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s046", Name: "Managed Keys Rotate", Slug: "managed_keys_rotate", Description: "Rotate managed keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s047", Name: "Managed Keys Archive", Slug: "managed_keys_archive", Description: "Archive managed keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s048", Name: "Managed Keys Destroy", Slug: "managed_keys_destroy", Description: "Destroy managed keys", PlanRestrictions: teamAndUp()},

		// User Management (Team+)
		{ID: "api_s049", Name: "Users Scopes List", Slug: "users_scopes_list", Description: "List user scopes", PlanRestrictions: teamAndUp()},
		{ID: "api_s050", Name: "Users List", Slug: "users_list", Description: "List users", PlanRestrictions: teamAndUp()},
		{ID: "api_s051", Name: "Users Create", Slug: "users_create", Description: "Create users", PlanRestrictions: teamAndUp()},
		{ID: "api_s052", Name: "Users Get", Slug: "users_get", Description: "Get user details", PlanRestrictions: teamAndUp()},
		{ID: "api_s053", Name: "Users Update", Slug: "users_update", Description: "Update users", PlanRestrictions: teamAndUp()},
		{ID: "api_s054", Name: "Users Delete", Slug: "users_delete", Description: "Delete users", PlanRestrictions: teamAndUp()},
		{ID: "api_s055", Name: "Users API Keys List", Slug: "users_apikeys_list", Description: "List user API keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s056", Name: "Users API Keys Create", Slug: "users_apikeys_create", Description: "Create user API keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s057", Name: "Users API Keys Get", Slug: "users_apikeys_get", Description: "Get user API keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s058", Name: "Users API Keys Update", Slug: "users_apikeys_update", Description: "Update user API keys", PlanRestrictions: teamAndUp()},
		{ID: "api_s059", Name: "Users API Keys Revoke", Slug: "users_apikeys_revoke", Description: "Revoke user API keys", PlanRestrictions: teamAndUp()},

		// Tenant Management (Startup+)
		{ID: "api_s060", Name: "Tenants Add", Slug: "tenants_add", Description: "Add tenants", PlanRestrictions: startupAndUp()},
		{ID: "api_s061", Name: "Tenants List", Slug: "tenants_list", Description: "List tenants", PlanRestrictions: startupAndUp()},
		{ID: "api_s062", Name: "Tenants Set Key", Slug: "tenants_setkey", Description: "Set tenant key", PlanRestrictions: startupAndUp()},
		{ID: "api_s063", Name: "Tenants Get Key", Slug: "tenants_getkey", Description: "Get tenant key", PlanRestrictions: startupAndUp()},
		{ID: "api_s064", Name: "Tenants Set Secret", Slug: "tenants_set_secret", Description: "Set tenant secret", PlanRestrictions: startupAndUp()},
		{ID: "api_s065", Name: "Tenants Get Secret", Slug: "tenants_get_secret", Description: "Get tenant secret", PlanRestrictions: startupAndUp()},

		// Groups & Namespaces (Team+)
		{ID: "api_s066", Name: "Groups Add", Slug: "groups_add", Description: "Add groups", PlanRestrictions: teamAndUp()},
		{ID: "api_s067", Name: "Groups Generate Secret", Slug: "groups_generate_secret", Description: "Generate group secret", PlanRestrictions: teamAndUp()},

		// Export/Import (Team+)
		{ID: "api_s068", Name: "Export All", Slug: "export_all", Description: "Export all data via API", PlanRestrictions: teamAndUp()},
		{ID: "api_s069", Name: "Import All", Slug: "import_all", Description: "Import all data via API", PlanRestrictions: teamAndUp()},
	},
}

// All features collection
var secretrFeatureCatalog = []secretrFeatureDefinition{
	cliFeature,
	guiFeature,
	apiFeature,
}

// ==================== Bootstrap Functions ====================

// BootstrapSecretrProduct ensures the Secretr product, plans, features, and
// plan-feature mappings exist inside the configured storage backend.
func BootstrapSecretrProduct(ctx context.Context, storage Storage) (*SecretrCatalogSnapshot, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()

	// Create product
	product := &Product{
		ID:          secretrProductID,
		Name:        "Secretr",
		Slug:        secretrProductSlug,
		Description: "Local-first, offline-capable secret management tool designed for developers, teams, and enterprises. All data stays on your device with military-grade encryption.",
		CreatedAt:   now,
		UpdatedAt:   now,
	}

	persistedProduct, err := upsertProduct(ctx, storage, product)
	if err != nil {
		return nil, fmt.Errorf("bootstrap product: %w", err)
	}

	// Seed features and scopes
	featureMap, err := seedSecretrFeatures(ctx, storage, persistedProduct.ID, now)
	if err != nil {
		return nil, fmt.Errorf("bootstrap features: %w", err)
	}

	// Seed plans
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
			return nil, fmt.Errorf("upsert feature %s: %w", def.Slug, err)
		}
		result[def.Slug] = persisted

		// Create scopes for this feature
		for _, scopeDef := range def.Scopes {
			scope := &FeatureScope{
				ID:         scopeDef.ID,
				FeatureID:  persisted.ID,
				Name:       scopeDef.Name,
				Slug:       scopeDef.Slug,
				Permission: ScopePermissionAllow, // Default permission
				Metadata: map[string]string{
					"description": scopeDef.Description,
				},
				CreatedAt: ts,
				UpdatedAt: ts,
			}
			if err := upsertFeatureScope(ctx, storage, scope); err != nil {
				return nil, fmt.Errorf("upsert scope %s: %w", scopeDef.Slug, err)
			}
		}
	}
	return result, nil
}

func seedSecretrPlans(ctx context.Context, storage Storage, product *Product, featureMap map[string]*Feature, ts time.Time) (map[string]*Plan, error) {
	planSnapshot := make(map[string]*Plan)

	for _, def := range secretrPlanDefinitions {
		plan := &Plan{
			ID:             def.ID,
			ProductID:      product.ID,
			Name:           def.Name,
			Slug:           def.Slug,
			Description:    def.Description,
			Price:          def.PricePerDevice, // Legacy field
			MinDevices:     def.MinDevices,
			PricePerDevice: def.PricePerDevice,
			Currency:       "USD",
			BillingCycle:   def.BillingCycle,
			TrialDays:      def.TrialDays,
			IsTrial:        def.IsTrial,
			IsActive:       def.IsActive,
			DisplayOrder:   def.DisplayOrder,
			Metadata: map[string]string{
				"storage_limit": def.StorageLimit,
			},
			CreatedAt: ts,
			UpdatedAt: ts,
		}

		// Enterprise has custom pricing
		if def.Slug == "enterprise" {
			plan.Metadata["price_model"] = "custom"
			plan.Metadata["price_notes"] = "Contact sales"
		} else if def.PricePerDevice > 0 {
			plan.Metadata["price_model"] = "per_device"
		}

		persistedPlan, err := upsertPlan(ctx, storage, plan)
		if err != nil {
			return nil, fmt.Errorf("upsert plan %s: %w", def.Slug, err)
		}
		planSnapshot[persistedPlan.Slug] = persistedPlan

		// Create plan-feature mappings with scope overrides
		if err := ensurePlanFeatures(ctx, storage, persistedPlan, featureMap, ts); err != nil {
			return nil, fmt.Errorf("ensure plan features for %s: %w", def.Slug, err)
		}
	}

	return planSnapshot, nil
}

func ensurePlanFeatures(ctx context.Context, storage Storage, plan *Plan, featureMap map[string]*Feature, ts time.Time) error {
	// All plans get all 3 features (CLI, GUI, API)
	// The scope overrides determine what's actually allowed

	for _, featureDef := range secretrFeatureCatalog {
		feature, ok := featureMap[featureDef.Slug]
		if !ok {
			return fmt.Errorf("missing feature %s for plan %s", featureDef.Slug, plan.Slug)
		}

		// Build scope overrides based on plan restrictions
		scopeOverrides := make(map[string]ScopeOverride)

		for _, scopeDef := range featureDef.Scopes {
			// Check if this plan has a restriction for this scope
			if scopeDef.PlanRestrictions != nil {
				if permission, hasRestriction := scopeDef.PlanRestrictions[plan.Slug]; hasRestriction {
					scopeOverrides[scopeDef.ID] = ScopeOverride{
						Permission: permission,
					}
				}
			}
		}

		// Determine if feature is enabled for this plan
		// API feature is only enabled for Team+ plans
		enabled := true
		if featureDef.Slug == "api" {
			enabled = planHasAPIAccess(plan.Slug)
		}

		pf := &PlanFeature{
			ID:             fmt.Sprintf("pf_%s_%s", plan.ID, feature.ID),
			PlanID:         plan.ID,
			FeatureID:      feature.ID,
			Enabled:        enabled,
			ScopeOverrides: scopeOverrides,
			CreatedAt:      ts,
			UpdatedAt:      ts,
		}

		if err := upsertPlanFeature(ctx, storage, pf); err != nil {
			return err
		}
	}
	return nil
}

func planHasAPIAccess(planSlug string) bool {
	switch planSlug {
	case "team", "startup", "enterprise":
		return true
	default:
		return false
	}
}

// ==================== Upsert Helpers ====================

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
		// Update existing plan with new values
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

// ==================== Utility Functions ====================

// GetAllSecretrPlans returns all plan definitions for reference
func GetAllSecretrPlans() []secretrPlanDefinition {
	return secretrPlanDefinitions
}

// GetSecretrPlanBySlug returns a plan definition by slug
func GetSecretrPlanBySlug(slug string) *secretrPlanDefinition {
	for _, def := range secretrPlanDefinitions {
		if def.Slug == slug {
			return &def
		}
	}
	return nil
}

// GetFeatureScopeRestrictions returns the scope restrictions for a given feature and scope
func GetFeatureScopeRestrictions(featureSlug, scopeSlug string) map[string]ScopePermission {
	var featureDef *secretrFeatureDefinition
	for _, f := range secretrFeatureCatalog {
		if f.Slug == featureSlug {
			featureDef = &f
			break
		}
	}
	if featureDef == nil {
		return nil
	}

	for _, s := range featureDef.Scopes {
		if s.Slug == scopeSlug {
			return s.PlanRestrictions
		}
	}
	return nil
}

// IsScopeAllowedForPlan checks if a scope is allowed for a given plan
func IsScopeAllowedForPlan(featureSlug, scopeSlug, planSlug string) bool {
	restrictions := GetFeatureScopeRestrictions(featureSlug, scopeSlug)
	if restrictions == nil {
		return true // No restrictions means allowed
	}
	permission, hasRestriction := restrictions[planSlug]
	if !hasRestriction {
		return true // Not in restrictions means allowed
	}
	return permission == ScopePermissionAllow
}

// GetPlanStorageLimit returns the storage limit for a plan
func GetPlanStorageLimit(planSlug string) string {
	for _, def := range secretrPlanDefinitions {
		if def.Slug == planSlug {
			return def.StorageLimit
		}
	}
	return "500 MB"
}

// GetPlanStorageLimitBytes returns the storage limit in bytes
func GetPlanStorageLimitBytes(planSlug string) int64 {
	switch planSlug {
	case "personal", "trial":
		return 524288000 // 500 MB
	case "solo":
		return 2147483648 // 2 GB
	case "professional":
		return 5368709120 // 5 GB
	case "team":
		return 10737418240 // 10 GB
	case "startup", "enterprise":
		return -1 // Unlimited
	default:
		return 524288000 // Default 500 MB
	}
}

// GetMinACV calculates minimum annual contract value
func GetMinACV(planSlug string) int64 {
	for _, def := range secretrPlanDefinitions {
		if def.Slug == planSlug {
			if def.PricePerDevice == 0 {
				return 0
			}
			return def.PricePerDevice * int64(def.MinDevices)
		}
	}
	return 0
}

// ==================== Scope Summary Functions ====================

// GetCLIScopeCount returns the number of CLI scopes
func GetCLIScopeCount() int {
	return len(cliFeature.Scopes)
}

// GetGUIScopeCount returns the number of GUI scopes
func GetGUIScopeCount() int {
	return len(guiFeature.Scopes)
}

// GetAPIScopeCount returns the number of API scopes
func GetAPIScopeCount() int {
	return len(apiFeature.Scopes)
}

// GetTotalScopeCount returns the total number of scopes
func GetTotalScopeCount() int {
	return GetCLIScopeCount() + GetGUIScopeCount() + GetAPIScopeCount()
}

// GetScopesForPlan returns all allowed scope slugs for a given plan
func GetScopesForPlan(planSlug string) map[string][]string {
	result := map[string][]string{
		"cli": {},
		"gui": {},
		"api": {},
	}

	for _, scope := range cliFeature.Scopes {
		if IsScopeAllowedForPlan("cli", scope.Slug, planSlug) {
			result["cli"] = append(result["cli"], scope.Slug)
		}
	}

	for _, scope := range guiFeature.Scopes {
		if IsScopeAllowedForPlan("gui", scope.Slug, planSlug) {
			result["gui"] = append(result["gui"], scope.Slug)
		}
	}

	// API is only available for Team+
	if planHasAPIAccess(planSlug) {
		for _, scope := range apiFeature.Scopes {
			if IsScopeAllowedForPlan("api", scope.Slug, planSlug) {
				result["api"] = append(result["api"], scope.Slug)
			}
		}
	}

	// Sort for deterministic output
	sort.Strings(result["cli"])
	sort.Strings(result["gui"])
	sort.Strings(result["api"])

	return result
}

// GetDeniedScopesForPlan returns all denied scope slugs for a given plan
func GetDeniedScopesForPlan(planSlug string) map[string][]string {
	result := map[string][]string{
		"cli": {},
		"gui": {},
		"api": {},
	}

	for _, scope := range cliFeature.Scopes {
		if !IsScopeAllowedForPlan("cli", scope.Slug, planSlug) {
			result["cli"] = append(result["cli"], scope.Slug)
		}
	}

	for _, scope := range guiFeature.Scopes {
		if !IsScopeAllowedForPlan("gui", scope.Slug, planSlug) {
			result["gui"] = append(result["gui"], scope.Slug)
		}
	}

	// API is only available for Team+, so denied for lower plans
	if !planHasAPIAccess(planSlug) {
		for _, scope := range apiFeature.Scopes {
			result["api"] = append(result["api"], scope.Slug)
		}
	} else {
		for _, scope := range apiFeature.Scopes {
			if !IsScopeAllowedForPlan("api", scope.Slug, planSlug) {
				result["api"] = append(result["api"], scope.Slug)
			}
		}
	}

	// Sort for deterministic output
	sort.Strings(result["cli"])
	sort.Strings(result["gui"])
	sort.Strings(result["api"])

	return result
}
