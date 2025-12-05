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
	defaultTrialDays   = 14
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
		Name:           "Free Trial",
		Slug:           "trial",
		Description:    "Try everything before you buy. Full access to all features with no device limit.",
		PricePerDevice: 0,
		MinDevices:     1,
		StorageLimit:   "Unlimited",
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
		Description:    "Core secrets, SSH, generators, GUI for individual developers",
		PricePerDevice: 2500, // $25/device/year
		MinDevices:     1,
		StorageLimit:   "1 GB",
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
		Description:    "For power users and freelancers: adds P2P, audit, 2FA, versioning",
		PricePerDevice: 6000, // $60/device/year
		MinDevices:     2,
		StorageLimit:   "5 GB",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   2,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_team",
		Name:           "Team",
		Slug:           "team",
		Description:    "Adds scratchpads, templates, rotation, log viewers, bundles",
		PricePerDevice: 9000, // $90/device/year
		MinDevices:     5,
		StorageLimit:   "25 GB",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   3,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_business",
		Name:           "Business",
		Slug:           "business",
		Description:    "API server, multi-tenant, ACL, sandbox, transfer system",
		PricePerDevice: 18000, // $180/device/year
		MinDevices:     15,
		StorageLimit:   "Unlimited",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   4,
		IsActive:       true,
	},
	{
		ID:             "plan_secretr_enterprise",
		Name:           "Enterprise",
		Slug:           "enterprise",
		Description:    "Custom SLAs, compliance programs, HSM, containers, dedicated support.",
		PricePerDevice: 0, // Custom pricing - contact sales
		MinDevices:     50,
		StorageLimit:   "Unlimited",
		BillingCycle:   "yearly",
		TrialDays:      0,
		IsTrial:        false,
		DisplayOrder:   5,
		IsActive:       true,
	},
}

// Plan tier order for cumulative feature inheritance
var secretrPlanOrder = []string{"personal", "solo", "team", "business", "enterprise"}

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

// Helper to create restriction maps - denies for all plans before the specified one
func denyBefore(planSlug string) map[string]ScopePermission {
	order := map[string]int{
		"personal":   0,
		"solo":       1,
		"team":       2,
		"business":   3,
		"enterprise": 4,
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
		"personal": permDeny,
		"solo":     permDeny,
		"team":     permDeny,
		"business": permDeny,
	}
}

func businessAndUp() map[string]ScopePermission {
	return denyBefore("business")
}

func teamAndUp() map[string]ScopePermission {
	return denyBefore("team")
}

func soloAndUp() map[string]ScopePermission {
	return denyBefore("solo")
}

type scopeDef struct {
	ID          string
	Name        string
	Slug        string
	Description string
	MinPlan     string
}

func buildScopes(defs []scopeDef) []secretrScopeDefinition {
	scopes := make([]secretrScopeDefinition, 0, len(defs))
	for _, def := range defs {
		scopes = append(scopes, secretrScopeDefinition{
			ID:               def.ID,
			Name:             def.Name,
			Slug:             def.Slug,
			Description:      def.Description,
			PlanRestrictions: restrictionForPlan(def.MinPlan),
		})
	}
	return scopes
}

// restrictionForPlan applies deny overrides to all plans below the minimum tier.
func restrictionForPlan(minPlan string) map[string]ScopePermission {
	switch strings.ToLower(minPlan) {
	case "":
		return nil
	case "solo":
		return soloAndUp()
	case "team", "professional":
		return teamAndUp()
	case "business", "startup":
		return businessAndUp()
	case "enterprise":
		return enterpriseOnly()
	default:
		return nil
	}
}

// CLI Feature with all 83 scopes from ENTITLEMENT_SCOPES.md
var cliFeature = secretrFeatureDefinition{
	ID:          "feat_cli_001",
	Name:        "CLI",
	Slug:        "cli",
	Category:    "interface",
	Description: "Command-line interface access for Secretr operations",
	Scopes: buildScopes([]scopeDef{
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

		// Sharing & Collaboration
		{ID: "cli_s011", Name: "Share", Slug: "share", Description: "ACL-based share secrets", MinPlan: "business"},
		{ID: "cli_s012", Name: "P2P Share", Slug: "p2p-share", Description: "P2P sharing on LAN", MinPlan: "solo"},
		{ID: "cli_s013", Name: "P2P", Slug: "p2p", Description: "P2P operations", MinPlan: "solo"},

		// Container Security
		{ID: "cli_s014", Name: "Container", Slug: "container", Description: "Container operations", MinPlan: "enterprise"},

		// Backup & Recovery
		{ID: "cli_s015", Name: "Backup", Slug: "backup", Description: "Backup operations"},
		{ID: "cli_s016", Name: "Export", Slug: "export", Description: "Export data"},
		{ID: "cli_s017", Name: "Import", Slug: "import", Description: "Import data"},

		// Generators
		{ID: "cli_s018", Name: "Generate JWT", Slug: "gen-jwt", Description: "Generate JWT secrets"},
		{ID: "cli_s019", Name: "Generate API Key", Slug: "gen-apikey", Description: "Generate API keys"},
		{ID: "cli_s020", Name: "Generate Keypair", Slug: "gen-keypair", Description: "Generate keypairs"},
		{ID: "cli_s021", Name: "Generate Symmetric Key", Slug: "gen-symkey", Description: "Generate symmetric keys"},
		{ID: "cli_s022", Name: "Dynamic Secrets", Slug: "dynamic", Description: "Dynamic secret generation"},

		// Templates & Rotation
		{ID: "cli_s023", Name: "Template", Slug: "template", Description: "Secret templates", MinPlan: "team"},
		{ID: "cli_s024", Name: "Rotate", Slug: "rotate", Description: "Secret rotation", MinPlan: "team"},

		// Tenant Management
		{ID: "cli_s025", Name: "Tenant", Slug: "tenant", Description: "Tenant management", MinPlan: "business"},

		// Import/Export Advanced
		{ID: "cli_s026", Name: "From File", Slug: "from-file", Description: "Import from file"},
		{ID: "cli_s027", Name: "To File", Slug: "to-file", Description: "Export to file"},
		{ID: "cli_s028", Name: "Pull", Slug: "pull", Description: "Pull secrets"},
		{ID: "cli_s029", Name: "Push", Slug: "push", Description: "Push secrets"},
		{ID: "cli_s030", Name: "Server Export", Slug: "server-export", Description: "Server export operations"},

		// Scratchpad
		{ID: "cli_s031", Name: "Scratchpad", Slug: "scratchpad", Description: "Encrypted scratchpads", MinPlan: "team"},

		// Environment
		{ID: "cli_s032", Name: "Print Env", Slug: "printenv", Description: "Print environment variables"},
		{ID: "cli_s033", Name: "Env", Slug: "env", Description: "Environment operations"},
		{ID: "cli_s034", Name: "Enrich", Slug: "enrich", Description: "Enrich process environment"},

		// Cryptography
		{ID: "cli_s035", Name: "Certificate", Slug: "certificate", Description: "Certificate operations"},
		{ID: "cli_s036", Name: "Sign", Slug: "sign", Description: "Sign data"},
		{ID: "cli_s037", Name: "Verify", Slug: "verify", Description: "Verify signatures"},
		{ID: "cli_s038", Name: "Hash", Slug: "hash", Description: "Hash operations"},

		// Versioning & Version Control
		{ID: "cli_s039", Name: "List KV Versions", Slug: "listkv", Description: "List KV versions", MinPlan: "solo"},
		{ID: "cli_s040", Name: "Rollback KV", Slug: "rollbackkv", Description: "Rollback KV versions", MinPlan: "solo"},
		{ID: "cli_s072", Name: "VCS", Slug: "vcs", Description: "Version control operations", MinPlan: "solo"},

		// Security Sandbox
		{ID: "cli_s041", Name: "Sandbox", Slug: "sandbox", Description: "Sandbox execution", MinPlan: "business"},
		{ID: "cli_s042", Name: "Secure Sandbox", Slug: "secure-sandbox", Description: "Secure sandbox execution", MinPlan: "business"},
		{ID: "cli_s043", Name: "SSB", Slug: "ssb", Description: "Secure sandbox shorthand", MinPlan: "business"},

		// Security Policy & Vault Security
		{ID: "cli_s044", Name: "Security Policy", Slug: "security-policy", Description: "Security policy configuration"},
		{ID: "cli_s045", Name: "Sec Policy", Slug: "sec-policy", Description: "Security policy shorthand"},
		{ID: "cli_s046", Name: "Vault Security", Slug: "vault-security", Description: "Vault security operations"},
		{ID: "cli_s047", Name: "VSec", Slug: "vsec", Description: "Vault security shorthand"},

		// Observability
		{ID: "cli_s048", Name: "Observability", Slug: "observability", Description: "Observability commands"},
		{ID: "cli_s049", Name: "Obs", Slug: "obs", Description: "Observability shorthand"},

		// FIPS & Compliance
		{ID: "cli_s050", Name: "FIPS", Slug: "fips", Description: "FIPS mode operations", MinPlan: "enterprise"},
		{ID: "cli_s051", Name: "FIPS-140", Slug: "fips-140", Description: "FIPS 140 compliance", MinPlan: "enterprise"},
		{ID: "cli_s052", Name: "Compliance", Slug: "compliance", Description: "Compliance framework operations", MinPlan: "enterprise"},
		{ID: "cli_s053", Name: "Comp", Slug: "comp", Description: "Compliance shorthand", MinPlan: "enterprise"},

		// Data Classification & Retention
		{ID: "cli_s054", Name: "Classify", Slug: "classify", Description: "Data classification", MinPlan: "enterprise"},
		{ID: "cli_s055", Name: "Data Classification", Slug: "data-classification", Description: "Data classification full", MinPlan: "enterprise"},
		{ID: "cli_s056", Name: "DC", Slug: "dc", Description: "Data classification shorthand", MinPlan: "enterprise"},
		{ID: "cli_s057", Name: "Retention", Slug: "retention", Description: "Data retention policies", MinPlan: "business"},
		{ID: "cli_s058", Name: "Ret", Slug: "ret", Description: "Retention shorthand", MinPlan: "business"},

		// Breach Management & Access Review
		{ID: "cli_s059", Name: "Breach", Slug: "breach", Description: "Breach management", MinPlan: "enterprise"},
		{ID: "cli_s060", Name: "Breach Notification", Slug: "breach-notification", Description: "Breach notifications", MinPlan: "enterprise"},
		{ID: "cli_s061", Name: "Access Review", Slug: "access-review", Description: "Access review workflow", MinPlan: "enterprise"},
		{ID: "cli_s062", Name: "AR", Slug: "ar", Description: "Access review shorthand", MinPlan: "enterprise"},
		{ID: "cli_s063", Name: "Access Reviews", Slug: "access-reviews", Description: "Access reviews list", MinPlan: "enterprise"},

		// Authentication
		{ID: "cli_s064", Name: "Enable 2FA", Slug: "enable-2fa", Description: "Enable two-factor auth", MinPlan: "solo"},
		{ID: "cli_s065", Name: "Disable 2FA", Slug: "disable-2fa", Description: "Disable two-factor auth", MinPlan: "solo"},
		{ID: "cli_s066", Name: "Enable Passkey", Slug: "enable-passkey", Description: "Enable passkey auth", MinPlan: "solo"},
		{ID: "cli_s067", Name: "Disable Passkey", Slug: "disable-passkey", Description: "Disable passkey auth", MinPlan: "solo"},
		{ID: "cli_s068", Name: "Enable Share Prompts", Slug: "enable-share-prompts", Description: "Enable share prompts", MinPlan: "solo"},

		// System Commands
		{ID: "cli_s069", Name: "Server", Slug: "server", Description: "Server mode operations", MinPlan: "business"},
		{ID: "cli_s070", Name: "KDS", Slug: "kds", Description: "Key distribution server", MinPlan: "business"},
		{ID: "cli_s071", Name: "Server Config", Slug: "server-config", Description: "Server configuration", MinPlan: "business"},

		// Vault Storage & Compaction
		{ID: "cli_s073", Name: "Compact", Slug: "compact", Description: "Vault compaction", MinPlan: "team"},
		{ID: "cli_s074", Name: "Vault Compact", Slug: "vault-compact", Description: "Vault compaction full", MinPlan: "team"},

		// Shamir Secret Sharing & Audit Logs
		{ID: "cli_s075", Name: "Shamir", Slug: "shamir", Description: "Shamir secret sharing", MinPlan: "solo"},
		{ID: "cli_s076", Name: "Shamir Split", Slug: "shamir-split", Description: "Split secret with Shamir", MinPlan: "solo"},
		{ID: "cli_s077", Name: "Shamir Combine", Slug: "shamir-combine", Description: "Combine Shamir shares", MinPlan: "solo"},
		{ID: "cli_s078", Name: "Audit", Slug: "audit", Description: "Audit log operations", MinPlan: "solo"},
		{ID: "cli_s079", Name: "Audit Log", Slug: "audit-log", Description: "Audit log viewing", MinPlan: "solo"},

		// Config Injection
		{ID: "cli_s080", Name: "Inject", Slug: "inject", Description: "Config injection", MinPlan: "business"},
		{ID: "cli_s081", Name: "Config Inject", Slug: "config-inject", Description: "Config file injection", MinPlan: "business"},

		// Transfer System (Business+)
		{ID: "cli_s084", Name: "Transfer", Slug: "transfer", Description: "Transfer command suite", MinPlan: "business"},
		{ID: "cli_s085", Name: "Transfer Devices", Slug: "transfer-devices", Description: "Manage transfer devices", MinPlan: "business"},
		{ID: "cli_s086", Name: "Transfer Devices List", Slug: "transfer-devices-list", Description: "List transfer devices", MinPlan: "business"},
		{ID: "cli_s087", Name: "Transfer Devices Add", Slug: "transfer-devices-add", Description: "Add transfer device", MinPlan: "business"},
		{ID: "cli_s088", Name: "Transfer Devices Remove", Slug: "transfer-devices-remove", Description: "Remove transfer device", MinPlan: "business"},
		{ID: "cli_s089", Name: "Transfer Devices Verify", Slug: "transfer-devices-verify", Description: "Verify transfer device", MinPlan: "business"},
		{ID: "cli_s090", Name: "Transfer Send", Slug: "transfer-send", Description: "Send transfer payload", MinPlan: "business"},
		{ID: "cli_s091", Name: "Transfer Upload", Slug: "transfer-upload", Description: "Upload transfer payload", MinPlan: "business"},
		{ID: "cli_s092", Name: "Transfer Download", Slug: "transfer-download", Description: "Download transfer payload", MinPlan: "business"},
		{ID: "cli_s093", Name: "Transfer Bundle", Slug: "transfer-bundle", Description: "Manage transfer bundles", MinPlan: "business"},
		{ID: "cli_s094", Name: "Transfer Bundle Create", Slug: "transfer-bundle-create", Description: "Create transfer bundle", MinPlan: "business"},
		{ID: "cli_s095", Name: "Transfer Bundle Import", Slug: "transfer-bundle-import", Description: "Import transfer bundle", MinPlan: "business"},
		{ID: "cli_s096", Name: "Transfer Bundle QR", Slug: "transfer-bundle-qr", Description: "Generate bundle QR codes", MinPlan: "business"},
		{ID: "cli_s097", Name: "Transfer Schedule", Slug: "transfer-schedule", Description: "Manage transfer schedules", MinPlan: "business"},
		{ID: "cli_s098", Name: "Transfer Schedule List", Slug: "transfer-schedule-list", Description: "List transfer schedules", MinPlan: "business"},
		{ID: "cli_s099", Name: "Transfer Schedule Add", Slug: "transfer-schedule-add", Description: "Add transfer schedule", MinPlan: "business"},
		{ID: "cli_s100", Name: "Transfer Schedule Pause", Slug: "transfer-schedule-pause", Description: "Pause transfer schedule", MinPlan: "business"},
		{ID: "cli_s101", Name: "Transfer Schedule Resume", Slug: "transfer-schedule-resume", Description: "Resume transfer schedule", MinPlan: "business"},
		{ID: "cli_s102", Name: "Transfer Schedule Run", Slug: "transfer-schedule-run", Description: "Run transfer schedule", MinPlan: "business"},

		// Container Security Audit
		{ID: "cli_s103", Name: "Container Audit", Slug: "container-audit", Description: "Container security audit", MinPlan: "enterprise"},
		{ID: "cli_s104", Name: "CSA", Slug: "csa", Description: "Container security audit shorthand", MinPlan: "enterprise"},

		// Interactive Log Viewers (Team+)
		{ID: "cli_s110", Name: "Interactive Logs", Slug: "view", Description: "Interactive log viewer", MinPlan: "team"},
		{ID: "cli_s111", Name: "Interactive Audit Logs", Slug: "view_audit-logs", Description: "Interactive audit log viewer", MinPlan: "team"},
		{ID: "cli_s112", Name: "Interactive Access Logs", Slug: "view_access-logs", Description: "Interactive access log viewer", MinPlan: "team"},
	}),
}

// GUI Feature with all 37 scopes from ENTITLEMENT_SCOPES.md
var guiFeature = secretrFeatureDefinition{
	ID:          "feat_gui_001",
	Name:        "GUI",
	Slug:        "gui",
	Category:    "interface",
	Description: "Desktop GUI application access",
	Scopes: buildScopes([]scopeDef{
		// CRUD Operations
		{ID: "gui_s001", Name: "View", Slug: "view", Description: "View secrets and data"},
		{ID: "gui_s002", Name: "List", Slug: "list", Description: "List items"},
		{ID: "gui_s003", Name: "Create", Slug: "create", Description: "Create new items"},
		{ID: "gui_s004", Name: "Update", Slug: "update", Description: "Update existing items"},
		{ID: "gui_s005", Name: "Delete", Slug: "delete", Description: "Delete items"},
		{ID: "gui_s006", Name: "Edit", Slug: "edit", Description: "Edit items"},

		// Secret Management
		{ID: "gui_s007", Name: "Secret Manager", Slug: "secret_manager", Description: "Secret management interface"},
		{ID: "gui_s008", Name: "Secret Search", Slug: "secret_search", Description: "Search secrets"},
		{ID: "gui_s009", Name: "Secret Filter", Slug: "secret_filter", Description: "Filter secrets"},
		{ID: "gui_s010", Name: "Password Protection", Slug: "password_protection", Description: "Password protection for secrets"},

		// File Management
		{ID: "gui_s011", Name: "File Manager", Slug: "file_manager", Description: "File management interface"},
		{ID: "gui_s012", Name: "File Upload", Slug: "file_upload", Description: "Upload files"},
		{ID: "gui_s013", Name: "File Download", Slug: "file_download", Description: "Download files"},

		// Generators & SSH
		{ID: "gui_s014", Name: "Password Generator", Slug: "password_generator", Description: "Generate passwords"},
		{ID: "gui_s015", Name: "SSH Key Generator", Slug: "ssh_key_generator", Description: "Generate SSH keys"},
		{ID: "gui_s016", Name: "Certificate Generator", Slug: "certificate_generator", Description: "Generate certificates"},
		{ID: "gui_s017", Name: "Hash Generator", Slug: "hash_generator", Description: "Generate hashes"},
		{ID: "gui_s018", Name: "SSH Profiles", Slug: "ssh_profiles", Description: "SSH profile management"},
		{ID: "gui_s019", Name: "SSH Terminal", Slug: "ssh_terminal", Description: "SSH terminal interface"},
		{ID: "gui_s020", Name: "SSH Import", Slug: "ssh_import", Description: "Import SSH keys"},

		// P2P Sharing (Solo+)
		{ID: "gui_s021", Name: "P2P Share", Slug: "p2p_share", Description: "P2P sharing interface", MinPlan: "solo"},
		{ID: "gui_s022", Name: "P2P Discover", Slug: "p2p_discover", Description: "Discover P2P peers", MinPlan: "solo"},
		{ID: "gui_s023", Name: "P2P Receive", Slug: "p2p_receive", Description: "Receive P2P shares", MinPlan: "solo"},

		// Crypto Operations
		{ID: "gui_s024", Name: "Sign Data", Slug: "sign_data", Description: "Data signing interface"},
		{ID: "gui_s025", Name: "Verify Signature", Slug: "verify_signature", Description: "Signature verification"},

		// Management Views
		{ID: "gui_s026", Name: "Templates", Slug: "templates", Description: "Template management", MinPlan: "team"},
		{ID: "gui_s027", Name: "Rotation", Slug: "rotation", Description: "Secret rotation management", MinPlan: "team"},
		{ID: "gui_s028", Name: "Backup Restore", Slug: "backup_restore", Description: "Backup and restore interface"},
		{ID: "gui_s029", Name: "Scratchpad", Slug: "scratchpad", Description: "Scratchpad interface", MinPlan: "team"},

		// Compliance Views (Enterprise)
		{ID: "gui_s030", Name: "Compliance Dashboard", Slug: "compliance_dashboard", Description: "Compliance dashboard", MinPlan: "enterprise"},
		{ID: "gui_s031", Name: "Data Classification", Slug: "data_classification", Description: "Data classification interface", MinPlan: "enterprise"},
		{ID: "gui_s032", Name: "Data Retention", Slug: "data_retention", Description: "Data retention interface", MinPlan: "enterprise"},
		{ID: "gui_s033", Name: "Breach Notification", Slug: "breach_notification", Description: "Breach notification interface", MinPlan: "enterprise"},
		{ID: "gui_s034", Name: "Access Reviews", Slug: "access_reviews", Description: "Access reviews interface", MinPlan: "enterprise"},
		{ID: "gui_s035", Name: "FIPS Compliance", Slug: "fips_compliance", Description: "FIPS compliance interface", MinPlan: "enterprise"},

		// Security Views (Solo+)
		{ID: "gui_s036", Name: "Two Factor Auth", Slug: "two_factor_auth", Description: "2FA management", MinPlan: "solo"},
		{ID: "gui_s037", Name: "Vault Lock", Slug: "vault_lock", Description: "Vault lock controls", MinPlan: "solo"},

		// Transfer System (Business+)
		{ID: "gui_s038", Name: "Transfer Dashboard", Slug: "transfer_dashboard", Description: "Transfer overview", MinPlan: "business"},
		{ID: "gui_s039", Name: "Transfer Devices", Slug: "transfer_devices", Description: "Transfer devices list", MinPlan: "business"},
		{ID: "gui_s040", Name: "Transfer Devices Manage", Slug: "transfer_devices_manage", Description: "Manage transfer devices", MinPlan: "business"},
		{ID: "gui_s041", Name: "Transfer Send", Slug: "transfer_send", Description: "Send from GUI", MinPlan: "business"},
		{ID: "gui_s042", Name: "Transfer Receive", Slug: "transfer_receive", Description: "Receive transfers", MinPlan: "business"},
		{ID: "gui_s043", Name: "Transfer Cloud", Slug: "transfer_cloud", Description: "Cloud transfer hub", MinPlan: "business"},
		{ID: "gui_s044", Name: "Transfer Cloud Upload", Slug: "transfer_cloud_upload", Description: "Upload via cloud", MinPlan: "business"},
		{ID: "gui_s045", Name: "Transfer Cloud Download", Slug: "transfer_cloud_download", Description: "Download via cloud", MinPlan: "business"},
		{ID: "gui_s046", Name: "Transfer Airgap", Slug: "transfer_airgap", Description: "Airgapped transfers", MinPlan: "business"},
		{ID: "gui_s047", Name: "Transfer Bundle Create", Slug: "transfer_bundle_create", Description: "Create transfer bundles", MinPlan: "business"},
		{ID: "gui_s048", Name: "Transfer Bundle Import", Slug: "transfer_bundle_import", Description: "Import transfer bundles", MinPlan: "business"},
		{ID: "gui_s049", Name: "Transfer Bundle QR", Slug: "transfer_bundle_qr", Description: "Transfer bundle QR tools", MinPlan: "business"},
		{ID: "gui_s050", Name: "Transfer Schedule", Slug: "transfer_schedule", Description: "Schedule transfers", MinPlan: "business"},
		{ID: "gui_s051", Name: "Transfer Schedule Manage", Slug: "transfer_schedule_manage", Description: "Manage schedules", MinPlan: "business"},
		{ID: "gui_s052", Name: "Transfer History", Slug: "transfer_history", Description: "Transfer history view", MinPlan: "business"},
		{ID: "gui_s053", Name: "Transfer Audit", Slug: "transfer_audit", Description: "Transfer audit log", MinPlan: "business"},
	}),
}

// API Feature with all 69 scopes from ENTITLEMENT_SCOPES.md
var apiFeature = secretrFeatureDefinition{
	ID:          "feat_api_001",
	Name:        "API",
	Slug:        "api",
	Category:    "integration",
	Description: "HTTP API access (requires Business+ plan)",
	Scopes: buildScopes([]scopeDef{
		// Setup & Configuration (Business+)
		{ID: "api_s001", Name: "Setup Check", Slug: "setup_check", Description: "Check setup status", MinPlan: "business"},
		{ID: "api_s002", Name: "Setup Complete", Slug: "setup_complete", Description: "Complete setup", MinPlan: "business"},
		{ID: "api_s003", Name: "Admin Regenerate Key", Slug: "admin_regenerate_key", Description: "Regenerate admin key", MinPlan: "business"},

		// Authentication (Business+)
		{ID: "api_s004", Name: "Auth Login", Slug: "auth_login", Description: "Authenticate user", MinPlan: "business"},
		{ID: "api_s005", Name: "Auth Sessions List", Slug: "auth_sessions_list", Description: "List active sessions", MinPlan: "business"},
		{ID: "api_s006", Name: "Auth Sessions Revoke", Slug: "auth_sessions_revoke", Description: "Revoke sessions", MinPlan: "business"},

		// Two-Factor Authentication (Solo+)
		{ID: "api_s007", Name: "2FA Status", Slug: "2fa_status", Description: "Get 2FA status", MinPlan: "solo"},
		{ID: "api_s008", Name: "2FA Setup Start", Slug: "2fa_setup_start", Description: "Start 2FA setup", MinPlan: "solo"},
		{ID: "api_s009", Name: "2FA Setup Verify", Slug: "2fa_setup_verify", Description: "Verify 2FA setup", MinPlan: "solo"},
		{ID: "api_s010", Name: "2FA Verify", Slug: "2fa_verify", Description: "Verify 2FA code", MinPlan: "solo"},
		{ID: "api_s011", Name: "2FA Disable", Slug: "2fa_disable", Description: "Disable 2FA", MinPlan: "solo"},
		{ID: "api_s012", Name: "2FA Backup Code", Slug: "2fa_backup_code", Description: "Get backup codes", MinPlan: "solo"},

		// Secrets Management (Business+)
		{ID: "api_s013", Name: "Secrets Read", Slug: "secrets_read", Description: "Read secrets via API", MinPlan: "business"},
		{ID: "api_s014", Name: "Secrets Write", Slug: "secrets_write", Description: "Write secrets via API", MinPlan: "business"},
		{ID: "api_s015", Name: "Secrets Delete", Slug: "secrets_delete", Description: "Delete secrets via API", MinPlan: "business"},
		{ID: "api_s016", Name: "Secrets List", Slug: "secrets_list", Description: "List secrets via API", MinPlan: "business"},

		// KV Versioning (Solo+)
		{ID: "api_s017", Name: "KV Versions List", Slug: "kv_versions_list", Description: "List KV versions", MinPlan: "solo"},
		{ID: "api_s018", Name: "KV Rollback", Slug: "kv_rollback", Description: "Rollback KV version", MinPlan: "solo"},

		// Transit Engine (Business+)
		{ID: "api_s019", Name: "Transit Encrypt", Slug: "transit_encrypt", Description: "Transit encryption", MinPlan: "business"},
		{ID: "api_s020", Name: "Transit Decrypt", Slug: "transit_decrypt", Description: "Transit decryption", MinPlan: "business"},

		// Dynamic Engines (Solo+)
		{ID: "api_s021", Name: "Dynamic Database", Slug: "dynamic_database", Description: "Dynamic database credentials", MinPlan: "solo"},
		{ID: "api_s022", Name: "Dynamic Cloud", Slug: "dynamic_cloud", Description: "Dynamic cloud tokens", MinPlan: "solo"},
		{ID: "api_s023", Name: "Dynamic Verify", Slug: "dynamic_verify", Description: "Verify dynamic credentials", MinPlan: "solo"},

		// Response Wrapping (Business+)
		{ID: "api_s024", Name: "Wrap Response", Slug: "wrap_response", Description: "Wrap API response", MinPlan: "business"},
		{ID: "api_s025", Name: "Unwrap Response", Slug: "unwrap_response", Description: "Unwrap API response", MinPlan: "business"},

		// File Management (Business+)
		{ID: "api_s026", Name: "Files List", Slug: "files_list", Description: "List files via API", MinPlan: "business"},
		{ID: "api_s027", Name: "Files Upload", Slug: "files_upload", Description: "Upload files via API", MinPlan: "business"},
		{ID: "api_s028", Name: "Files Download", Slug: "files_download", Description: "Download files via API", MinPlan: "business"},
		{ID: "api_s029", Name: "Files Delete", Slug: "files_delete", Description: "Delete files via API", MinPlan: "business"},
		{ID: "api_s030", Name: "Files Render", Slug: "files_render", Description: "Render files via API", MinPlan: "business"},

		// SSH Management (Business+)
		{ID: "api_s031", Name: "SSH Keys Get", Slug: "ssh_keys_get", Description: "Get SSH keys", MinPlan: "business"},
		{ID: "api_s032", Name: "SSH Keys Create", Slug: "ssh_keys_create", Description: "Create SSH keys", MinPlan: "business"},
		{ID: "api_s033", Name: "SSH Keys Delete", Slug: "ssh_keys_delete", Description: "Delete SSH keys", MinPlan: "business"},
		{ID: "api_s034", Name: "SSH Keys List", Slug: "ssh_keys_list", Description: "List SSH keys", MinPlan: "business"},
		{ID: "api_s035", Name: "SSH Profiles Get", Slug: "ssh_profiles_get", Description: "Get SSH profiles", MinPlan: "business"},
		{ID: "api_s036", Name: "SSH Profiles Create", Slug: "ssh_profiles_create", Description: "Create SSH profiles", MinPlan: "business"},
		{ID: "api_s037", Name: "SSH Profiles Delete", Slug: "ssh_profiles_delete", Description: "Delete SSH profiles", MinPlan: "business"},
		{ID: "api_s038", Name: "SSH Profiles List", Slug: "ssh_profiles_list", Description: "List SSH profiles", MinPlan: "business"},

		// Certificate Management (Solo+)
		{ID: "api_s039", Name: "Certificate Generate", Slug: "certificate_generate", Description: "Generate certificates", MinPlan: "solo"},

		// Key Generation (Personal+)
		{ID: "api_s040", Name: "Generate JWT", Slug: "generate_jwt", Description: "Generate JWT secrets", MinPlan: "personal"},
		{ID: "api_s041", Name: "Generate API Key", Slug: "generate_apikey", Description: "Generate API keys", MinPlan: "personal"},
		{ID: "api_s042", Name: "Generate Keypair", Slug: "generate_keypair", Description: "Generate keypairs", MinPlan: "personal"},
		{ID: "api_s043", Name: "Generate Symmetric Key", Slug: "generate_symkey", Description: "Generate symmetric keys", MinPlan: "personal"},

		// Managed Keys (Business+)
		{ID: "api_s044", Name: "Managed Keys List", Slug: "managed_keys_list", Description: "List managed keys", MinPlan: "business"},
		{ID: "api_s045", Name: "Managed Keys Create", Slug: "managed_keys_create", Description: "Create managed keys", MinPlan: "business"},
		{ID: "api_s046", Name: "Managed Keys Rotate", Slug: "managed_keys_rotate", Description: "Rotate managed keys", MinPlan: "business"},
		{ID: "api_s047", Name: "Managed Keys Archive", Slug: "managed_keys_archive", Description: "Archive managed keys", MinPlan: "business"},
		{ID: "api_s048", Name: "Managed Keys Destroy", Slug: "managed_keys_destroy", Description: "Destroy managed keys", MinPlan: "business"},

		// User Management (Business+)
		{ID: "api_s049", Name: "Users Scopes List", Slug: "users_scopes_list", Description: "List user scopes", MinPlan: "business"},
		{ID: "api_s050", Name: "Users List", Slug: "users_list", Description: "List users", MinPlan: "business"},
		{ID: "api_s051", Name: "Users Create", Slug: "users_create", Description: "Create users", MinPlan: "business"},
		{ID: "api_s052", Name: "Users Get", Slug: "users_get", Description: "Get user details", MinPlan: "business"},
		{ID: "api_s053", Name: "Users Update", Slug: "users_update", Description: "Update users", MinPlan: "business"},
		{ID: "api_s054", Name: "Users Delete", Slug: "users_delete", Description: "Delete users", MinPlan: "business"},
		{ID: "api_s055", Name: "Users API Keys List", Slug: "users_apikeys_list", Description: "List user API keys", MinPlan: "business"},
		{ID: "api_s056", Name: "Users API Keys Create", Slug: "users_apikeys_create", Description: "Create user API keys", MinPlan: "business"},
		{ID: "api_s057", Name: "Users API Keys Get", Slug: "users_apikeys_get", Description: "Get user API keys", MinPlan: "business"},
		{ID: "api_s058", Name: "Users API Keys Update", Slug: "users_apikeys_update", Description: "Update user API keys", MinPlan: "business"},
		{ID: "api_s059", Name: "Users API Keys Revoke", Slug: "users_apikeys_revoke", Description: "Revoke user API keys", MinPlan: "business"},

		// Tenant Management (Business+)
		{ID: "api_s060", Name: "Tenants Add", Slug: "tenants_add", Description: "Add tenants", MinPlan: "business"},
		{ID: "api_s061", Name: "Tenants List", Slug: "tenants_list", Description: "List tenants", MinPlan: "business"},
		{ID: "api_s062", Name: "Tenants Set Key", Slug: "tenants_setkey", Description: "Set tenant key", MinPlan: "business"},
		{ID: "api_s063", Name: "Tenants Get Key", Slug: "tenants_getkey", Description: "Get tenant key", MinPlan: "business"},
		{ID: "api_s064", Name: "Tenants Set Secret", Slug: "tenants_set_secret", Description: "Set tenant secret", MinPlan: "business"},
		{ID: "api_s065", Name: "Tenants Get Secret", Slug: "tenants_get_secret", Description: "Get tenant secret", MinPlan: "business"},

		// Groups & Namespaces (Business+)
		{ID: "api_s066", Name: "Groups Add", Slug: "groups_add", Description: "Add groups", MinPlan: "business"},
		{ID: "api_s067", Name: "Groups Generate Secret", Slug: "groups_generate_secret", Description: "Generate group secret", MinPlan: "business"},

		// Transfer System (Business+)
		{ID: "api_s070", Name: "Transfer Devices List", Slug: "transfer_devices_list", Description: "List trusted devices", MinPlan: "business"},
		{ID: "api_s071", Name: "Transfer Devices Add", Slug: "transfer_devices_add", Description: "Add trusted devices", MinPlan: "business"},
		{ID: "api_s072", Name: "Transfer Devices Remove", Slug: "transfer_devices_remove", Description: "Remove trusted devices", MinPlan: "business"},
		{ID: "api_s073", Name: "Transfer Devices Verify", Slug: "transfer_devices_verify", Description: "Verify device trust", MinPlan: "business"},
		{ID: "api_s074", Name: "Transfer Send", Slug: "transfer_send", Description: "Send transfer payload", MinPlan: "business"},
		{ID: "api_s075", Name: "Transfer Receive", Slug: "transfer_receive", Description: "Receive transfer payload", MinPlan: "business"},
		{ID: "api_s076", Name: "Transfer Status", Slug: "transfer_status", Description: "Check transfer status", MinPlan: "business"},
		{ID: "api_s077", Name: "Transfer Cancel", Slug: "transfer_cancel", Description: "Cancel transfer", MinPlan: "business"},
		{ID: "api_s078", Name: "Transfer Cloud Upload", Slug: "transfer_cloud_upload", Description: "Upload to transfer cloud", MinPlan: "business"},
		{ID: "api_s079", Name: "Transfer Cloud Download", Slug: "transfer_cloud_download", Description: "Download from transfer cloud", MinPlan: "business"},
		{ID: "api_s080", Name: "Transfer Cloud List", Slug: "transfer_cloud_list", Description: "List cloud transfers", MinPlan: "business"},
		{ID: "api_s081", Name: "Transfer Bundle Create", Slug: "transfer_bundle_create", Description: "Create transfer bundle", MinPlan: "business"},
		{ID: "api_s082", Name: "Transfer Bundle Import", Slug: "transfer_bundle_import", Description: "Import transfer bundle", MinPlan: "business"},
		{ID: "api_s083", Name: "Transfer Bundle QR Generate", Slug: "transfer_bundle_qr_generate", Description: "Generate bundle QR", MinPlan: "business"},
		{ID: "api_s084", Name: "Transfer Bundle QR Scan", Slug: "transfer_bundle_qr_scan", Description: "Scan bundle QR", MinPlan: "business"},
		{ID: "api_s085", Name: "Transfer Schedule List", Slug: "transfer_schedule_list", Description: "List transfer schedules", MinPlan: "business"},
		{ID: "api_s086", Name: "Transfer Schedule Create", Slug: "transfer_schedule_create", Description: "Create transfer schedule", MinPlan: "business"},
		{ID: "api_s087", Name: "Transfer Schedule Update", Slug: "transfer_schedule_update", Description: "Update transfer schedule", MinPlan: "business"},
		{ID: "api_s088", Name: "Transfer Schedule Delete", Slug: "transfer_schedule_delete", Description: "Delete transfer schedule", MinPlan: "business"},
		{ID: "api_s089", Name: "Transfer Schedule Pause", Slug: "transfer_schedule_pause", Description: "Pause transfer schedule", MinPlan: "business"},
		{ID: "api_s090", Name: "Transfer Schedule Resume", Slug: "transfer_schedule_resume", Description: "Resume transfer schedule", MinPlan: "business"},
		{ID: "api_s091", Name: "Transfer Schedule Run", Slug: "transfer_schedule_run", Description: "Run scheduled transfer", MinPlan: "business"},
		{ID: "api_s092", Name: "Transfer History", Slug: "transfer_history", Description: "Transfer history feed", MinPlan: "business"},
		{ID: "api_s093", Name: "Transfer Audit", Slug: "transfer_audit", Description: "Transfer audit records", MinPlan: "business"},
		{ID: "api_s094", Name: "Transfer Manifest Get", Slug: "transfer_manifest_get", Description: "Fetch transfer manifest", MinPlan: "business"},
		{ID: "api_s095", Name: "Transfer Manifest Verify", Slug: "transfer_manifest_verify", Description: "Verify transfer manifest", MinPlan: "business"},

		// Export/Import (Personal+)
		{ID: "api_s096", Name: "Export All", Slug: "export_all", Description: "Export all data via API", MinPlan: "personal"},
		{ID: "api_s097", Name: "Import All", Slug: "import_all", Description: "Import all data via API", MinPlan: "personal"},
	}),
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
		// API feature is only enabled for Business+ plans
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
	case "business", "enterprise", "trial":
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
	return "1 GB"
}

// GetPlanStorageLimitBytes returns the storage limit in bytes
func GetPlanStorageLimitBytes(planSlug string) int64 {
	switch planSlug {
	case "trial":
		return -1 // Unlimited during trial
	case "personal":
		return 1073741824 // 1 GB
	case "solo":
		return 5368709120 // 5 GB
	case "team":
		return 26843545600 // 25 GB
	case "business", "enterprise":
		return -1 // Unlimited
	default:
		return 1073741824 // Default 1 GB
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

	// API is only available for Business+
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

	// API is only available for Business+, so denied for lower plans
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

// MigrateTransferScopes adds the transfer feature scopes to the API feature if they don't already exist.
// This is a migration function that can be called to ensure the transfer scopes are present
// without requiring a full bootstrap. It's idempotent and safe to call multiple times.
func MigrateTransferScopes(ctx context.Context, storage Storage) error {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()

	var transferScopes []secretrScopeDefinition
	for _, scope := range apiFeature.Scopes {
		if strings.HasPrefix(scope.Slug, "transfer_") {
			transferScopes = append(transferScopes, scope)
		}
	}
	if len(transferScopes) == 0 {
		return nil
	}

	for _, scopeDef := range transferScopes {
		scope := &FeatureScope{
			ID:         scopeDef.ID,
			FeatureID:  apiFeature.ID,
			Name:       scopeDef.Name,
			Slug:       scopeDef.Slug,
			Permission: ScopePermissionAllow,
			Metadata: map[string]string{
				"description": scopeDef.Description,
			},
			CreatedAt: now,
			UpdatedAt: now,
		}
		if err := upsertFeatureScope(ctx, storage, scope); err != nil {
			return fmt.Errorf("migrate transfer scope %s: %w", scopeDef.Slug, err)
		}
	}

	return nil
}
