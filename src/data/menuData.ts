// Secretr Licensing Plans Reference Data
// This data mirrors the Go backend definitions for reference in the web UI

export interface PlanDefinition {
    id: string;
    name: string;
    slug: string;
    description: string;
    pricePerDevice: number; // cents per device per year
    minDevices: number;
    storageLimit: string;
    billingCycle: string;
    trialDays: number;
    isTrial: boolean;
    displayOrder: number;
    isActive: boolean;
}

export interface ScopeDefinition {
    id: string;
    name: string;
    slug: string;
    description: string;
    minPlan?: string; // Minimum plan slug required (if restricted)
}

export interface FeatureDefinition {
    id: string;
    name: string;
    slug: string;
    category: string;
    description: string;
    scopes: ScopeDefinition[];
}

// Plan Definitions based on PLANS.md
export const planDefinitions: PlanDefinition[] = [
    {
        id: "plan_secretr_trial",
        name: "Free Trial",
        slug: "trial",
        description: "Try everything before you buy. Full access to all features for 14 days. No credit card required.",
        pricePerDevice: 0,
        minDevices: 1,
        storageLimit: "Unlimited",
        billingCycle: "trial",
        trialDays: 14,
        isTrial: true,
        displayOrder: 0,
        isActive: true,
    },
    {
        id: "plan_secretr_personal",
        name: "Personal",
        slug: "personal",
        description: "Best for: Individual developers managing personal secrets",
        pricePerDevice: 1500, // $15/device/year
        minDevices: 1,
        storageLimit: "1 GB",
        billingCycle: "yearly",
        trialDays: 0,
        isTrial: false,
        displayOrder: 1,
        isActive: true,
    },
    {
        id: "plan_secretr_solo",
        name: "Solo",
        slug: "solo",
        description: "Best for: Power users and freelancers with multiple workstations",
        pricePerDevice: 4000, // $40/device/year
        minDevices: 2,
        storageLimit: "5 GB",
        billingCycle: "yearly",
        trialDays: 0,
        isTrial: false,
        displayOrder: 2,
        isActive: true,
    },
    {
        id: "plan_secretr_team",
        name: "Team",
        slug: "team",
        description: "Best for: Small teams collaborating on projects",
        pricePerDevice: 7800, // $78/device/year
        minDevices: 5,
        storageLimit: "25 GB",
        billingCycle: "yearly",
        trialDays: 0,
        isTrial: false,
        displayOrder: 3,
        isActive: true,
    },
    {
        id: "plan_secretr_business",
        name: "Business",
        slug: "business",
        description: "Best for: Growing organizations with centralized secret management needs",
        pricePerDevice: 13500, // $135/device/year
        minDevices: 15,
        storageLimit: "Unlimited",
        billingCycle: "yearly",
        trialDays: 0,
        isTrial: false,
        displayOrder: 4,
        isActive: true,
    },
    {
        id: "plan_secretr_enterprise",
        name: "Enterprise",
        slug: "enterprise",
        description: "Best for: Organizations with strict compliance and governance requirements. Custom SLAs, dedicated support, on-premises deployment assistance.",
        pricePerDevice: 0, // Custom pricing
        minDevices: 50,
        storageLimit: "Unlimited",
        billingCycle: "yearly",
        trialDays: 0,
        isTrial: false,
        displayOrder: 5,
        isActive: true,
    },
];

// CLI Feature Scopes (83 scopes)
export const cliScopes: ScopeDefinition[] = [
    // Basic Operations (All Plans)
    { id: "cli_s001", name: "Get Secret", slug: "get", description: "Get a secret value" },
    { id: "cli_s002", name: "Set Secret", slug: "set", description: "Set a secret value" },
    { id: "cli_s003", name: "List Secrets", slug: "list", description: "List all secrets" },
    { id: "cli_s004", name: "Delete Secret", slug: "delete", description: "Delete a secret" },
    { id: "cli_s005", name: "Copy Secret", slug: "copy", description: "Copy secret to clipboard" },
    { id: "cli_s006", name: "Secret Password", slug: "secret-password", description: "Manage secret passwords" },

    // SSH Management (All Plans)
    { id: "cli_s007", name: "SSH", slug: "ssh", description: "SSH operations" },
    { id: "cli_s008", name: "SSH Key", slug: "ssh-key", description: "Manage SSH keys" },
    { id: "cli_s009", name: "SSH Profile", slug: "ssh-profile", description: "Manage SSH profiles" },

    // File Management (All Plans)
    { id: "cli_s010", name: "Files", slug: "files", description: "File vault operations" },

    // Sharing & Collaboration
    { id: "cli_s011", name: "Share", slug: "share", description: "ACL-based share secrets", minPlan: "business" },
    { id: "cli_s012", name: "P2P Share", slug: "p2p-share", description: "P2P sharing on LAN", minPlan: "solo" },
    { id: "cli_s013", name: "P2P", slug: "p2p", description: "P2P operations", minPlan: "solo" },

    // Container Security
    { id: "cli_s014", name: "Container", slug: "container", description: "Container operations", minPlan: "enterprise" },

    // Backup & Recovery (All Plans)
    { id: "cli_s015", name: "Backup", slug: "backup", description: "Backup operations" },
    { id: "cli_s016", name: "Export", slug: "export", description: "Export data" },
    { id: "cli_s017", name: "Import", slug: "import", description: "Import data" },

    // Generators (Personal+)
    { id: "cli_s018", name: "Generate JWT", slug: "gen-jwt", description: "Generate JWT secrets" },
    { id: "cli_s019", name: "Generate API Key", slug: "gen-apikey", description: "Generate API keys" },
    { id: "cli_s020", name: "Generate Keypair", slug: "gen-keypair", description: "Generate keypairs" },
    { id: "cli_s021", name: "Generate Symmetric Key", slug: "gen-symkey", description: "Generate symmetric keys" },
    { id: "cli_s022", name: "Dynamic Secrets", slug: "dynamic", description: "Dynamic secret generation" },

    // Templates
    { id: "cli_s023", name: "Template", slug: "template", description: "Secret templates", minPlan: "team" },

    // Secret Rotation
    { id: "cli_s024", name: "Rotate", slug: "rotate", description: "Secret rotation", minPlan: "team" },

    // Tenant Management
    { id: "cli_s025", name: "Tenant", slug: "tenant", description: "Tenant management", minPlan: "business" },

    // Import/Export Advanced (All Plans)
    { id: "cli_s026", name: "From File", slug: "from-file", description: "Import from file" },
    { id: "cli_s027", name: "To File", slug: "to-file", description: "Export to file" },
    { id: "cli_s028", name: "Pull", slug: "pull", description: "Pull secrets" },
    { id: "cli_s029", name: "Push", slug: "push", description: "Push secrets" },
    { id: "cli_s030", name: "Server Export", slug: "server-export", description: "Server export operations" },

    // Scratchpad
    { id: "cli_s031", name: "Scratchpad", slug: "scratchpad", description: "Encrypted scratchpads", minPlan: "team" },

    // Environment (All Plans)
    { id: "cli_s032", name: "Print Env", slug: "printenv", description: "Print environment variables" },
    { id: "cli_s033", name: "Env", slug: "env", description: "Environment operations" },
    { id: "cli_s034", name: "Enrich", slug: "enrich", description: "Enrich process environment" },

    // Cryptography (All Plans)
    { id: "cli_s035", name: "Certificate", slug: "certificate", description: "Certificate operations" },
    { id: "cli_s036", name: "Sign", slug: "sign", description: "Sign data" },
    { id: "cli_s037", name: "Verify", slug: "verify", description: "Verify signatures" },
    { id: "cli_s038", name: "Hash", slug: "hash", description: "Hash operations" },

    // Versioning
    { id: "cli_s039", name: "List KV Versions", slug: "listkv", description: "List KV versions", minPlan: "solo" },
    { id: "cli_s040", name: "Rollback KV", slug: "rollbackkv", description: "Rollback KV versions", minPlan: "solo" },

    // Security Sandbox
    { id: "cli_s041", name: "Sandbox", slug: "sandbox", description: "Sandbox execution", minPlan: "business" },
    { id: "cli_s042", name: "Secure Sandbox", slug: "secure-sandbox", description: "Secure sandbox execution", minPlan: "business" },
    { id: "cli_s043", name: "SSB", slug: "ssb", description: "Secure sandbox shorthand", minPlan: "business" },

    // Security Policy (Personal+)
    { id: "cli_s044", name: "Security Policy", slug: "security-policy", description: "Security policy configuration" },
    { id: "cli_s045", name: "Sec Policy", slug: "sec-policy", description: "Security policy shorthand" },

    // Vault Security (Personal+)
    { id: "cli_s046", name: "Vault Security", slug: "vault-security", description: "Vault security operations" },
    { id: "cli_s047", name: "VSec", slug: "vsec", description: "Vault security shorthand" },

    // Observability (Personal+)
    { id: "cli_s048", name: "Observability", slug: "observability", description: "Observability commands" },
    { id: "cli_s049", name: "Obs", slug: "obs", description: "Observability shorthand" },

    // FIPS Compliance
    { id: "cli_s050", name: "FIPS", slug: "fips", description: "FIPS mode operations", minPlan: "enterprise" },
    { id: "cli_s051", name: "FIPS-140", slug: "fips-140", description: "FIPS 140 compliance", minPlan: "enterprise" },

    // Compliance Frameworks
    { id: "cli_s052", name: "Compliance", slug: "compliance", description: "Compliance framework operations", minPlan: "enterprise" },
    { id: "cli_s053", name: "Comp", slug: "comp", description: "Compliance shorthand", minPlan: "enterprise" },

    // Data Classification
    { id: "cli_s054", name: "Classify", slug: "classify", description: "Data classification", minPlan: "enterprise" },
    { id: "cli_s055", name: "Data Classification", slug: "data-classification", description: "Data classification full", minPlan: "enterprise" },
    { id: "cli_s056", name: "DC", slug: "dc", description: "Data classification shorthand", minPlan: "enterprise" },

    // Data Retention
    { id: "cli_s057", name: "Retention", slug: "retention", description: "Data retention policies", minPlan: "business" },
    { id: "cli_s058", name: "Ret", slug: "ret", description: "Retention shorthand", minPlan: "business" },

    // Breach Management
    { id: "cli_s059", name: "Breach", slug: "breach", description: "Breach management", minPlan: "enterprise" },
    { id: "cli_s060", name: "Breach Notification", slug: "breach-notification", description: "Breach notifications", minPlan: "enterprise" },

    // Access Review
    { id: "cli_s061", name: "Access Review", slug: "access-review", description: "Access review workflow", minPlan: "enterprise" },
    { id: "cli_s062", name: "AR", slug: "ar", description: "Access review shorthand", minPlan: "enterprise" },
    { id: "cli_s063", name: "Access Reviews", slug: "access-reviews", description: "Access reviews list", minPlan: "enterprise" },

    // Authentication
    { id: "cli_s064", name: "Enable 2FA", slug: "enable-2fa", description: "Enable two-factor auth", minPlan: "solo" },
    { id: "cli_s065", name: "Disable 2FA", slug: "disable-2fa", description: "Disable two-factor auth", minPlan: "solo" },
    { id: "cli_s066", name: "Enable Passkey", slug: "enable-passkey", description: "Enable passkey auth", minPlan: "solo" },
    { id: "cli_s067", name: "Disable Passkey", slug: "disable-passkey", description: "Disable passkey auth", minPlan: "solo" },
    { id: "cli_s068", name: "Enable Share Prompts", slug: "enable-share-prompts", description: "Enable share prompts" },

    // System Commands
    { id: "cli_s069", name: "Server", slug: "server", description: "Server mode operations", minPlan: "business" },
    { id: "cli_s070", name: "KDS", slug: "kds", description: "Key distribution server", minPlan: "business" },
    { id: "cli_s071", name: "Server Config", slug: "server-config", description: "Server configuration", minPlan: "business" },

    // Version Control
    { id: "cli_s072", name: "VCS", slug: "vcs", description: "Version control operations", minPlan: "solo" },

    // Vault Storage & Compaction
    { id: "cli_s073", name: "Compact", slug: "compact", description: "Vault compaction", minPlan: "team" },
    { id: "cli_s074", name: "Vault Compact", slug: "vault-compact", description: "Vault compaction full", minPlan: "team" },

    // Shamir Secret Sharing
    { id: "cli_s075", name: "Shamir", slug: "shamir", description: "Shamir secret sharing", minPlan: "solo" },
    { id: "cli_s076", name: "Shamir Split", slug: "shamir-split", description: "Split secret with Shamir", minPlan: "solo" },
    { id: "cli_s077", name: "Shamir Combine", slug: "shamir-combine", description: "Combine Shamir shares", minPlan: "solo" },

    // Audit Logs
    { id: "cli_s078", name: "Audit", slug: "audit", description: "Audit log operations", minPlan: "solo" },
    { id: "cli_s079", name: "Audit Log", slug: "audit-log", description: "Audit log viewing", minPlan: "solo" },

    // Config Injection
    { id: "cli_s080", name: "Inject", slug: "inject", description: "Config injection", minPlan: "business" },
    { id: "cli_s081", name: "Config Inject", slug: "config-inject", description: "Config file injection", minPlan: "business" },

    // Container Security Audit
    { id: "cli_s082", name: "Container Audit", slug: "container-audit", description: "Container security audit", minPlan: "enterprise" },
    { id: "cli_s083", name: "CSA", slug: "csa", description: "Container security audit shorthand", minPlan: "enterprise" },
];

// GUI Feature Scopes (37 scopes)
export const guiScopes: ScopeDefinition[] = [
    // CRUD Operations (All Plans)
    { id: "gui_s001", name: "View", slug: "view", description: "View secrets and data" },
    { id: "gui_s002", name: "List", slug: "list", description: "List items" },
    { id: "gui_s003", name: "Create", slug: "create", description: "Create new items" },
    { id: "gui_s004", name: "Update", slug: "update", description: "Update existing items" },
    { id: "gui_s005", name: "Delete", slug: "delete", description: "Delete items" },
    { id: "gui_s006", name: "Edit", slug: "edit", description: "Edit items" },

    // Secret Management Views (All Plans)
    { id: "gui_s007", name: "Secret Manager", slug: "secret_manager", description: "Secret management interface" },
    { id: "gui_s008", name: "Secret Search", slug: "secret_search", description: "Search secrets" },
    { id: "gui_s009", name: "Secret Filter", slug: "secret_filter", description: "Filter secrets" },
    { id: "gui_s010", name: "Password Protection", slug: "password_protection", description: "Password protection for secrets" },

    // File Management Views (All Plans)
    { id: "gui_s011", name: "File Manager", slug: "file_manager", description: "File management interface" },
    { id: "gui_s012", name: "File Upload", slug: "file_upload", description: "Upload files" },
    { id: "gui_s013", name: "File Download", slug: "file_download", description: "Download files" },

    // Generator Views (All Plans)
    { id: "gui_s014", name: "Password Generator", slug: "password_generator", description: "Generate passwords" },
    { id: "gui_s015", name: "SSH Key Generator", slug: "ssh_key_generator", description: "Generate SSH keys" },
    { id: "gui_s016", name: "Certificate Generator", slug: "certificate_generator", description: "Generate certificates" },
    { id: "gui_s017", name: "Hash Generator", slug: "hash_generator", description: "Generate hashes" },

    // SSH Management Views (All Plans)
    { id: "gui_s018", name: "SSH Profiles", slug: "ssh_profiles", description: "SSH profile management" },
    { id: "gui_s019", name: "SSH Terminal", slug: "ssh_terminal", description: "SSH terminal interface" },
    { id: "gui_s020", name: "SSH Import", slug: "ssh_import", description: "Import SSH keys" },

    // P2P Sharing Views
    { id: "gui_s021", name: "P2P Share", slug: "p2p_share", description: "P2P sharing interface", minPlan: "solo" },
    { id: "gui_s022", name: "P2P Discover", slug: "p2p_discover", description: "Discover P2P peers", minPlan: "solo" },
    { id: "gui_s023", name: "P2P Receive", slug: "p2p_receive", description: "Receive P2P shares", minPlan: "solo" },

    // Cryptographic Operations Views (All Plans)
    { id: "gui_s024", name: "Sign Data", slug: "sign_data", description: "Data signing interface" },
    { id: "gui_s025", name: "Verify Signature", slug: "verify_signature", description: "Signature verification" },

    // Management Views
    { id: "gui_s026", name: "Templates", slug: "templates", description: "Template management", minPlan: "team" },
    { id: "gui_s027", name: "Rotation", slug: "rotation", description: "Secret rotation management", minPlan: "team" },
    { id: "gui_s028", name: "Backup Restore", slug: "backup_restore", description: "Backup and restore interface" },
    { id: "gui_s029", name: "Scratchpad", slug: "scratchpad", description: "Scratchpad interface", minPlan: "team" },

    // Compliance Views
    { id: "gui_s030", name: "Compliance Dashboard", slug: "compliance_dashboard", description: "Compliance dashboard", minPlan: "enterprise" },
    { id: "gui_s031", name: "Data Classification", slug: "data_classification", description: "Data classification interface", minPlan: "enterprise" },
    { id: "gui_s032", name: "Data Retention", slug: "data_retention", description: "Data retention interface", minPlan: "business" },
    { id: "gui_s033", name: "Breach Notification", slug: "breach_notification", description: "Breach notification interface", minPlan: "enterprise" },
    { id: "gui_s034", name: "Access Reviews", slug: "access_reviews", description: "Access reviews interface", minPlan: "enterprise" },
    { id: "gui_s035", name: "FIPS Compliance", slug: "fips_compliance", description: "FIPS compliance interface", minPlan: "enterprise" },

    // Security Views
    { id: "gui_s036", name: "Two Factor Auth", slug: "two_factor_auth", description: "2FA management", minPlan: "solo" },
    { id: "gui_s037", name: "Vault Lock", slug: "vault_lock", description: "Vault lock controls" },
];

// API Feature Scopes (69 scopes)
export const apiScopes: ScopeDefinition[] = [
    // Setup & Configuration
    { id: "api_s001", name: "Setup Check", slug: "setup_check", description: "Check setup status", minPlan: "business" },
    { id: "api_s002", name: "Setup Complete", slug: "setup_complete", description: "Complete setup", minPlan: "business" },
    { id: "api_s003", name: "Admin Regenerate Key", slug: "admin_regenerate_key", description: "Regenerate admin key", minPlan: "business" },

    // Authentication
    { id: "api_s004", name: "Auth Login", slug: "auth_login", description: "Authenticate user", minPlan: "business" },
    { id: "api_s005", name: "Auth Sessions List", slug: "auth_sessions_list", description: "List active sessions", minPlan: "business" },
    { id: "api_s006", name: "Auth Sessions Revoke", slug: "auth_sessions_revoke", description: "Revoke sessions", minPlan: "business" },

    // Two-Factor Authentication
    { id: "api_s007", name: "2FA Status", slug: "2fa_status", description: "Get 2FA status", minPlan: "business" },
    { id: "api_s008", name: "2FA Setup Start", slug: "2fa_setup_start", description: "Start 2FA setup", minPlan: "business" },
    { id: "api_s009", name: "2FA Setup Verify", slug: "2fa_setup_verify", description: "Verify 2FA setup", minPlan: "business" },
    { id: "api_s010", name: "2FA Verify", slug: "2fa_verify", description: "Verify 2FA code", minPlan: "business" },
    { id: "api_s011", name: "2FA Disable", slug: "2fa_disable", description: "Disable 2FA", minPlan: "business" },
    { id: "api_s012", name: "2FA Backup Code", slug: "2fa_backup_code", description: "Get backup codes", minPlan: "business" },

    // Secrets Management
    { id: "api_s013", name: "Secrets Read", slug: "secrets_read", description: "Read secrets via API", minPlan: "business" },
    { id: "api_s014", name: "Secrets Write", slug: "secrets_write", description: "Write secrets via API", minPlan: "business" },
    { id: "api_s015", name: "Secrets Delete", slug: "secrets_delete", description: "Delete secrets via API", minPlan: "business" },
    { id: "api_s016", name: "Secrets List", slug: "secrets_list", description: "List secrets via API", minPlan: "business" },

    // KV Versioning
    { id: "api_s017", name: "KV Versions List", slug: "kv_versions_list", description: "List KV versions", minPlan: "business" },
    { id: "api_s018", name: "KV Rollback", slug: "kv_rollback", description: "Rollback KV version", minPlan: "business" },

    // Transit Engine
    { id: "api_s019", name: "Transit Encrypt", slug: "transit_encrypt", description: "Transit encryption", minPlan: "business" },
    { id: "api_s020", name: "Transit Decrypt", slug: "transit_decrypt", description: "Transit decryption", minPlan: "business" },

    // Dynamic Engines
    { id: "api_s021", name: "Dynamic Database", slug: "dynamic_database", description: "Dynamic database credentials", minPlan: "business" },
    { id: "api_s022", name: "Dynamic Cloud", slug: "dynamic_cloud", description: "Dynamic cloud tokens", minPlan: "business" },
    { id: "api_s023", name: "Dynamic Verify", slug: "dynamic_verify", description: "Verify dynamic credentials", minPlan: "business" },

    // Response Wrapping
    { id: "api_s024", name: "Wrap Response", slug: "wrap_response", description: "Wrap API response", minPlan: "business" },
    { id: "api_s025", name: "Unwrap Response", slug: "unwrap_response", description: "Unwrap API response", minPlan: "business" },

    // File Management
    { id: "api_s026", name: "Files List", slug: "files_list", description: "List files via API", minPlan: "business" },
    { id: "api_s027", name: "Files Upload", slug: "files_upload", description: "Upload files via API", minPlan: "business" },
    { id: "api_s028", name: "Files Download", slug: "files_download", description: "Download files via API", minPlan: "business" },
    { id: "api_s029", name: "Files Delete", slug: "files_delete", description: "Delete files via API", minPlan: "business" },
    { id: "api_s030", name: "Files Render", slug: "files_render", description: "Render files via API", minPlan: "business" },

    // SSH Management
    { id: "api_s031", name: "SSH Keys Get", slug: "ssh_keys_get", description: "Get SSH keys", minPlan: "business" },
    { id: "api_s032", name: "SSH Keys Create", slug: "ssh_keys_create", description: "Create SSH keys", minPlan: "business" },
    { id: "api_s033", name: "SSH Keys Delete", slug: "ssh_keys_delete", description: "Delete SSH keys", minPlan: "business" },
    { id: "api_s034", name: "SSH Keys List", slug: "ssh_keys_list", description: "List SSH keys", minPlan: "business" },
    { id: "api_s035", name: "SSH Profiles Get", slug: "ssh_profiles_get", description: "Get SSH profiles", minPlan: "business" },
    { id: "api_s036", name: "SSH Profiles Create", slug: "ssh_profiles_create", description: "Create SSH profiles", minPlan: "business" },
    { id: "api_s037", name: "SSH Profiles Delete", slug: "ssh_profiles_delete", description: "Delete SSH profiles", minPlan: "business" },
    { id: "api_s038", name: "SSH Profiles List", slug: "ssh_profiles_list", description: "List SSH profiles", minPlan: "business" },

    // Certificate Management
    { id: "api_s039", name: "Certificate Generate", slug: "certificate_generate", description: "Generate certificates", minPlan: "business" },

    // Key Generation
    { id: "api_s040", name: "Generate JWT", slug: "generate_jwt", description: "Generate JWT secrets", minPlan: "business" },
    { id: "api_s041", name: "Generate API Key", slug: "generate_apikey", description: "Generate API keys", minPlan: "business" },
    { id: "api_s042", name: "Generate Keypair", slug: "generate_keypair", description: "Generate keypairs", minPlan: "business" },
    { id: "api_s043", name: "Generate Symmetric Key", slug: "generate_symkey", description: "Generate symmetric keys", minPlan: "business" },

    // Managed Keys
    { id: "api_s044", name: "Managed Keys List", slug: "managed_keys_list", description: "List managed keys", minPlan: "business" },
    { id: "api_s045", name: "Managed Keys Create", slug: "managed_keys_create", description: "Create managed keys", minPlan: "business" },
    { id: "api_s046", name: "Managed Keys Rotate", slug: "managed_keys_rotate", description: "Rotate managed keys", minPlan: "business" },
    { id: "api_s047", name: "Managed Keys Archive", slug: "managed_keys_archive", description: "Archive managed keys", minPlan: "business" },
    { id: "api_s048", name: "Managed Keys Destroy", slug: "managed_keys_destroy", description: "Destroy managed keys", minPlan: "business" },

    // User Management
    { id: "api_s049", name: "Users Scopes List", slug: "users_scopes_list", description: "List user scopes", minPlan: "business" },
    { id: "api_s050", name: "Users List", slug: "users_list", description: "List users", minPlan: "business" },
    { id: "api_s051", name: "Users Create", slug: "users_create", description: "Create users", minPlan: "business" },
    { id: "api_s052", name: "Users Get", slug: "users_get", description: "Get user details", minPlan: "business" },
    { id: "api_s053", name: "Users Update", slug: "users_update", description: "Update users", minPlan: "business" },
    { id: "api_s054", name: "Users Delete", slug: "users_delete", description: "Delete users", minPlan: "business" },
    { id: "api_s055", name: "Users API Keys List", slug: "users_apikeys_list", description: "List user API keys", minPlan: "business" },
    { id: "api_s056", name: "Users API Keys Create", slug: "users_apikeys_create", description: "Create user API keys", minPlan: "business" },
    { id: "api_s057", name: "Users API Keys Get", slug: "users_apikeys_get", description: "Get user API keys", minPlan: "business" },
    { id: "api_s058", name: "Users API Keys Update", slug: "users_apikeys_update", description: "Update user API keys", minPlan: "business" },
    { id: "api_s059", name: "Users API Keys Revoke", slug: "users_apikeys_revoke", description: "Revoke user API keys", minPlan: "business" },

    // Tenant Management
    { id: "api_s060", name: "Tenants Add", slug: "tenants_add", description: "Add tenants", minPlan: "business" },
    { id: "api_s061", name: "Tenants List", slug: "tenants_list", description: "List tenants", minPlan: "business" },
    { id: "api_s062", name: "Tenants Set Key", slug: "tenants_setkey", description: "Set tenant key", minPlan: "business" },
    { id: "api_s063", name: "Tenants Get Key", slug: "tenants_getkey", description: "Get tenant key", minPlan: "business" },
    { id: "api_s064", name: "Tenants Set Secret", slug: "tenants_set_secret", description: "Set tenant secret", minPlan: "business" },
    { id: "api_s065", name: "Tenants Get Secret", slug: "tenants_get_secret", description: "Get tenant secret", minPlan: "business" },

    // Groups & Namespaces
    { id: "api_s066", name: "Groups Add", slug: "groups_add", description: "Add groups", minPlan: "business" },
    { id: "api_s067", name: "Groups Generate Secret", slug: "groups_generate_secret", description: "Generate group secret", minPlan: "business" },

    // Export/Import
    { id: "api_s068", name: "Export All", slug: "export_all", description: "Export all data via API", minPlan: "business" },
    { id: "api_s069", name: "Import All", slug: "import_all", description: "Import all data via API", minPlan: "business" },
];

// Feature Definitions
export const featureDefinitions: FeatureDefinition[] = [
    {
        id: "feat_cli_001",
        name: "CLI",
        slug: "cli",
        category: "interface",
        description: "Command-line interface access for Secretr operations",
        scopes: cliScopes,
    },
    {
        id: "feat_gui_001",
        name: "GUI",
        slug: "gui",
        category: "interface",
        description: "Desktop GUI application access",
        scopes: guiScopes,
    },
    {
        id: "feat_api_001",
        name: "API",
        slug: "api",
        category: "integration",
        description: "HTTP API access (requires Business+ plan)",
        scopes: apiScopes,
    },
];

// Helper functions
export const getPlanBySlug = (slug: string): PlanDefinition | undefined => {
    return planDefinitions.find((p) => p.slug === slug);
};

export const getFeatureBySlug = (slug: string): FeatureDefinition | undefined => {
    return featureDefinitions.find((f) => f.slug === slug);
};

export const isScopeAvailableForPlan = (scopeMinPlan: string | undefined, planSlug: string): boolean => {
    if (!scopeMinPlan) return true; // No restriction means available for all plans

    const planOrder = ["personal", "solo", "team", "business", "enterprise"];
    const minPlanIndex = planOrder.indexOf(scopeMinPlan);
    const currentPlanIndex = planOrder.indexOf(planSlug);

    return currentPlanIndex >= minPlanIndex;
};

export const getScopeSummary = () => ({
    cli: cliScopes.length,
    gui: guiScopes.length,
    api: apiScopes.length,
    total: cliScopes.length + guiScopes.length + apiScopes.length,
});

export const getStorageLimitBytes = (planSlug: string): number => {
    switch (planSlug) {
        case "trial":
            return -1; // Unlimited during trial
        case "personal":
            return 1073741824; // 1 GB
        case "solo":
            return 5368709120; // 5 GB
        case "team":
            return 26843545600; // 25 GB
        case "business":
        case "enterprise":
            return -1; // Unlimited
        default:
            return 1073741824; // Default 1 GB
    }
};

export const getMinACV = (planSlug: string): number => {
    const plan = getPlanBySlug(planSlug);
    if (!plan || plan.pricePerDevice === 0) return 0;
    return plan.pricePerDevice * plan.minDevices;
};
