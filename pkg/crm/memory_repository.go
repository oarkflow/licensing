package crm

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// MemoryRepository is an in-memory implementation of Repository for tests and prototypes.
type MemoryRepository struct {
	mu sync.RWMutex

	tenants         map[string]*Tenant
	slugIndex       map[string]string
	settings        map[string]*TenantSettings
	users           map[string]*CRMUser
	contacts        map[string]*Contact
	secrets         map[string]*CredentialSecret
	sessions        map[string]*SessionToken
	entitlements    map[string]*EntitlementBinding
	releases        map[string]*ProductRelease
	devices         map[string]*DeviceLedger
	deviceIndex     map[string]string // fingerprint -> ledgerID (per tenant keyed via helper)
	serviceAccounts map[string]*ServiceAccount
}

// NewMemoryRepository returns a zero-dependency Repository implementation.
func NewMemoryRepository() *MemoryRepository {
	return &MemoryRepository{
		tenants:         make(map[string]*Tenant),
		slugIndex:       make(map[string]string),
		settings:        make(map[string]*TenantSettings),
		users:           make(map[string]*CRMUser),
		contacts:        make(map[string]*Contact),
		secrets:         make(map[string]*CredentialSecret),
		sessions:        make(map[string]*SessionToken),
		entitlements:    make(map[string]*EntitlementBinding),
		releases:        make(map[string]*ProductRelease),
		devices:         make(map[string]*DeviceLedger),
		deviceIndex:     make(map[string]string),
		serviceAccounts: make(map[string]*ServiceAccount),
	}
}

// Tenant operations

func (r *MemoryRepository) CreateTenant(_ context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is nil")
	}
	key := normalizeKey(tenant.Slug)
	if key == "" {
		return fmt.Errorf("tenant slug required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tenants[tenant.ID]; exists {
		return ErrTenantExists
	}
	if _, taken := r.slugIndex[key]; taken {
		return ErrTenantExists
	}
	r.tenants[tenant.ID] = cloneTenant(tenant)
	r.slugIndex[key] = tenant.ID
	return nil
}

func (r *MemoryRepository) UpdateTenant(_ context.Context, tenant *Tenant) error {
	if tenant == nil {
		return fmt.Errorf("tenant is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.tenants[tenant.ID]; !exists {
		return ErrTenantMissing
	}
	oldKey := normalizeKey(r.tenants[tenant.ID].Slug)
	newKey := normalizeKey(tenant.Slug)
	if newKey == "" {
		return fmt.Errorf("tenant slug required")
	}
	if oldKey != newKey {
		if _, taken := r.slugIndex[newKey]; taken {
			return ErrTenantExists
		}
		delete(r.slugIndex, oldKey)
		r.slugIndex[newKey] = tenant.ID
	}
	r.tenants[tenant.ID] = cloneTenant(tenant)
	return nil
}

func (r *MemoryRepository) GetTenant(_ context.Context, tenantID string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tenant, ok := r.tenants[tenantID]
	if !ok {
		return nil, ErrTenantMissing
	}
	return cloneTenant(tenant), nil
}

func (r *MemoryRepository) GetTenantBySlug(_ context.Context, slug string) (*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.slugIndex[normalizeKey(slug)]
	if !ok {
		return nil, ErrTenantMissing
	}
	return cloneTenant(r.tenants[id]), nil
}

func (r *MemoryRepository) ListTenants(_ context.Context, opts ListTenantsOptions) ([]*Tenant, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	query := strings.ToLower(strings.TrimSpace(opts.Query))
	statusSet := make(map[TenantStatus]struct{}, len(opts.Statuses))
	for _, st := range opts.Statuses {
		statusSet[st] = struct{}{}
	}
	var list []*Tenant
	for _, tenant := range r.tenants {
		if len(statusSet) > 0 {
			if _, ok := statusSet[tenant.Status]; !ok {
				continue
			}
		}
		if query != "" {
			needle := strings.ToLower(tenant.Name + " " + tenant.Slug)
			if !strings.Contains(needle, query) {
				continue
			}
		}
		list = append(list, cloneTenant(tenant))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	start, end := clampWindow(len(list), opts.Offset, opts.Limit)
	return list[start:end], nil
}

func (r *MemoryRepository) SaveTenantSettings(_ context.Context, settings *TenantSettings) error {
	if settings == nil {
		return fmt.Errorf("settings is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.settings[settings.TenantID] = cloneTenantSettings(settings)
	return nil
}

func (r *MemoryRepository) GetTenantSettings(_ context.Context, tenantID string) (*TenantSettings, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	settings, ok := r.settings[tenantID]
	if !ok {
		return nil, ErrTenantMissing
	}
	return cloneTenantSettings(settings), nil
}

// Users

func (r *MemoryRepository) CreateCRMUser(_ context.Context, user *CRMUser) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}
	email := normalizeKey(user.Email)
	username := normalizeKey(user.Username)
	if email == "" || username == "" {
		return fmt.Errorf("email and username required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.users[user.ID]; exists {
		return ErrUserExists
	}
	if r.userExists(user.TenantID, func(u *CRMUser) bool { return normalizeKey(u.Email) == email }) {
		return ErrUserExists
	}
	if r.userExists(user.TenantID, func(u *CRMUser) bool { return normalizeKey(u.Username) == username }) {
		return ErrUserExists
	}
	r.users[user.ID] = cloneCRMUser(user)
	return nil
}

func (r *MemoryRepository) UpdateCRMUser(_ context.Context, user *CRMUser) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	current, ok := r.users[user.ID]
	if !ok {
		return ErrUserMissing
	}
	email := normalizeKey(user.Email)
	username := normalizeKey(user.Username)
	if email == "" || username == "" {
		return fmt.Errorf("email and username required")
	}
	if normalizeKey(current.Email) != email && r.userExists(user.TenantID, func(u *CRMUser) bool { return u.ID != user.ID && normalizeKey(u.Email) == email }) {
		return ErrUserExists
	}
	if normalizeKey(current.Username) != username && r.userExists(user.TenantID, func(u *CRMUser) bool { return u.ID != user.ID && normalizeKey(u.Username) == username }) {
		return ErrUserExists
	}
	r.users[user.ID] = cloneCRMUser(user)
	return nil
}

func (r *MemoryRepository) DeleteCRMUser(_ context.Context, userID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.users[userID]; !ok {
		return ErrUserMissing
	}
	delete(r.users, userID)
	return nil
}

func (r *MemoryRepository) GetCRMUser(_ context.Context, userID string) (*CRMUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	user, ok := r.users[userID]
	if !ok {
		return nil, ErrUserMissing
	}
	return cloneCRMUser(user), nil
}

func (r *MemoryRepository) GetCRMUserByEmail(_ context.Context, tenantID, email string) (*CRMUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	target := normalizeKey(email)
	for _, user := range r.users {
		if user.TenantID == tenantID && normalizeKey(user.Email) == target {
			return cloneCRMUser(user), nil
		}
	}
	return nil, ErrUserMissing
}

func (r *MemoryRepository) FindCRMUserByIdentifier(_ context.Context, identifier string) (*CRMUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	target := normalizeKey(identifier)
	for _, user := range r.users {
		if normalizeKey(user.Email) == target || normalizeKey(user.Username) == target {
			return cloneCRMUser(user), nil
		}
	}
	return nil, ErrUserMissing
}

func (r *MemoryRepository) ListCRMUsers(_ context.Context, tenantID string) ([]*CRMUser, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []*CRMUser
	for _, user := range r.users {
		if user.TenantID == tenantID {
			list = append(list, cloneCRMUser(user))
		}
	}
	sort.Slice(list, func(i, j int) bool { return strings.Compare(list[i].Email, list[j].Email) < 0 })
	return list, nil
}

// Contacts

func (r *MemoryRepository) CreateContact(_ context.Context, contact *Contact) error {
	if contact == nil {
		return fmt.Errorf("contact is nil")
	}
	email := normalizeKey(contact.Email)
	if email == "" {
		return fmt.Errorf("contact email required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.contacts[contact.ID]; exists {
		return ErrContactExists
	}
	if r.contactExists(contact.TenantID, contact.ID, email) {
		return ErrContactExists
	}
	r.contacts[contact.ID] = cloneContact(contact)
	return nil
}

func (r *MemoryRepository) UpdateContact(_ context.Context, contact *Contact) error {
	if contact == nil {
		return fmt.Errorf("contact is nil")
	}
	email := normalizeKey(contact.Email)
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.contacts[contact.ID]; !ok {
		return ErrContactMissing
	}
	if r.contactExists(contact.TenantID, contact.ID, email) {
		return ErrContactExists
	}
	r.contacts[contact.ID] = cloneContact(contact)
	return nil
}

func (r *MemoryRepository) DeleteContact(_ context.Context, contactID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.contacts[contactID]; !ok {
		return ErrContactMissing
	}
	delete(r.contacts, contactID)
	return nil
}

func (r *MemoryRepository) GetContact(_ context.Context, contactID string) (*Contact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	contact, ok := r.contacts[contactID]
	if !ok {
		return nil, ErrContactMissing
	}
	return cloneContact(contact), nil
}

func (r *MemoryRepository) ListContacts(_ context.Context, opts ListContactsOptions) ([]*Contact, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	query := strings.ToLower(strings.TrimSpace(opts.Query))
	tagSet := make(map[string]struct{}, len(opts.Tags))
	for _, tag := range opts.Tags {
		tagSet[strings.ToLower(tag)] = struct{}{}
	}
	var list []*Contact
	for _, contact := range r.contacts {
		if opts.TenantID != "" && contact.TenantID != opts.TenantID {
			continue
		}
		if opts.ClientID != "" && contact.ClientID != opts.ClientID {
			continue
		}
		if len(tagSet) > 0 && !contactHasTags(contact, tagSet) {
			continue
		}
		if query != "" {
			needle := strings.ToLower(contact.FirstName + " " + contact.LastName + " " + contact.Email)
			if !strings.Contains(needle, query) {
				continue
			}
		}
		list = append(list, cloneContact(contact))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	start, end := clampWindow(len(list), opts.Offset, opts.Limit)
	return list[start:end], nil
}

// Credential secrets

func (r *MemoryRepository) SaveCredentialSecret(_ context.Context, secret *CredentialSecret) error {
	if secret == nil {
		return fmt.Errorf("secret is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.secrets[secret.ID] = cloneCredentialSecret(secret)
	return nil
}

func (r *MemoryRepository) GetLatestCredentialSecret(_ context.Context, tenantID, subjectID string, _ SessionSubjectType, secretType CredentialSecretType) (*CredentialSecret, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var candidate *CredentialSecret
	for _, secret := range r.secrets {
		if secret.TenantID != tenantID {
			continue
		}
		if secretType != "" && secret.Type != secretType {
			continue
		}
		if subjectID != "" && secret.UserID != subjectID && secret.ContactID != subjectID {
			continue
		}
		if candidate == nil || secret.Version > candidate.Version {
			candidate = secret
		}
	}
	if candidate == nil {
		return nil, ErrSecretMissing
	}
	return cloneCredentialSecret(candidate), nil
}

func (r *MemoryRepository) ListCredentialSecrets(_ context.Context, tenantID, subjectID string, secretType CredentialSecretType) ([]*CredentialSecret, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []*CredentialSecret
	for _, secret := range r.secrets {
		if secret.TenantID != tenantID {
			continue
		}
		if secretType != "" && secret.Type != secretType {
			continue
		}
		if subjectID != "" && secret.UserID != subjectID && secret.ContactID != subjectID {
			continue
		}
		list = append(list, cloneCredentialSecret(secret))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Version > list[j].Version })
	return list, nil
}

// Sessions

func (r *MemoryRepository) CreateSessionToken(_ context.Context, token *SessionToken) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.sessions[token.ID]; exists {
		return fmt.Errorf("session already exists")
	}
	r.sessions[token.ID] = cloneSessionToken(token)
	return nil
}

func (r *MemoryRepository) UpdateSessionToken(_ context.Context, token *SessionToken) error {
	if token == nil {
		return fmt.Errorf("token is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.sessions[token.ID]; !ok {
		return ErrSessionMissing
	}
	r.sessions[token.ID] = cloneSessionToken(token)
	return nil
}

func (r *MemoryRepository) GetSessionToken(_ context.Context, tokenID string) (*SessionToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	token, ok := r.sessions[tokenID]
	if !ok {
		return nil, ErrSessionMissing
	}
	return cloneSessionToken(token), nil
}

func (r *MemoryRepository) ListActiveSessionTokens(_ context.Context, filter SessionTokenFilter) ([]*SessionToken, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	now := time.Now()
	var list []*SessionToken
	for _, token := range r.sessions {
		if filter.TenantID != "" && token.TenantID != filter.TenantID {
			continue
		}
		if filter.SubjectID != "" && token.SubjectID != filter.SubjectID {
			continue
		}
		if filter.SubjectType != "" && token.SubjectType != filter.SubjectType {
			continue
		}
		if !filter.IncludeRevoked {
			if !token.RevokedAt.IsZero() || token.ExpiresAt.Before(now) {
				continue
			}
		}
		list = append(list, cloneSessionToken(token))
	}
	return list, nil
}

func (r *MemoryRepository) RevokeSessionTokens(_ context.Context, filter SessionTokenFilter) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now()
	count := 0
	for _, token := range r.sessions {
		if filter.TenantID != "" && token.TenantID != filter.TenantID {
			continue
		}
		if filter.SubjectID != "" && token.SubjectID != filter.SubjectID {
			continue
		}
		if filter.SubjectType != "" && token.SubjectType != filter.SubjectType {
			continue
		}
		if token.RevokedAt.IsZero() {
			token.RevokedAt = now
			r.sessions[token.ID] = token
			count++
		}
	}
	return count, nil
}

// Entitlements

func (r *MemoryRepository) CreateEntitlementBinding(_ context.Context, binding *EntitlementBinding) error {
	if binding == nil {
		return fmt.Errorf("binding is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.entitlements[binding.ID]; exists {
		return ErrEntitlementExists
	}
	r.entitlements[binding.ID] = cloneEntitlement(binding)
	return nil
}

func (r *MemoryRepository) UpdateEntitlementBinding(_ context.Context, binding *EntitlementBinding) error {
	if binding == nil {
		return fmt.Errorf("binding is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.entitlements[binding.ID]; !ok {
		return ErrEntitlementMissing
	}
	r.entitlements[binding.ID] = cloneEntitlement(binding)
	return nil
}

func (r *MemoryRepository) GetEntitlementBinding(_ context.Context, bindingID string) (*EntitlementBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	binding, ok := r.entitlements[bindingID]
	if !ok {
		return nil, ErrEntitlementMissing
	}
	return cloneEntitlement(binding), nil
}

func (r *MemoryRepository) ListEntitlementBindings(_ context.Context, opts ListEntitlementsOptions) ([]*EntitlementBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	statusSet := make(map[EntitlementStatus]struct{}, len(opts.Statuses))
	for _, st := range opts.Statuses {
		statusSet[st] = struct{}{}
	}
	var list []*EntitlementBinding
	for _, binding := range r.entitlements {
		if opts.TenantID != "" && binding.TenantID != opts.TenantID {
			continue
		}
		if opts.ContactID != "" && binding.ContactID != opts.ContactID {
			continue
		}
		if opts.ProductID != "" && binding.ProductID != opts.ProductID {
			continue
		}
		if len(statusSet) > 0 {
			if _, ok := statusSet[binding.Status]; !ok {
				continue
			}
		}
		list = append(list, cloneEntitlement(binding))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].EffectiveAt.Before(list[j].EffectiveAt) })
	return list, nil
}

// Product releases

func (r *MemoryRepository) CreateProductRelease(_ context.Context, release *ProductRelease) error {
	if release == nil {
		return fmt.Errorf("release is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.releases[release.ID]; exists {
		return fmt.Errorf("release exists")
	}
	r.releases[release.ID] = cloneRelease(release)
	return nil
}

func (r *MemoryRepository) UpdateProductRelease(_ context.Context, release *ProductRelease) error {
	if release == nil {
		return fmt.Errorf("release is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.releases[release.ID]; !ok {
		return fmt.Errorf("release missing")
	}
	r.releases[release.ID] = cloneRelease(release)
	return nil
}

func (r *MemoryRepository) DeleteProductRelease(_ context.Context, releaseID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.releases[releaseID]; !ok {
		return fmt.Errorf("release missing")
	}
	delete(r.releases, releaseID)
	return nil
}

func (r *MemoryRepository) GetProductRelease(_ context.Context, releaseID string) (*ProductRelease, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	release, ok := r.releases[releaseID]
	if !ok {
		return nil, fmt.Errorf("release missing")
	}
	return cloneRelease(release), nil
}

func (r *MemoryRepository) ListProductReleases(_ context.Context, productID string, limit int) ([]*ProductRelease, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []*ProductRelease
	for _, release := range r.releases {
		if release.ProductID == productID {
			list = append(list, cloneRelease(release))
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].PublishedAt.After(list[j].PublishedAt) })
	start, end := clampWindow(len(list), 0, limit)
	return list[start:end], nil
}

// Device ledger

func (r *MemoryRepository) UpsertDeviceLedger(_ context.Context, record *DeviceLedger) error {
	if record == nil {
		return fmt.Errorf("device ledger is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if record.ID == "" {
		record.ID = fmt.Sprintf("ledger-%s-%s", record.TenantID, record.DeviceFingerprint)
	}
	key := deviceKey(record.TenantID, record.DeviceFingerprint)
	r.deviceIndex[key] = record.ID
	r.devices[record.ID] = cloneDeviceLedger(record)
	return nil
}

func (r *MemoryRepository) GetDeviceLedgerByFingerprint(_ context.Context, tenantID, fingerprint string) (*DeviceLedger, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	id, ok := r.deviceIndex[deviceKey(tenantID, fingerprint)]
	if !ok {
		return nil, fmt.Errorf("device ledger missing")
	}
	return cloneDeviceLedger(r.devices[id]), nil
}

func (r *MemoryRepository) ListDeviceLedgers(_ context.Context, filter DeviceLedgerFilter) ([]*DeviceLedger, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []*DeviceLedger
	for _, record := range r.devices {
		if filter.TenantID != "" && record.TenantID != filter.TenantID {
			continue
		}
		if filter.ClientID != "" && record.ClientID != filter.ClientID {
			continue
		}
		if filter.LicenseID != "" && record.LicenseID != filter.LicenseID {
			continue
		}
		if filter.Fingerprint != "" && record.DeviceFingerprint != filter.Fingerprint {
			continue
		}
		if filter.PendingOnly && !record.PendingRevocation {
			continue
		}
		list = append(list, cloneDeviceLedger(record))
	}
	sort.Slice(list, func(i, j int) bool { return list[i].UpdatedAt.After(list[j].UpdatedAt) })
	return list, nil
}

// Service accounts

func (r *MemoryRepository) CreateServiceAccount(_ context.Context, sa *ServiceAccount) error {
	if sa == nil {
		return fmt.Errorf("service account is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, exists := r.serviceAccounts[sa.ID]; exists {
		return fmt.Errorf("service account exists")
	}
	r.serviceAccounts[sa.ID] = cloneServiceAccount(sa)
	return nil
}

func (r *MemoryRepository) UpdateServiceAccount(_ context.Context, sa *ServiceAccount) error {
	if sa == nil {
		return fmt.Errorf("service account is nil")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.serviceAccounts[sa.ID]; !ok {
		return ErrServiceAccountMissing
	}
	r.serviceAccounts[sa.ID] = cloneServiceAccount(sa)
	return nil
}

func (r *MemoryRepository) DeleteServiceAccount(_ context.Context, serviceAccountID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.serviceAccounts[serviceAccountID]; !ok {
		return ErrServiceAccountMissing
	}
	delete(r.serviceAccounts, serviceAccountID)
	return nil
}

func (r *MemoryRepository) GetServiceAccount(_ context.Context, serviceAccountID string) (*ServiceAccount, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sa, ok := r.serviceAccounts[serviceAccountID]
	if !ok {
		return nil, ErrServiceAccountMissing
	}
	return cloneServiceAccount(sa), nil
}

func (r *MemoryRepository) ListServiceAccounts(_ context.Context, tenantID string) ([]*ServiceAccount, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var list []*ServiceAccount
	for _, sa := range r.serviceAccounts {
		if tenantID != "" && sa.TenantID != tenantID {
			continue
		}
		list = append(list, cloneServiceAccount(sa))
	}
	sort.Slice(list, func(i, j int) bool { return strings.Compare(list[i].Name, list[j].Name) < 0 })
	return list, nil
}

// --- helpers ---

func (r *MemoryRepository) userExists(tenantID string, match func(*CRMUser) bool) bool {
	for _, user := range r.users {
		if user.TenantID != tenantID {
			continue
		}
		if match(user) {
			return true
		}
	}
	return false
}

func (r *MemoryRepository) contactExists(tenantID, selfID, email string) bool {
	for _, contact := range r.contacts {
		if contact.TenantID != tenantID {
			continue
		}
		if contact.ID == selfID {
			continue
		}
		if normalizeKey(contact.Email) == email {
			return true
		}
	}
	return false
}

func clampWindow(length, offset, limit int) (int, int) {
	if offset < 0 {
		offset = 0
	}
	if offset > length {
		offset = length
	}
	end := length
	if limit > 0 && offset+limit < end {
		end = offset + limit
	}
	return offset, end
}

func normalizeKey(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func deviceKey(tenantID, fingerprint string) string {
	return tenantID + "::" + fingerprint
}

func contactHasTags(contact *Contact, desired map[string]struct{}) bool {
	if len(desired) == 0 {
		return true
	}
	for _, tag := range contact.Tags {
		if _, ok := desired[strings.ToLower(tag)]; ok {
			return true
		}
	}
	return false
}

// Clone helpers

func cloneTenant(t *Tenant) *Tenant {
	if t == nil {
		return nil
	}
	copy := *t
	copy.Metadata = cloneStringMap(t.Metadata)
	return &copy
}

func cloneTenantSettings(ts *TenantSettings) *TenantSettings {
	if ts == nil {
		return nil
	}
	copy := *ts
	copy.LoginModes = cloneStringSlice(ts.LoginModes)
	copy.AllowedOrigins = cloneStringSlice(ts.AllowedOrigins)
	copy.Metadata = cloneStringMap(ts.Metadata)
	return &copy
}

func cloneCRMUser(u *CRMUser) *CRMUser {
	if u == nil {
		return nil
	}
	copy := *u
	copy.PasswordHash = append([]byte(nil), u.PasswordHash...)
	copy.MFAMethods = cloneStringSlice(u.MFAMethods)
	copy.Attributes = cloneStringMap(u.Attributes)
	return &copy
}

func cloneContact(c *Contact) *Contact {
	if c == nil {
		return nil
	}
	copy := *c
	copy.Tags = cloneStringSlice(c.Tags)
	copy.Attributes = cloneStringMap(c.Attributes)
	return &copy
}

func cloneCredentialSecret(cs *CredentialSecret) *CredentialSecret {
	if cs == nil {
		return nil
	}
	copy := *cs
	copy.Hash = append([]byte(nil), cs.Hash...)
	copy.EncryptedValue = append([]byte(nil), cs.EncryptedValue...)
	copy.Metadata = cloneStringMap(cs.Metadata)
	return &copy
}

func cloneSessionToken(st *SessionToken) *SessionToken {
	if st == nil {
		return nil
	}
	copy := *st
	copy.Audience = cloneStringSlice(st.Audience)
	copy.Scopes = cloneStringSlice(st.Scopes)
	copy.Metadata = cloneStringMap(st.Metadata)
	return &copy
}

func cloneEntitlement(e *EntitlementBinding) *EntitlementBinding {
	if e == nil {
		return nil
	}
	copy := *e
	if e.FeatureOverrides != nil {
		copy.FeatureOverrides = make(map[string]FeatureOverride, len(e.FeatureOverrides))
		for k, v := range e.FeatureOverrides {
			fo := v
			fo.Metadata = cloneStringMap(v.Metadata)
			if v.Scopes != nil {
				fo.Scopes = make(map[string]ScopeOverride, len(v.Scopes))
				for sk, sv := range v.Scopes {
					so := sv
					so.Metadata = cloneStringMap(sv.Metadata)
					fo.Scopes[sk] = so
				}
			}
			copy.FeatureOverrides[k] = fo
		}
	}
	return &copy
}

func cloneRelease(pr *ProductRelease) *ProductRelease {
	if pr == nil {
		return nil
	}
	copy := *pr
	copy.Metadata = cloneStringMap(pr.Metadata)
	return &copy
}

func cloneDeviceLedger(dl *DeviceLedger) *DeviceLedger {
	if dl == nil {
		return nil
	}
	copy := *dl
	copy.Metadata = cloneStringMap(dl.Metadata)
	return &copy
}

func cloneServiceAccount(sa *ServiceAccount) *ServiceAccount {
	if sa == nil {
		return nil
	}
	copy := *sa
	copy.Scopes = cloneStringSlice(sa.Scopes)
	return &copy
}

func cloneStringSlice(src []string) []string {
	if len(src) == 0 {
		return nil
	}
	out := make([]string, len(src))
	copy(out, src)
	return out
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}
