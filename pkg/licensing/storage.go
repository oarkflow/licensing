package licensing

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Storage interface {
	SaveClient(ctx context.Context, client *Client) error
	UpdateClient(ctx context.Context, client *Client) error
	GetClient(ctx context.Context, clientID string) (*Client, error)
	GetClientByEmail(ctx context.Context, email string) (*Client, error)
	ListClients(ctx context.Context) ([]*Client, error)
	SaveLicense(ctx context.Context, license *License) error
	UpdateLicense(ctx context.Context, license *License) error
	GetLicense(ctx context.Context, licenseID string) (*License, error)
	GetLicenseByKey(ctx context.Context, licenseKey string) (*License, error)
	ListLicenses(ctx context.Context) ([]*License, error)
	RecordActivation(ctx context.Context, record *ActivationRecord) error
	ListActivations(ctx context.Context, licenseID string) ([]*ActivationRecord, error)
	CreateAdminUser(ctx context.Context, user *AdminUser) error
	GetAdminUser(ctx context.Context, userID string) (*AdminUser, error)
	GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error)
	ListAdminUsers(ctx context.Context) ([]*AdminUser, error)
	SaveAPIKey(ctx context.Context, key *APIKeyRecord) error
	UpdateAPIKey(ctx context.Context, key *APIKeyRecord) error
	GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error)
	ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKeyRecord, error)

	// Product management
	SaveProduct(ctx context.Context, product *Product) error
	UpdateProduct(ctx context.Context, product *Product) error
	GetProduct(ctx context.Context, productID string) (*Product, error)
	GetProductBySlug(ctx context.Context, slug string) (*Product, error)
	ListProducts(ctx context.Context) ([]*Product, error)
	DeleteProduct(ctx context.Context, productID string) error

	// Plan management
	SavePlan(ctx context.Context, plan *Plan) error
	UpdatePlan(ctx context.Context, plan *Plan) error
	GetPlan(ctx context.Context, planID string) (*Plan, error)
	GetPlanBySlug(ctx context.Context, productID, slug string) (*Plan, error)
	ListPlansByProduct(ctx context.Context, productID string) ([]*Plan, error)
	DeletePlan(ctx context.Context, planID string) error

	// Feature management
	SaveFeature(ctx context.Context, feature *Feature) error
	UpdateFeature(ctx context.Context, feature *Feature) error
	GetFeature(ctx context.Context, featureID string) (*Feature, error)
	GetFeatureBySlug(ctx context.Context, productID, slug string) (*Feature, error)
	ListFeaturesByProduct(ctx context.Context, productID string) ([]*Feature, error)
	DeleteFeature(ctx context.Context, featureID string) error

	// Feature scope management
	SaveFeatureScope(ctx context.Context, scope *FeatureScope) error
	UpdateFeatureScope(ctx context.Context, scope *FeatureScope) error
	GetFeatureScope(ctx context.Context, scopeID string) (*FeatureScope, error)
	ListFeatureScopes(ctx context.Context, featureID string) ([]*FeatureScope, error)
	DeleteFeatureScope(ctx context.Context, scopeID string) error

	// Plan-Feature relationship management
	SavePlanFeature(ctx context.Context, pf *PlanFeature) error
	UpdatePlanFeature(ctx context.Context, pf *PlanFeature) error
	GetPlanFeature(ctx context.Context, planID, featureID string) (*PlanFeature, error)
	ListPlanFeatures(ctx context.Context, planID string) ([]*PlanFeature, error)
	DeletePlanFeature(ctx context.Context, planID, featureID string) error

	// Entitlement computation
	ComputeLicenseEntitlements(ctx context.Context, productID, planID string) (*LicenseEntitlements, error)
}

var (
	errClientExists        = errors.New("client already exists")
	errClientMissing       = errors.New("client not found")
	errLicenseExists       = errors.New("license already exists")
	errLicenseMissing      = errors.New("license not found")
	errUserExists          = errors.New("user already exists")
	errUserMissing         = errors.New("user not found")
	errAPIKeyExists        = errors.New("api key already exists")
	errAPIKeyMissing       = errors.New("api key not found")
	errProductExists       = errors.New("product already exists")
	errProductMissing      = errors.New("product not found")
	errPlanExists          = errors.New("plan already exists")
	errPlanMissing         = errors.New("plan not found")
	errFeatureExists       = errors.New("feature already exists")
	errFeatureMissing      = errors.New("feature not found")
	errFeatureScopeExists  = errors.New("feature scope already exists")
	errFeatureScopeMissing = errors.New("feature scope not found")
	errPlanFeatureExists   = errors.New("plan feature already exists")
	errPlanFeatureMissing  = errors.New("plan feature not found")
)

type AdminUser struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash []byte    `json:"password_hash"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type APIKeyRecord struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Hash      string    `json:"hash"`
	Prefix    string    `json:"prefix"`
	CreatedAt time.Time `json:"created_at"`
	LastUsed  time.Time `json:"last_used_at,omitempty"`
}

func cloneAdminUser(user *AdminUser) *AdminUser {
	if user == nil {
		return nil
	}
	clone := *user
	if len(user.PasswordHash) > 0 {
		clone.PasswordHash = append([]byte(nil), user.PasswordHash...)
	}
	return &clone
}

func cloneAPIKeyRecord(key *APIKeyRecord) *APIKeyRecord {
	if key == nil {
		return nil
	}
	clone := *key
	return &clone
}

type InMemoryStorage struct {
	mu             sync.RWMutex
	clients        map[string]*Client
	clientsByEmail map[string]string
	licenses       map[string]*License
	licensesByKey  map[string]string
	activations    map[string][]*ActivationRecord
	adminUsers     map[string]*AdminUser
	adminByName    map[string]string
	apiKeys        map[string]*APIKeyRecord
	apiKeysByHash  map[string]string
	apiKeysByUser  map[string]map[string]struct{}
	// Product management
	products       map[string]*Product
	productsBySlug map[string]string
	plans          map[string]*Plan
	plansBySlug    map[string]string // key: "productID:slug"
	features       map[string]*Feature
	featuresBySlug map[string]string // key: "productID:slug"
	featureScopes  map[string]*FeatureScope
	planFeatures   map[string]*PlanFeature // key: "planID:featureID"
}

func NewInMemoryStorage() *InMemoryStorage {
	return &InMemoryStorage{
		clients:        make(map[string]*Client),
		clientsByEmail: make(map[string]string),
		licenses:       make(map[string]*License),
		licensesByKey:  make(map[string]string),
		activations:    make(map[string][]*ActivationRecord),
		adminUsers:     make(map[string]*AdminUser),
		adminByName:    make(map[string]string),
		apiKeys:        make(map[string]*APIKeyRecord),
		apiKeysByHash:  make(map[string]string),
		apiKeysByUser:  make(map[string]map[string]struct{}),
		products:       make(map[string]*Product),
		productsBySlug: make(map[string]string),
		plans:          make(map[string]*Plan),
		plansBySlug:    make(map[string]string),
		features:       make(map[string]*Feature),
		featuresBySlug: make(map[string]string),
		featureScopes:  make(map[string]*FeatureScope),
		planFeatures:   make(map[string]*PlanFeature),
	}
}

type storageSnapshot struct {
	Clients     map[string]*Client             `json:"clients"`
	Licenses    map[string]*License            `json:"licenses"`
	Activations map[string][]*ActivationRecord `json:"activations"`
	AdminUsers  map[string]*AdminUser          `json:"admin_users"`
	APIKeys     map[string]*APIKeyRecord       `json:"api_keys"`
}

func (s *InMemoryStorage) SaveClient(_ context.Context, client *Client) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[client.ID]; exists {
		return errClientExists
	}
	emailKey := normalizeEmail(client.Email)
	if emailKey != "" {
		if _, exists := s.clientsByEmail[emailKey]; exists {
			return errClientExists
		}
		s.clientsByEmail[emailKey] = client.ID
	}
	s.clients[client.ID] = cloneClient(client)
	return nil
}

func (s *InMemoryStorage) UpdateClient(_ context.Context, client *Client) error {
	if client == nil {
		return fmt.Errorf("client is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.clients[client.ID]
	if !exists {
		return errClientMissing
	}
	oldEmail := normalizeEmail(current.Email)
	newEmail := normalizeEmail(client.Email)
	if oldEmail != newEmail {
		if mappedID, taken := s.clientsByEmail[newEmail]; taken && mappedID != client.ID {
			return errClientExists
		}
		delete(s.clientsByEmail, oldEmail)
	}
	s.clients[client.ID] = cloneClient(client)
	s.clientsByEmail[newEmail] = client.ID
	return nil
}

func (s *InMemoryStorage) GetClient(_ context.Context, clientID string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	client, ok := s.clients[clientID]
	if !ok {
		return nil, errClientMissing
	}
	return cloneClient(client), nil
}

func (s *InMemoryStorage) GetClientByEmail(_ context.Context, email string) (*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clientID, ok := s.clientsByEmail[normalizeEmail(email)]
	if !ok {
		return nil, errClientMissing
	}
	return cloneClient(s.clients[clientID]), nil
}

func (s *InMemoryStorage) ListClients(_ context.Context) ([]*Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	clients := make([]*Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, cloneClient(client))
	}
	return clients, nil
}

func (s *InMemoryStorage) SaveLicense(_ context.Context, license *License) error {
	if license == nil {
		return fmt.Errorf("license is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.licenses[license.ID]; exists {
		return errLicenseExists
	}
	key := normalizeLicenseKey(license.LicenseKey)
	if key != "" {
		if _, exists := s.licensesByKey[key]; exists {
			return errLicenseExists
		}
		s.licensesByKey[key] = license.ID
	}
	s.licenses[license.ID] = cloneLicense(license)
	return nil
}

func (s *InMemoryStorage) UpdateLicense(_ context.Context, license *License) error {
	if license == nil {
		return fmt.Errorf("license is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	current, exists := s.licenses[license.ID]
	if !exists {
		return errLicenseMissing
	}
	oldKey := normalizeLicenseKey(current.LicenseKey)
	newKey := normalizeLicenseKey(license.LicenseKey)
	if oldKey != newKey {
		if mappedID, taken := s.licensesByKey[newKey]; taken && mappedID != license.ID {
			return errLicenseExists
		}
		delete(s.licensesByKey, oldKey)
	}
	s.licenses[license.ID] = cloneLicense(license)
	s.licensesByKey[newKey] = license.ID
	return nil
}

func (s *InMemoryStorage) GetLicense(_ context.Context, licenseID string) (*License, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	license, exists := s.licenses[licenseID]
	if !exists {
		return nil, errLicenseMissing
	}
	return cloneLicense(license), nil
}

func (s *InMemoryStorage) GetLicenseByKey(_ context.Context, licenseKey string) (*License, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	licenseID, ok := s.licensesByKey[normalizeLicenseKey(licenseKey)]
	if !ok {
		return nil, errLicenseMissing
	}
	return cloneLicense(s.licenses[licenseID]), nil
}

func (s *InMemoryStorage) ListLicenses(_ context.Context) ([]*License, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	licenses := make([]*License, 0, len(s.licenses))
	for _, license := range s.licenses {
		licenses = append(licenses, cloneLicense(license))
	}
	return licenses, nil
}

func (s *InMemoryStorage) RecordActivation(_ context.Context, record *ActivationRecord) error {
	if record == nil {
		return fmt.Errorf("record is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := *record
	s.activations[record.LicenseID] = append(s.activations[record.LicenseID], &cloned)
	return nil
}

func (s *InMemoryStorage) ListActivations(_ context.Context, licenseID string) ([]*ActivationRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	records := s.activations[licenseID]
	result := make([]*ActivationRecord, 0, len(records))
	for _, record := range records {
		result = append(result, cloneActivationRecord(record))
	}
	return result, nil
}

func (s *InMemoryStorage) CreateAdminUser(_ context.Context, user *AdminUser) error {
	if user == nil {
		return fmt.Errorf("user is nil")
	}
	username := strings.ToLower(strings.TrimSpace(user.Username))
	if username == "" {
		return fmt.Errorf("username is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.adminUsers[user.ID]; exists {
		return errUserExists
	}
	if _, exists := s.adminByName[username]; exists {
		return errUserExists
	}
	clone := cloneAdminUser(user)
	s.adminUsers[user.ID] = clone
	s.adminByName[username] = user.ID
	return nil
}

func (s *InMemoryStorage) GetAdminUser(_ context.Context, userID string) (*AdminUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	user, ok := s.adminUsers[userID]
	if !ok {
		return nil, errUserMissing
	}
	return cloneAdminUser(user), nil
}

func (s *InMemoryStorage) GetAdminUserByUsername(_ context.Context, username string) (*AdminUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.adminByName[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return nil, errUserMissing
	}
	return cloneAdminUser(s.adminUsers[id]), nil
}

func (s *InMemoryStorage) ListAdminUsers(_ context.Context) ([]*AdminUser, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	users := make([]*AdminUser, 0, len(s.adminUsers))
	for _, user := range s.adminUsers {
		users = append(users, cloneAdminUser(user))
	}
	return users, nil
}

func (s *InMemoryStorage) SaveAPIKey(_ context.Context, key *APIKeyRecord) error {
	if key == nil {
		return fmt.Errorf("api key is nil")
	}
	if key.Hash == "" {
		return fmt.Errorf("api key hash required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.apiKeys[key.ID]; exists {
		return errAPIKeyExists
	}
	if _, exists := s.apiKeysByHash[key.Hash]; exists {
		return errAPIKeyExists
	}
	clone := cloneAPIKeyRecord(key)
	s.apiKeys[key.ID] = clone
	s.apiKeysByHash[key.Hash] = key.ID
	if _, ok := s.apiKeysByUser[key.UserID]; !ok {
		s.apiKeysByUser[key.UserID] = make(map[string]struct{})
	}
	s.apiKeysByUser[key.UserID][key.ID] = struct{}{}
	return nil
}

func (s *InMemoryStorage) UpdateAPIKey(_ context.Context, key *APIKeyRecord) error {
	if key == nil {
		return fmt.Errorf("api key is nil")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, exists := s.apiKeys[key.ID]
	if !exists {
		return errAPIKeyMissing
	}
	if stored.Hash != key.Hash {
		return fmt.Errorf("api key hash mismatch")
	}
	s.apiKeys[key.ID] = cloneAPIKeyRecord(key)
	return nil
}

func (s *InMemoryStorage) GetAPIKeyByHash(_ context.Context, hash string) (*APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.apiKeysByHash[hash]
	if !ok {
		return nil, errAPIKeyMissing
	}
	return cloneAPIKeyRecord(s.apiKeys[id]), nil
}

func (s *InMemoryStorage) ListAPIKeysByUser(_ context.Context, userID string) ([]*APIKeyRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	keyIDs := s.apiKeysByUser[userID]
	if len(keyIDs) == 0 {
		return []*APIKeyRecord{}, nil
	}
	keys := make([]*APIKeyRecord, 0, len(keyIDs))
	for keyID := range keyIDs {
		if record, ok := s.apiKeys[keyID]; ok {
			keys = append(keys, cloneAPIKeyRecord(record))
		}
	}
	return keys, nil
}

func (s *InMemoryStorage) snapshot() *storageSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	snapshot := &storageSnapshot{
		Clients:     make(map[string]*Client, len(s.clients)),
		Licenses:    make(map[string]*License, len(s.licenses)),
		Activations: make(map[string][]*ActivationRecord, len(s.activations)),
		AdminUsers:  make(map[string]*AdminUser, len(s.adminUsers)),
		APIKeys:     make(map[string]*APIKeyRecord, len(s.apiKeys)),
	}
	for id, client := range s.clients {
		snapshot.Clients[id] = cloneClient(client)
	}
	for id, license := range s.licenses {
		snapshot.Licenses[id] = cloneLicense(license)
	}
	for id, records := range s.activations {
		clones := make([]*ActivationRecord, 0, len(records))
		for _, record := range records {
			clones = append(clones, cloneActivationRecord(record))
		}
		snapshot.Activations[id] = clones
	}
	for id, user := range s.adminUsers {
		snapshot.AdminUsers[id] = cloneAdminUser(user)
	}
	for id, key := range s.apiKeys {
		snapshot.APIKeys[id] = cloneAPIKeyRecord(key)
	}
	return snapshot
}

func (s *InMemoryStorage) loadSnapshot(snapshot *storageSnapshot) {
	if snapshot == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients = make(map[string]*Client, len(snapshot.Clients))
	s.clientsByEmail = make(map[string]string, len(snapshot.Clients))
	for id, client := range snapshot.Clients {
		cloned := cloneClient(client)
		s.clients[id] = cloned
		s.clientsByEmail[normalizeEmail(cloned.Email)] = id
	}
	s.licenses = make(map[string]*License, len(snapshot.Licenses))
	s.licensesByKey = make(map[string]string, len(snapshot.Licenses))
	for id, license := range snapshot.Licenses {
		cloned := cloneLicense(license)
		s.licenses[id] = cloned
		s.licensesByKey[normalizeLicenseKey(cloned.LicenseKey)] = id
	}
	s.activations = make(map[string][]*ActivationRecord, len(snapshot.Activations))
	for id, records := range snapshot.Activations {
		clones := make([]*ActivationRecord, 0, len(records))
		for _, record := range records {
			clones = append(clones, cloneActivationRecord(record))
		}
		s.activations[id] = clones
	}
	s.adminUsers = make(map[string]*AdminUser, len(snapshot.AdminUsers))
	s.adminByName = make(map[string]string, len(snapshot.AdminUsers))
	for id, user := range snapshot.AdminUsers {
		cloned := cloneAdminUser(user)
		s.adminUsers[id] = cloned
		s.adminByName[strings.ToLower(strings.TrimSpace(cloned.Username))] = id
	}
	s.apiKeys = make(map[string]*APIKeyRecord, len(snapshot.APIKeys))
	s.apiKeysByHash = make(map[string]string, len(snapshot.APIKeys))
	s.apiKeysByUser = make(map[string]map[string]struct{})
	for id, key := range snapshot.APIKeys {
		cloned := cloneAPIKeyRecord(key)
		s.apiKeys[id] = cloned
		s.apiKeysByHash[cloned.Hash] = id
		if _, ok := s.apiKeysByUser[cloned.UserID]; !ok {
			s.apiKeysByUser[cloned.UserID] = make(map[string]struct{})
		}
		s.apiKeysByUser[cloned.UserID][id] = struct{}{}
	}
}

type PersistentStorage struct {
	backend *InMemoryStorage
	path    string
}

func NewPersistentStorage(path string) (*PersistentStorage, error) {
	if strings.TrimSpace(path) == "" {
		return nil, fmt.Errorf("persistent storage path is required")
	}
	ps := &PersistentStorage{
		backend: NewInMemoryStorage(),
		path:    path,
	}
	if err := ps.loadFromDisk(); err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
	}
	return ps, nil
}

func (ps *PersistentStorage) SaveClient(ctx context.Context, client *Client) error {
	if err := ps.backend.SaveClient(ctx, client); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateClient(ctx context.Context, client *Client) error {
	if err := ps.backend.UpdateClient(ctx, client); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetClient(ctx context.Context, clientID string) (*Client, error) {
	return ps.backend.GetClient(ctx, clientID)
}

func (ps *PersistentStorage) GetClientByEmail(ctx context.Context, email string) (*Client, error) {
	return ps.backend.GetClientByEmail(ctx, email)
}

func (ps *PersistentStorage) ListClients(ctx context.Context) ([]*Client, error) {
	return ps.backend.ListClients(ctx)
}

func (ps *PersistentStorage) SaveLicense(ctx context.Context, license *License) error {
	if err := ps.backend.SaveLicense(ctx, license); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateLicense(ctx context.Context, license *License) error {
	if err := ps.backend.UpdateLicense(ctx, license); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetLicense(ctx context.Context, licenseID string) (*License, error) {
	return ps.backend.GetLicense(ctx, licenseID)
}

func (ps *PersistentStorage) GetLicenseByKey(ctx context.Context, licenseKey string) (*License, error) {
	return ps.backend.GetLicenseByKey(ctx, licenseKey)
}

func (ps *PersistentStorage) ListLicenses(ctx context.Context) ([]*License, error) {
	return ps.backend.ListLicenses(ctx)
}

func (ps *PersistentStorage) RecordActivation(ctx context.Context, record *ActivationRecord) error {
	if err := ps.backend.RecordActivation(ctx, record); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) ListActivations(ctx context.Context, licenseID string) ([]*ActivationRecord, error) {
	return ps.backend.ListActivations(ctx, licenseID)
}

func (ps *PersistentStorage) CreateAdminUser(ctx context.Context, user *AdminUser) error {
	if err := ps.backend.CreateAdminUser(ctx, user); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetAdminUser(ctx context.Context, userID string) (*AdminUser, error) {
	return ps.backend.GetAdminUser(ctx, userID)
}

func (ps *PersistentStorage) GetAdminUserByUsername(ctx context.Context, username string) (*AdminUser, error) {
	return ps.backend.GetAdminUserByUsername(ctx, username)
}

func (ps *PersistentStorage) ListAdminUsers(ctx context.Context) ([]*AdminUser, error) {
	return ps.backend.ListAdminUsers(ctx)
}

func (ps *PersistentStorage) SaveAPIKey(ctx context.Context, key *APIKeyRecord) error {
	if err := ps.backend.SaveAPIKey(ctx, key); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) UpdateAPIKey(ctx context.Context, key *APIKeyRecord) error {
	if err := ps.backend.UpdateAPIKey(ctx, key); err != nil {
		return err
	}
	return ps.persist()
}

func (ps *PersistentStorage) GetAPIKeyByHash(ctx context.Context, hash string) (*APIKeyRecord, error) {
	return ps.backend.GetAPIKeyByHash(ctx, hash)
}

func (ps *PersistentStorage) ListAPIKeysByUser(ctx context.Context, userID string) ([]*APIKeyRecord, error) {
	return ps.backend.ListAPIKeysByUser(ctx, userID)
}

func (ps *PersistentStorage) persist() error {
	snapshot := ps.backend.snapshot()
	data, err := json.MarshalIndent(snapshot, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(ps.path), 0o700); err != nil {
		return err
	}
	tmpPath := ps.path + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmpPath, ps.path)
}

func (ps *PersistentStorage) loadFromDisk() error {
	data, err := os.ReadFile(ps.path)
	if err != nil {
		return err
	}
	var snapshot storageSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return err
	}
	ps.backend.loadSnapshot(&snapshot)
	return nil
}

func BuildStorageFromEnv() (Storage, string, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE")))
	switch mode {
	case "", "sqlite", "sql", "sqlite3":
		path := strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_SQLITE_PATH"))
		if path == "" {
			path = filepath.Join("data", "licensing.db")
		} else {
			path = filepath.Clean(path)
		}
		storage, err := NewSQLiteStorage(path)
		if err != nil {
			return nil, "", err
		}
		return storage, fmt.Sprintf("sqlite:%s", path), nil
	case "memory":
		return NewInMemoryStorage(), "memory", nil
	case "file", "disk", "persistent":
		path := strings.TrimSpace(os.Getenv("LICENSE_SERVER_STORAGE_FILE"))
		if path == "" {
			path = filepath.Join("data", "licensing-state.json")
		} else {
			path = filepath.Clean(path)
		}
		storage, err := NewPersistentStorage(path)
		if err != nil {
			return nil, "", err
		}
		return storage, fmt.Sprintf("file:%s", path), nil
	default:
		return nil, "", fmt.Errorf("unsupported storage mode %q", mode)
	}
}
