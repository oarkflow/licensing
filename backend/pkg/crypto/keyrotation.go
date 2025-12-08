package crypto

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"
)

// KeyRotationConfig configures key rotation behavior
type KeyRotationConfig struct {
	RotationInterval time.Duration // How often to rotate keys
	MaxKeyAge        time.Duration // Maximum age before forced rotation
	MinKeyAge        time.Duration // Minimum age before allowing rotation
	RetentionPeriod  time.Duration // How long to keep old keys for verification
}

// DefaultKeyRotationConfig returns recommended settings
func DefaultKeyRotationConfig() *KeyRotationConfig {
	return &KeyRotationConfig{
		RotationInterval: 90 * 24 * time.Hour,  // 90 days
		MaxKeyAge:        180 * 24 * time.Hour, // 180 days
		MinKeyAge:        7 * 24 * time.Hour,   // 7 days
		RetentionPeriod:  365 * 24 * time.Hour, // 1 year
	}
}

// KeyVersion represents a versioned key
type KeyVersion struct {
	ID        string
	Signer    Signer
	CreatedAt time.Time
	ExpiresAt time.Time
	Status    KeyStatus
}

// KeyStatus represents the status of a key
type KeyStatus string

const (
	KeyStatusActive  KeyStatus = "active"  // Currently used for signing
	KeyStatusRetired KeyStatus = "retired" // No longer used for signing, kept for verification
	KeyStatusExpired KeyStatus = "expired" // Past retention period
	KeyStatusRevoked KeyStatus = "revoked" // Compromised, should not be used
)

// KeyManager manages multiple key versions with automatic rotation
type KeyManager struct {
	config       *KeyRotationConfig
	keys         map[string]*KeyVersion
	currentKeyID string
	algorithm    SigningAlgorithm
	mu           sync.RWMutex
	rotationChan chan struct{}
	stopChan     chan struct{}
}

// NewKeyManager creates a new key manager
func NewKeyManager(algorithm SigningAlgorithm, config *KeyRotationConfig) (*KeyManager, error) {
	if config == nil {
		config = DefaultKeyRotationConfig()
	}

	km := &KeyManager{
		config:       config,
		keys:         make(map[string]*KeyVersion),
		algorithm:    algorithm,
		rotationChan: make(chan struct{}, 1),
		stopChan:     make(chan struct{}),
	}

	// Generate initial key
	if err := km.generateNewKey(); err != nil {
		return nil, fmt.Errorf("failed to generate initial key: %w", err)
	}

	return km, nil
}

// generateNewKey generates a new key and sets it as current
func (km *KeyManager) generateNewKey() error {
	km.mu.Lock()
	defer km.mu.Unlock()

	keyID := generateKeyID()
	var signer Signer
	var err error

	switch km.algorithm {
	case AlgorithmEd25519:
		signer, err = NewEd25519Signer(keyID)
	case AlgorithmRSAPSS:
		signer, err = NewRSAPSSSigner(keyID)
	default:
		return fmt.Errorf("unsupported algorithm: %s", km.algorithm)
	}

	if err != nil {
		return fmt.Errorf("failed to create signer: %w", err)
	}

	now := time.Now()
	keyVersion := &KeyVersion{
		ID:        keyID,
		Signer:    signer,
		CreatedAt: now,
		ExpiresAt: now.Add(km.config.MaxKeyAge),
		Status:    KeyStatusActive,
	}

	// Retire current key if exists
	if km.currentKeyID != "" {
		if oldKey, exists := km.keys[km.currentKeyID]; exists {
			oldKey.Status = KeyStatusRetired
		}
	}

	km.keys[keyID] = keyVersion
	km.currentKeyID = keyID

	return nil
}

// GetCurrentSigner returns the current active signer
func (km *KeyManager) GetCurrentSigner() (Signer, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	if km.currentKeyID == "" {
		return nil, fmt.Errorf("no active key")
	}

	keyVersion, exists := km.keys[km.currentKeyID]
	if !exists {
		return nil, fmt.Errorf("current key not found")
	}

	if keyVersion.Status != KeyStatusActive {
		return nil, fmt.Errorf("current key is not active")
	}

	return keyVersion.Signer, nil
}

// GetSigner returns a specific signer by key ID (for verification)
func (km *KeyManager) GetSigner(keyID string) (Signer, error) {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keyVersion, exists := km.keys[keyID]
	if !exists {
		return nil, fmt.Errorf("key not found: %s", keyID)
	}

	if keyVersion.Status == KeyStatusRevoked {
		return nil, fmt.Errorf("key is revoked: %s", keyID)
	}

	return keyVersion.Signer, nil
}

// RotateKey manually triggers key rotation
func (km *KeyManager) RotateKey() error {
	km.mu.RLock()
	currentKey := km.keys[km.currentKeyID]
	km.mu.RUnlock()

	// Check minimum age
	if time.Since(currentKey.CreatedAt) < km.config.MinKeyAge {
		return fmt.Errorf("key is too young to rotate (min age: %s)", km.config.MinKeyAge)
	}

	return km.generateNewKey()
}

// StartAutoRotation starts automatic key rotation
func (km *KeyManager) StartAutoRotation() {
	go func() {
		ticker := time.NewTicker(24 * time.Hour) // Check daily
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				km.checkAndRotate()
			case <-km.rotationChan:
				km.checkAndRotate()
			case <-km.stopChan:
				return
			}
		}
	}()
}

// StopAutoRotation stops automatic key rotation
func (km *KeyManager) StopAutoRotation() {
	close(km.stopChan)
}

// checkAndRotate checks if rotation is needed and performs it
func (km *KeyManager) checkAndRotate() {
	km.mu.RLock()
	currentKey, exists := km.keys[km.currentKeyID]
	km.mu.RUnlock()

	if !exists {
		return
	}

	age := time.Since(currentKey.CreatedAt)

	// Rotate if key has reached rotation interval or max age
	if age >= km.config.RotationInterval || age >= km.config.MaxKeyAge {
		if err := km.generateNewKey(); err != nil {
			// Log error but don't panic - keep using current key
			fmt.Printf("Key rotation failed: %v\n", err)
		}
	}

	// Clean up expired keys
	km.cleanupExpiredKeys()
}

// cleanupExpiredKeys removes keys past retention period
func (km *KeyManager) cleanupExpiredKeys() {
	km.mu.Lock()
	defer km.mu.Unlock()

	now := time.Now()
	for keyID, keyVersion := range km.keys {
		if keyVersion.Status == KeyStatusRetired {
			age := now.Sub(keyVersion.CreatedAt)
			if age > km.config.RetentionPeriod {
				keyVersion.Status = KeyStatusExpired
				delete(km.keys, keyID)
			}
		}
	}
}

// RevokeKey marks a key as revoked (compromised)
func (km *KeyManager) RevokeKey(keyID string) error {
	km.mu.Lock()
	defer km.mu.Unlock()

	keyVersion, exists := km.keys[keyID]
	if !exists {
		return fmt.Errorf("key not found: %s", keyID)
	}

	keyVersion.Status = KeyStatusRevoked

	// If revoking current key, generate new one immediately
	if keyID == km.currentKeyID {
		km.mu.Unlock()
		err := km.generateNewKey()
		km.mu.Lock()
		return err
	}

	return nil
}

// ListKeys returns all keys with their status
func (km *KeyManager) ListKeys() map[string]*KeyVersion {
	km.mu.RLock()
	defer km.mu.RUnlock()

	keys := make(map[string]*KeyVersion, len(km.keys))
	for k, v := range km.keys {
		keys[k] = v
	}
	return keys
}

// GetCurrentKeyID returns the current active key ID
func (km *KeyManager) GetCurrentKeyID() string {
	km.mu.RLock()
	defer km.mu.RUnlock()
	return km.currentKeyID
}

// KeyRotationEvent represents a key rotation event
type KeyRotationEvent struct {
	OldKeyID  string
	NewKeyID  string
	Timestamp time.Time
	Reason    string
}

// generateKeyID generates a unique key identifier
func generateKeyID() string {
	b := make([]byte, 8)
	rand.Read(b)
	timestamp := time.Now().Unix()
	return fmt.Sprintf("key-%d-%x", timestamp, b)
}

// ExportKeyMetadata exports key metadata (not private keys)
func (km *KeyManager) ExportKeyMetadata() map[string]interface{} {
	km.mu.RLock()
	defer km.mu.RUnlock()

	metadata := make(map[string]interface{})
	metadata["current_key_id"] = km.currentKeyID
	metadata["algorithm"] = km.algorithm
	metadata["rotation_interval"] = km.config.RotationInterval.String()

	keys := make([]map[string]interface{}, 0, len(km.keys))
	for _, kv := range km.keys {
		keys = append(keys, map[string]interface{}{
			"id":         kv.ID,
			"created_at": kv.CreatedAt,
			"expires_at": kv.ExpiresAt,
			"status":     kv.Status,
			"age_days":   int(time.Since(kv.CreatedAt).Hours() / 24),
		})
	}
	metadata["keys"] = keys

	return metadata
}
