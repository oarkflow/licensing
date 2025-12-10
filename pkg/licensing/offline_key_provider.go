package licensing

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// OfflineSigningProvider signs offline bundles and exposes public keys.
type OfflineSigningProvider interface {
	ActiveKeyID() (string, error)
	PublicKey(keyID string) ([]byte, error)
	Sign(keyID string, payload []byte) ([]byte, error)
	ListKeyIDs() ([]string, error)
	Close() error
}

// BuildOfflineSigningProviderFromEnv configures provider based on env vars.
// Supported modes: "storage" (use storage's private key), "env" (private keys in env).
func BuildOfflineSigningProviderFromEnv(storage Storage) (OfflineSigningProvider, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LICENSE_SERVER_OFFLINE_KEY_PROVIDER")))
	switch mode {
	case "", "storage":
		// Use storage private keys if present
		if storage == nil {
			return nil, fmt.Errorf("storage required for storage-based offline provider")
		}
		return &storageOfflineProvider{storage: storage}, nil
	case "env":
		// Build map from env vars: LICENSE_SERVER_OFFLINE_KEY_<KEYID>=BASE64_PRIVATE_KEY
		keys := map[string][]byte{}
		for _, kv := range os.Environ() {
			if !strings.HasPrefix(kv, "LICENSE_SERVER_OFFLINE_KEY_") {
				continue
			}
			parts := strings.SplitN(kv, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name := strings.TrimPrefix(parts[0], "LICENSE_SERVER_OFFLINE_KEY_")
			raw := strings.TrimSpace(parts[1])
			if raw == "" || name == "" {
				continue
			}
			decoded, err := base64.StdEncoding.DecodeString(raw)
			if err != nil {
				return nil, fmt.Errorf("failed to decode env private key for %s: %w", name, err)
			}
			keys[name] = decoded
		}
		active := strings.TrimSpace(os.Getenv("LICENSE_SERVER_OFFLINE_ACTIVE_KEY_ID"))
		if len(keys) == 0 {
			return nil, fmt.Errorf("no offline private keys found in environment")
		}
		return newEnvOfflineProvider(keys, active), nil
	default:
		return nil, fmt.Errorf("unsupported offline key provider %q", mode)
	}
}

// storageOfflineProvider reads private/public keys from Storage backend (if private stored)
type storageOfflineProvider struct {
	storage Storage
}

func (s *storageOfflineProvider) ActiveKeyID() (string, error) {
	key, err := s.storage.GetActiveSigningKey(context.Background())
	if err != nil {
		return "", err
	}
	return key.ID, nil
}

func (s *storageOfflineProvider) PublicKey(keyID string) ([]byte, error) {
	key, err := s.storage.GetSigningKey(context.Background(), keyID)
	if err != nil {
		return nil, err
	}
	return key.PublicKey, nil
}

func (s *storageOfflineProvider) Sign(keyID string, payload []byte) ([]byte, error) {
	key, err := s.storage.GetSigningKey(context.Background(), keyID)
	if err != nil {
		return nil, err
	}
	if len(key.PrivateKey) == 0 {
		return nil, fmt.Errorf("private key not present in storage for key %s", keyID)
	}
	return ed25519.Sign(ed25519.PrivateKey(key.PrivateKey), payload), nil
}

func (s *storageOfflineProvider) ListKeyIDs() ([]string, error) {
	keys, err := s.storage.ListSigningKeys(context.Background())
	if err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(keys))
	for _, k := range keys {
		ids = append(ids, k.ID)
	}
	return ids, nil
}

func (s *storageOfflineProvider) Close() error { return nil }

// envOfflineProvider stores key material in env variables (base64) — suitable for KMS simulation
type envOfflineProvider struct {
	mu      sync.RWMutex
	keys    map[string][]byte // id -> private key bytes (ed25519)
	publics map[string][]byte
	active  string
}

func newEnvOfflineProvider(keys map[string][]byte, active string) *envOfflineProvider {
	p := &envOfflineProvider{keys: make(map[string][]byte), publics: make(map[string][]byte), active: active}
	for id, priv := range keys {
		p.keys[id] = priv
		// derive public key
		if len(priv) >= ed25519.SeedSize {
			// priv could be seed or full private key
			if len(priv) == ed25519.PrivateKeySize {
				pub := priv[ed25519.SeedSize:]
				p.publics[id] = make([]byte, len(pub))
				copy(p.publics[id], pub)
			} else {
				// derive using seed
				k := ed25519.NewKeyFromSeed(priv[:ed25519.SeedSize])
				p.publics[id] = k[ed25519.SeedSize:]
			}
		}
	}
	// set active to first if empty
	if p.active == "" {
		for id := range p.keys {
			p.active = id
			break
		}
	}
	return p
}

func (p *envOfflineProvider) ActiveKeyID() (string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.active == "" {
		return "", errors.New("no active offline key")
	}
	return p.active, nil
}

func (p *envOfflineProvider) PublicKey(keyID string) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	pub, ok := p.publics[keyID]
	if !ok {
		return nil, fmt.Errorf("public key not found: %s", keyID)
	}
	return pub, nil
}

func (p *envOfflineProvider) Sign(keyID string, payload []byte) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	priv, ok := p.keys[keyID]
	if !ok {
		return nil, fmt.Errorf("private key not found: %s", keyID)
	}
	return ed25519.Sign(ed25519.PrivateKey(priv), payload), nil
}

func (p *envOfflineProvider) ListKeyIDs() ([]string, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	ids := make([]string, 0, len(p.keys))
	for id := range p.keys {
		ids = append(ids, id)
	}
	return ids, nil
}

func (p *envOfflineProvider) Close() error { return nil }
