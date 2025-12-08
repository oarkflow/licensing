package licensing

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SigningProvider abstracts the hardware/software component responsible for
// signing license payload digests.
type SigningProvider interface {
	ID() string
	PublicKey() *rsa.PublicKey
	Sign(digest []byte) ([]byte, error)
	Close() error
}

// BuildSigningProviderFromEnv configures a provider based on environment
// variables. Supported providers:
//   - software (default): in-memory RSA key generated on startup
//   - file: RSA private key loaded from disk (PKCS#1/PKCS#8 PEM, optional passphrase)
//   - tpm: hardware TPM 2.0 device accessed via go-tpm
func BuildSigningProviderFromEnv() (SigningProvider, error) {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("LICENSE_SERVER_KEY_PROVIDER")))
	switch mode {
	case "", "software", "memory", "soft", "dev":
		bits := 2048
		if raw := strings.TrimSpace(os.Getenv("LICENSE_SERVER_KEY_BITS")); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil && parsed >= 2048 {
				bits = parsed
			}
		}
		return NewSoftwareKeyProvider(bits)
	case "file", "pem":
		path := strings.TrimSpace(os.Getenv("LICENSE_SERVER_KEY_FILE"))
		if path == "" {
			return nil, fmt.Errorf("LICENSE_SERVER_KEY_FILE is required when using the file key provider")
		}
		pass := os.Getenv("LICENSE_SERVER_KEY_PASSPHRASE")
		return NewFileKeyProvider(path, pass)
	case "tpm", "hardware", "hw":
		device := strings.TrimSpace(os.Getenv("LICENSE_SERVER_TPM_DEVICE"))
		return NewTPMDeviceKeyProvider(device)
	default:
		return nil, fmt.Errorf("unsupported key provider %q", mode)
	}
}

type softwareKeyProvider struct {
	id   string
	priv *rsa.PrivateKey
	pub  *rsa.PublicKey
}

// NewSoftwareKeyProvider generates an in-memory RSA key for development/testing.
func NewSoftwareKeyProvider(bits int) (SigningProvider, error) {
	if bits < 2048 {
		bits = 2048
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate rsa key: %w", err)
	}
	return &softwareKeyProvider{
		id:   fmt.Sprintf("software-rsa-%d", bits),
		priv: priv,
		pub:  &priv.PublicKey,
	}, nil
}

func (p *softwareKeyProvider) ID() string                { return p.id }
func (p *softwareKeyProvider) PublicKey() *rsa.PublicKey { return p.pub }
func (p *softwareKeyProvider) Sign(digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest required")
	}
	return rsa.SignPSS(rand.Reader, p.priv, cryptoHashForDigest(len(digest)), digest, nil)
}
func (p *softwareKeyProvider) Close() error { return nil }

type fileKeyProvider struct {
	path       string
	passphrase string
	mu         sync.RWMutex
	priv       *rsa.PrivateKey
	pub        *rsa.PublicKey
	modTime    time.Time
}

// NewFileKeyProvider loads a PEM encoded RSA private key from disk and watches
// for rotation by checking the file's mtime prior to each signature.
func NewFileKeyProvider(path, passphrase string) (SigningProvider, error) {
	cleaned := filepath.Clean(path)
	provider := &fileKeyProvider{path: cleaned, passphrase: passphrase}
	if err := provider.reload(); err != nil {
		return nil, err
	}
	return provider, nil
}

func (p *fileKeyProvider) ID() string { return fmt.Sprintf("file:%s", p.path) }
func (p *fileKeyProvider) PublicKey() *rsa.PublicKey {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.pub
}

func (p *fileKeyProvider) Sign(digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest required")
	}
	if err := p.reloadIfRotated(); err != nil {
		return nil, err
	}
	p.mu.RLock()
	priv := p.priv
	p.mu.RUnlock()
	if priv == nil {
		return nil, fmt.Errorf("private key not loaded")
	}
	return rsa.SignPSS(rand.Reader, priv, cryptoHashForDigest(len(digest)), digest, nil)
}

func (p *fileKeyProvider) Close() error { return nil }

func (p *fileKeyProvider) reloadIfRotated() error {
	info, err := os.Stat(p.path)
	if err != nil {
		return err
	}
	p.mu.RLock()
	unchanged := p.modTime.Equal(info.ModTime())
	p.mu.RUnlock()
	if unchanged {
		return nil
	}
	return p.reload()
}

func (p *fileKeyProvider) reload() error {
	info, err := os.Stat(p.path)
	if err != nil {
		return fmt.Errorf("stat signing key: %w", err)
	}
	if err := enforceKeyPermissions(info); err != nil {
		return err
	}
	data, err := os.ReadFile(p.path)
	if err != nil {
		return fmt.Errorf("read signing key: %w", err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return fmt.Errorf("signing key file does not contain valid PEM data")
	}
	der := block.Bytes
	if x509.IsEncryptedPEMBlock(block) {
		if p.passphrase == "" {
			return fmt.Errorf("signing key is encrypted but LICENSE_SERVER_KEY_PASSPHRASE is empty")
		}
		decrypted, err := x509.DecryptPEMBlock(block, []byte(p.passphrase))
		if err != nil {
			return fmt.Errorf("failed to decrypt signing key: %w", err)
		}
		der = decrypted
	}
	priv, err := parseRSAPrivateKey(der)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.priv = priv
	p.pub = &priv.PublicKey
	p.modTime = info.ModTime()
	p.mu.Unlock()
	return nil
}

func parseRSAPrivateKey(der []byte) (*rsa.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}
	rsaKey, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("pkcs8 key is not RSA")
	}
	return rsaKey, nil
}

func enforceKeyPermissions(info fs.FileInfo) error {
	if info.Mode().IsDir() {
		return fmt.Errorf("signing key path points to directory")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("signing key file must not be accessible by group/others (run chmod 600)")
	}
	return nil
}

func cryptoHashForDigest(length int) crypto.Hash {
	switch length {
	case sha256.Size:
		return crypto.SHA256
	default:
		return crypto.SHA256
	}
}
