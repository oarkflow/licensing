package licensing

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// tpmDeviceKeyProvider communicates with a hardware TPM 2.0 device through the
// go-tpm library. It lazily creates a primary RSA key for signing
// (TPM_ALG_RSASSA + SHA256) and keeps the handle until Close is invoked.
type tpmDeviceKeyProvider struct {
	path   string
	rwc    io.ReadWriteCloser
	handle tpmutil.Handle
	pub    *rsa.PublicKey
	mu     sync.Mutex
}

const defaultTPMDeviceLinux = "/dev/tpmrm0"
const fallbackTPMDeviceLinux = "/dev/tpm0"
const defaultTPMDeviceWindows = `\\.\TPM`
const defaultTPMDeviceDarwin = "/dev/tpm0"

// NewTPMDeviceKeyProvider initializes a TPM-backed signing provider. If device
// is empty it attempts to open the default path for the current OS.
func NewTPMDeviceKeyProvider(device string) (SigningProvider, error) {
	path := strings.TrimSpace(device)
	if path == "" {
		path = defaultTPMDevice()
	}
	rwc, err := tpm2.OpenTPM(path)
	if err != nil {
		return nil, fmt.Errorf("open tpm at %s: %w", path, err)
	}
	template := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign:        &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256},
			KeyBits:     2048,
			ExponentRaw: 0,
		},
	}
	handle, pub, err := tpm2.CreatePrimary(rwc, tpm2.HandleOwner, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		_ = rwc.Close()
		return nil, fmt.Errorf("create primary key: %w", err)
	}
	rsaKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		flushAndClose(rwc, handle)
		return nil, fmt.Errorf("tpm key is not RSA")
	}
	return &tpmDeviceKeyProvider{path: path, rwc: rwc, handle: handle, pub: rsaKey}, nil
}

func (p *tpmDeviceKeyProvider) ID() string {
	return fmt.Sprintf("tpm:%s", p.path)
}

func (p *tpmDeviceKeyProvider) PublicKey() *rsa.PublicKey {
	return p.pub
}

func (p *tpmDeviceKeyProvider) Sign(digest []byte) ([]byte, error) {
	if len(digest) == 0 {
		return nil, fmt.Errorf("digest required")
	}
	if len(digest) != crypto.SHA256.Size() {
		return nil, fmt.Errorf("tpm signer expects SHA-256 digest")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	sig, err := tpm2.Sign(p.rwc, p.handle, "", digest, nil, &tpm2.SigScheme{Alg: tpm2.AlgRSASSA, Hash: tpm2.AlgSHA256})
	if err != nil {
		return nil, fmt.Errorf("tpm sign failed: %w", err)
	}
	return sig.RSA.Signature, nil
}

func (p *tpmDeviceKeyProvider) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	return flushAndClose(p.rwc, p.handle)
}

func flushAndClose(rwc io.ReadWriteCloser, handle tpmutil.Handle) error {
	var closeErr error
	if rwc != nil {
		if handle != 0 {
			if err := tpm2.FlushContext(rwc, handle); err != nil {
				closeErr = err
			}
		}
		if err := rwc.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}

func defaultTPMDevice() string {
	switch runtime.GOOS {
	case "linux":
		if _, err := os.Stat(defaultTPMDeviceLinux); err == nil {
			return defaultTPMDeviceLinux
		}
		return fallbackTPMDeviceLinux
	case "windows":
		return defaultTPMDeviceWindows
	case "darwin":
		return defaultTPMDeviceDarwin
	default:
		return defaultTPMDeviceLinux
	}
}
