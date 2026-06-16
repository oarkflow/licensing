package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/oarkflow/licensing/pkg/device"
)

const (
	exitTamper     = 1
	exitError      = 2
	sigSize        = ed25519.SignatureSize
	pubKeySize     = ed25519.PublicKeySize
	signatureMagic = "LICFP-SIG-V2\x00\x00\x00\x00"
	footerSize     = sigSize + len(signatureMagic)
)

var (
	version           = "dev"
	embeddedPubKeyHex = ""
)

type output struct {
	Fingerprint string            `json:"fingerprint"`
	Platform    string            `json:"platform"`
	Hostname    string            `json:"hostname"`
	Label       string            `json:"label"`
	Identifiers map[string]string `json:"identifiers"`
	IsContainer bool              `json:"is_container"`
}

func main() {
	if err := selfVerify(); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY FAILURE: %v\n", err)
		os.Exit(exitTamper)
	}

	flagJSON := flag.Bool("json", false, "output device identity as JSON")
	flagVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *flagVersion {
		fmt.Println(version)
		return
	}

	info, err := device.GetInfo()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint error: %v\n", err)
		os.Exit(exitError)
	}

	out := output{
		Fingerprint: info.Fingerprint,
		Platform:    info.Platform,
		Hostname:    info.Name,
		Label:       info.Label,
		Identifiers: info.Identifiers,
		IsContainer: info.IsContainer,
	}

	if *flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(out); err != nil {
			fmt.Fprintf(os.Stderr, "json encode error: %v\n", err)
			os.Exit(exitError)
		}
		return
	}

	fmt.Println("Device Fingerprint")
	fmt.Println("==================")
	fmt.Printf("Fingerprint: %s\n", info.Fingerprint)
	fmt.Printf("Platform:     %s\n", info.Platform)
	fmt.Printf("Hostname:     %s\n", info.Name)
	fmt.Printf("Label:        %s\n", info.Label)
	fmt.Printf("Container:    %t\n", info.IsContainer)
	fmt.Println()
	fmt.Println("Identifiers:")
	for k, v := range info.Identifiers {
		fmt.Printf("  %s: %s\n", k, v)
	}
}

func selfVerify() error {
	pubHex := strings.TrimSpace(embeddedPubKeyHex)
	if pubHex == "" {
		return nil
	}
	pub, err := hex.DecodeString(pubHex)
	if err != nil {
		return fmt.Errorf("embedded public key is not valid hex: %w", err)
	}
	if len(pub) != pubKeySize {
		return fmt.Errorf("embedded public key length %d, want %d", len(pub), pubKeySize)
	}

	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("cannot resolve executable: %w", err)
	}
	clean := filepath.Clean(exe)

	f, err := os.Open(clean)
	if err != nil {
		return fmt.Errorf("cannot open executable: %w", err)
	}
	defer f.Close()

	st, err := f.Stat()
	if err != nil {
		return fmt.Errorf("cannot stat executable: %w", err)
	}
	bodyLen := st.Size() - int64(footerSize)
	if bodyLen <= 0 {
		return errors.New("binary is too small to contain an appended signature footer")
	}

	footer := make([]byte, footerSize)
	if _, err := f.ReadAt(footer, bodyLen); err != nil {
		return fmt.Errorf("cannot read appended signature footer: %w", err)
	}
	sig := footer[:sigSize]
	magic := string(footer[sigSize:])
	if magic != signatureMagic {
		return errors.New("binary signature footer is missing or invalid")
	}

	h := sha256.New()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek error: %w", err)
	}
	if _, err := io.CopyN(h, f, bodyLen); err != nil {
		return fmt.Errorf("hash error: %w", err)
	}
	digest := h.Sum(nil)

	if !ed25519.Verify(pub, digest, sig) {
		return errors.New("binary signature verification failed — the executable has been modified")
	}
	return nil
}
