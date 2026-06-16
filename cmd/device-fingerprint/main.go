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

	licensingclient "github.com/oarkflow/licensing/pkg/client"
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

func main() {
	if err := selfVerify(); err != nil {
		fmt.Fprintf(os.Stderr, "SECURITY FAILURE: %v\n", err)
		os.Exit(exitTamper)
	}

	configDir := flag.String("config-dir", "", fmt.Sprintf("Directory for local licensing data (default $HOME/%s)", licensingclient.DefaultConfigDir))
	deviceKeyProvider := flag.String("device-key-provider", "software", "Device proof key provider: software, os, tpm, or auto")
	deviceKeyFile := flag.String("device-key-file", "", "Software device proof key file; use a persistent mounted path for containers")
	deviceKeyName := flag.String("device-key-name", "", "OS keyring account/key label")
	tpmDevice := flag.String("tpm-device", "", "TPM device path for device proof")
	flagJSON := flag.Bool("json", false, "output device identity as JSON")
	flagVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *flagVersion {
		fmt.Println(version)
		return
	}

	client, err := licensingclient.New(licensingclient.Config{
		ConfigDir:         strings.TrimSpace(*configDir),
		DeviceKeyProvider: strings.TrimSpace(*deviceKeyProvider),
		DeviceKeyFile:     strings.TrimSpace(*deviceKeyFile),
		DeviceKeyName:     strings.TrimSpace(*deviceKeyName),
		TPMDevice:         strings.TrimSpace(*tpmDevice),
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint error: %v\n", err)
		os.Exit(exitError)
	}
	identity, err := client.CurrentDeviceIdentity()
	if err != nil {
		fmt.Fprintf(os.Stderr, "fingerprint error: %v\n", err)
		os.Exit(exitError)
	}

	if *flagJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(identity); err != nil {
			fmt.Fprintf(os.Stderr, "json encode error: %v\n", err)
			os.Exit(exitError)
		}
		return
	}

	fmt.Println("Device Fingerprint Info")
	fmt.Println("-----------------------")
	fmt.Printf("Fingerprint:          %s\n", identity.Fingerprint)
	fmt.Printf("Key ID:               %s\n", identity.KeyID)
	fmt.Printf("Key provider:         %s\n", identity.KeyProvider)
	fmt.Printf("Proof algorithm:      %s\n", identity.PublicKeyAlgorithm)
	if strings.TrimSpace(identity.HardwareFingerprint) != "" {
		fmt.Printf("Hardware fingerprint: %s\n", identity.HardwareFingerprint)
	}
	if strings.TrimSpace(identity.HardwareConfidence) != "" {
		fmt.Printf("Hardware confidence:  %s\n", identity.HardwareConfidence)
	}
	if strings.TrimSpace(identity.Platform) != "" {
		fmt.Printf("Platform:             %s\n", identity.Platform)
	}
	if strings.TrimSpace(identity.Label) != "" {
		fmt.Printf("Label:                %s\n", identity.Label)
	}
	fmt.Printf("Container:            %t\n", identity.IsContainer)
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
