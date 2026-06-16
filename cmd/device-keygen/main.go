package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	flagKeyFile := flag.String("key-file", "device_ed25519.pem", "path to device key file (PEM)")
	flagGen := flag.Bool("gen", false, "generate key if missing")
	flag.Parse()

	path := *flagKeyFile
	clean := filepath.Clean(path)

	var keyFP string

	if data, err := os.ReadFile(clean); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			fmt.Fprintf(os.Stderr, "no PEM block in %s\n", clean)
			os.Exit(1)
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "parse error in %s: %v\n", clean, err)
			os.Exit(1)
		}
		priv, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			fmt.Fprintf(os.Stderr, "key in %s is not Ed25519\n", clean)
			os.Exit(1)
		}
		pub := priv.Public().(ed25519.PublicKey)
		fp := sha256.Sum256(pub)
		keyFP = "fp:v2:ed25519:" + hex.EncodeToString(fp[:])
		fmt.Printf("Fingerprint: %s\n", keyFP)
		fmt.Printf("Key file:    %s\n", clean)
		return
	}

	if !*flagGen {
		fmt.Fprintf(os.Stderr, "key not found at %s; use -gen to create\n", clean)
		os.Exit(1)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation failed: %v\n", err)
		os.Exit(1)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key marshalling failed: %v\n", err)
		os.Exit(1)
	}
	var buf bytes.Buffer
	if err := pem.Encode(&buf, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		fmt.Fprintf(os.Stderr, "PEM encode failed: %v\n", err)
		os.Exit(1)
	}
	if err := os.MkdirAll(filepath.Dir(clean), 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir error: %v\n", err)
		os.Exit(1)
	}
	if err := os.WriteFile(clean, buf.Bytes(), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write error: %v\n", err)
		os.Exit(1)
	}

	fp := sha256.Sum256(pub)
	keyFP = "fp:v2:ed25519:" + hex.EncodeToString(fp[:])
	fmt.Printf("Fingerprint: %s\n", keyFP)
	fmt.Printf("Key file:    %s\n", clean)
}
