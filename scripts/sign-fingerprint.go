package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	genKey := flag.Bool("gen-key", false, "generate a new Ed25519 signing key pair")
	keyOut := flag.String("out", "signing-key.pem", "output path for the generated private key")
	signBin := flag.String("sign", "", "path to binary to sign (appends 64-byte Ed25519 signature)")
	keyPath := flag.String("key", "signing-key.pem", "path to the Ed25519 private key (PEM)")
	pubKey := flag.Bool("pubkey", false, "extract and print hex public key from private key")
	flag.Parse()

	switch {
	case *genKey:
		generateKey(*keyOut)
	case *pubKey:
		printPubKey(*keyPath)
	case *signBin != "":
		signBinary(*signBin, *keyPath)
	default:
		fmt.Println("Usage:")
		fmt.Println("  Generate key pair:")
		fmt.Println("    go run scripts/sign-fingerprint.go -gen-key -out signing-key.pem")
		fmt.Println()
		fmt.Println("  Extract public key hex:")
		fmt.Println("    go run scripts/sign-fingerprint.go -pubkey -key signing-key.pem")
		fmt.Println()
		fmt.Println("  Sign a binary:")
		fmt.Println("    go run scripts/sign-fingerprint.go -sign device-fingerprint -key signing-key.pem")
	}
}

func generateKey(path string) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key generation failed: %v\n", err)
		os.Exit(1)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal failed: %v\n", err)
		os.Exit(1)
	}

	f, err := os.Create(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create %s: %v\n", path, err)
		os.Exit(1)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{Type: "PRIVATE KEY", Bytes: der}); err != nil {
		fmt.Fprintf(os.Stderr, "PEM encode: %v\n", err)
		os.Exit(1)
	}

	pubHex := hex.EncodeToString(pub)
	fmt.Println("Key pair written to", path)
	fmt.Println("Public key hex (use with -ldflags):")
	fmt.Println(pubHex)
}

func printPubKey(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", path, err)
		os.Exit(1)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		fmt.Fprintf(os.Stderr, "no PEM block in %s\n", path)
		os.Exit(1)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse key: %v\n", err)
		os.Exit(1)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "key is not Ed25519\n")
		os.Exit(1)
	}
	pub := priv.Public().(ed25519.PublicKey)
	fmt.Print(hex.EncodeToString(pub))
}

func signBinary(binPath, keyPath string) {
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read key %s: %v\n", keyPath, err)
		os.Exit(1)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		fmt.Fprintf(os.Stderr, "no PEM block in %s\n", keyPath)
		os.Exit(1)
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "parse key: %v\n", err)
		os.Exit(1)
	}
	priv, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		fmt.Fprintf(os.Stderr, "key is not Ed25519\n")
		os.Exit(1)
	}

	bin, err := os.ReadFile(binPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read binary %s: %v\n", binPath, err)
		os.Exit(1)
	}

	digest := sha256.Sum256(bin)
	sig := ed25519.Sign(priv, digest[:])

	f, err := os.OpenFile(binPath, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "open binary for append: %v\n", err)
		os.Exit(1)
	}
	defer f.Close()

	if _, err := f.Write(sig); err != nil {
		fmt.Fprintf(os.Stderr, "append signature: %v\n", err)
		os.Exit(1)
	}

	_ = io.Discard
	fmt.Printf("Signed %s (%d-byte signature appended)\n", binPath, len(sig))
}
