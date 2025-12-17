package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

func mai1n() {
	fixturesDir := filepath.Join("docs", "fixtures", "v1")
	respData, err := os.ReadFile(filepath.Join(fixturesDir, "activation_response.json"))
	if err != nil {
		fmt.Printf("read activation_response: %v\n", err)
		os.Exit(1)
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(respData, &resp); err != nil {
		fmt.Printf("unmarshal resp: %v\n", err)
		os.Exit(1)
	}
	encHex := resp["encrypted_license"].(string)
	nonceHex := resp["nonce"].(string)

	enc, _ := hex.DecodeString(encHex)
	nonce, _ := hex.DecodeString(nonceHex)

	storedData, _ := os.ReadFile(filepath.Join(fixturesDir, "stored_license.json"))
	var stored map[string]interface{}
	_ = json.Unmarshal(storedData, &stored)
	fingerprint := stored["device_fingerprint"].(string)

	material := fingerprint + hex.EncodeToString(nonce)
	key := sha256.Sum256([]byte(material))

	block, _ := aes.NewCipher(key[:])
	gcm, _ := cipher.NewGCM(block)
	decrypted, err := gcm.Open(nil, nonce, enc, nil)
	if err != nil {
		fmt.Printf("decrypt failed: %v\n", err)
		os.Exit(1)
	}
	if len(decrypted) < 32 {
		fmt.Printf("decrypted too small\n")
		os.Exit(1)
	}
	licenseJSON := decrypted[32:]
	fmt.Printf("RAW JSON:\n%s\n", string(licenseJSON))
}
