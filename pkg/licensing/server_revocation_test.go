package licensing

import (
    "context"
    "crypto/ed25519"
    "encoding/base64"
    "encoding/json"
    "net/http/httptest"
    "testing"
    "time"
)

func TestRevocationManifestSigned(t *testing.T) {
    storage := NewInMemoryStorage()
    lm, err := NewLicenseManager(storage)
    if err != nil {
        t.Fatalf("NewLicenseManager failed: %v", err)
    }

    // Create server
    rl := NewRateLimiter(100, time.Minute)
    s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
    if err != nil {
        t.Fatalf("NewServer failed: %v", err)
    }

    // Create an ed25519 signing key and save in storage and activate
    pub, priv, err := ed25519.GenerateKey(nil)
    if err != nil {
        t.Fatalf("key generation failed: %v", err)
    }
    key := &SigningKey{ID: "rk1", Name: "revkey", PublicKey: pub, PrivateKey: priv, IsActive: true, CreatedAt: time.Now().UTC()}
    if err := storage.SaveSigningKey(context.Background(), key); err != nil {
        t.Fatalf("SaveSigningKey failed: %v", err)
    }
    if err := storage.SetActiveSigningKey(context.Background(), key.ID); err != nil {
        t.Fatalf("SetActiveSigningKey failed: %v", err)
    }

    ctx := context.Background()
    // create client and license
    client := &Client{ID: "c1", Email: "rev@example.com", Status: ClientStatusActive, CreatedAt: time.Now(), UpdatedAt: time.Now()}
    if err := storage.SaveClient(ctx, client); err != nil {
        t.Fatalf("SaveClient failed: %v", err)
    }
    lic := &License{ID: "lic-rev", ClientID: client.ID, LicenseKey: "LIC-REV-1", IssuedAt: time.Now().UTC(), ExpiresAt: time.Now().Add(24*time.Hour), Devices: map[string]*LicenseDevice{}, MaxDevices: 1}
    if err := storage.SaveLicense(ctx, lic); err != nil {
        t.Fatalf("SaveLicense failed: %v", err)
    }

    // Create offline token and revoke it
    token := &OfflineValidationToken{Token: "ot1", LicenseKey: lic.LicenseKey, ClientID: client.ID, DeviceFingerprint: "dev1", ValidUntil: time.Now().Add(7*24*time.Hour), MaxUses: 5, IsRevoked: true, RevokedAt: time.Now(), CreatedAt: time.Now()}
    if err := storage.SaveOfflineValidationToken(ctx, token); err != nil {
        t.Fatalf("SaveOfflineValidationToken failed: %v", err)
    }

    // Revoke license via manager
    if _, err := lm.RevokeLicense(ctx, lic.ID, "test revoke"); err != nil {
        t.Fatalf("RevokeLicense failed: %v", err)
    }

    // Call manifest endpoint
    req := httptest.NewRequest("GET", "/api/licenses/offline-revocations", nil)
    w := httptest.NewRecorder()
    s.handleGetRevocationManifest(w, req)
    if w.Code != 200 {
        t.Fatalf("expected 200 for manifest, got %d body=%s", w.Code, w.Body.String())
    }

    var resp map[string]interface{}
    if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
        t.Fatalf("failed to unmarshal manifest response: %v", err)
    }

    // Validate signature present
    sigVal, ok := resp["signature"].(string)
    if !ok || sigVal == "" {
        t.Fatalf("expected signature in manifest response")
    }
    keyID, ok := resp["signing_key_id"].(string)
    if !ok || keyID == "" {
        t.Fatalf("expected signing_key_id in manifest response")
    }
    manifestRaw, ok := resp["manifest"]
    if !ok {
        t.Fatalf("manifest missing")
    }
    // verify signature over manifest
    payloadBytes, _ := json.Marshal(manifestRaw)
    sig, err := base64.StdEncoding.DecodeString(sigVal)
    if err != nil {
        t.Fatalf("invalid signature encoding: %v", err)
    }
    // fetch public key from storage
    sk, err := storage.GetSigningKey(context.Background(), keyID)
    if err != nil {
        t.Fatalf("failed to fetch signing key: %v", err)
    }
    if len(sk.PublicKey) == 0 {
        t.Fatalf("public key missing")
    }
    if !ed25519.Verify(ed25519.PublicKey(sk.PublicKey), payloadBytes, sig) {
        t.Fatalf("signature verification failed")
    }
}
