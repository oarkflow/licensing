package licensing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func testDeviceProof(t *testing.T, purpose string, challenge *DeviceChallenge, req *ActivationRequest, priv ed25519.PrivateKey) *DeviceProof {
	t.Helper()
	pub := priv.Public().(ed25519.PublicKey)
	payload := DeviceProofPayload{
		Purpose:     purpose,
		ChallengeID: challenge.ID,
		Nonce:       challenge.Nonce,
		LicenseKey:  req.LicenseKey,
		ClientID:    req.ClientID,
		Email:       req.Email,
		ProductID:   req.ProductID,
		Fingerprint: req.DeviceFingerprint,
		PublicKey:   pub,
	}
	sig := ed25519.Sign(priv, CanonicalDeviceProofPayload(payload))
	return &DeviceProof{
		Version:            DeviceProofVersionV2,
		Purpose:            purpose,
		ChallengeID:        challenge.ID,
		Nonce:              challenge.Nonce,
		Fingerprint:        req.DeviceFingerprint,
		KeyID:              DeviceProofPublicKeyID(pub),
		KeyProvider:        "software-test",
		PublicKeyAlgorithm: DeviceProofAlgorithmEd25519,
		PublicKey:          EncodeDeviceProofBytes(pub),
		Signature:          EncodeDeviceProofBytes(sig),
		Attestation: map[string]string{
			"type":   "software",
			"status": "test",
		},
	}
}

func testEd25519Fingerprint(priv ed25519.PrivateKey) string {
	return DeviceProofFingerprint(DeviceProofAlgorithmEd25519, priv.Public().(ed25519.PublicKey))
}

func testRSAFingerprint(t *testing.T, priv *rsa.PrivateKey) string {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}
	return DeviceProofFingerprint(DeviceProofAlgorithmRSAPSSSHA256, pubDER)
}

func testRSADeviceProof(t *testing.T, purpose string, challenge *DeviceChallenge, req *ActivationRequest, priv *rsa.PrivateKey) *DeviceProof {
	t.Helper()
	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey failed: %v", err)
	}
	payload := DeviceProofPayload{
		Purpose:     purpose,
		ChallengeID: challenge.ID,
		Nonce:       challenge.Nonce,
		LicenseKey:  req.LicenseKey,
		ClientID:    req.ClientID,
		Email:       req.Email,
		ProductID:   req.ProductID,
		Fingerprint: req.DeviceFingerprint,
		PublicKey:   pubDER,
	}
	digest := sha256.Sum256(CanonicalDeviceProofPayload(payload))
	sig, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatalf("SignPSS failed: %v", err)
	}
	return &DeviceProof{
		Version:            DeviceProofVersionV2,
		Purpose:            purpose,
		ChallengeID:        challenge.ID,
		Nonce:              challenge.Nonce,
		Fingerprint:        req.DeviceFingerprint,
		KeyID:              DeviceProofPublicKeyID(pubDER),
		KeyProvider:        "hardware-tpm2-test",
		PublicKeyAlgorithm: DeviceProofAlgorithmRSAPSSSHA256,
		PublicKey:          EncodeDeviceProofBytes(pubDER),
		Signature:          EncodeDeviceProofBytes(sig),
		Attestation: map[string]string{
			"type":   "tpm2",
			"status": "unattested-test",
		},
	}
}

func TestDeviceProofFingerprintContract(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	keyID := DeviceProofPublicKeyID(pub)
	first := DeviceProofFingerprint(DeviceProofAlgorithmEd25519, pub)
	second := DeviceProofFingerprint(" ED25519 ", pub)
	want := "fp:v2:ed25519:" + keyID

	if first != want {
		t.Fatalf("unexpected versioned proof fingerprint: got %s want %s", first, want)
	}
	if second != first {
		t.Fatalf("expected algorithm normalization to be deterministic, got %s then %s", first, second)
	}
	if keyID == first {
		t.Fatalf("expected versioned proof fingerprint to be distinct from legacy raw key id")
	}
}

func seedProofLicenseManager(t *testing.T, maxDevices int) (*LicenseManager, *Client, *License) {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	ctx := context.Background()
	client, err := lm.CreateClient(ctx, "proof@example.com")
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	license, err := lm.GenerateLicense(ctx, client.ID, 24*time.Hour, maxDevices, "pro", LicenseCheckModeEachRun, 0)
	if err != nil {
		t.Fatalf("GenerateLicense failed: %v", err)
	}
	return lm, client, license
}

func TestDeviceProofRejectsFakeActivationWithoutProof(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)

	req := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: "attackerchosenfp01",
	}
	resp, err := lm.ActivateLicense(context.Background(), req)
	if err != nil {
		t.Fatalf("ActivateLicense failed: %v", err)
	}
	if resp.Success || resp.Message != "device proof required" {
		t.Fatalf("expected fake activation without proof to be rejected, got %+v", resp)
	}
}

func TestDeviceProofRejectsSpoofedDeviceCapAttemptsWithoutProof(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 2)

	for _, fp := range []string{"fakefingerprint0001", "fakefingerprint0002", "fakefingerprint0003"} {
		resp, err := lm.ActivateLicense(context.Background(), &ActivationRequest{
			Email:             client.Email,
			ClientID:          client.ID,
			LicenseKey:        license.LicenseKey,
			DeviceFingerprint: fp,
		})
		if err != nil || !resp.Success {
			if err != nil {
				t.Fatalf("ActivateLicense(%s) failed unexpectedly: %v", fp, err)
			}
			if resp.Message != "device proof required" {
				t.Fatalf("expected fake fingerprint %s to be rejected for missing proof, got %+v", fp, resp)
			}
			continue
		}
		t.Fatalf("expected fake fingerprint %s to be rejected before device-cap accounting, got %+v", fp, resp)
	}
}

func TestDeviceProofRejectsTrialBypassWithRotatedFakeFingerprintsWithoutProof(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	lm, err := NewLicenseManager(NewInMemoryStorage())
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}

	for _, fp := range []string{"trialfakefp000001", "trialfakefp000002", "trialfakefp000003"} {
		resp, err := lm.GenerateTrialLicense(context.Background(), &TrialLicenseRequest{
			Email:             "trial-pentest@example.com",
			DeviceFingerprint: fp,
			TrialDurationDays: 7,
		})
		if err != nil {
			if err.Error() != "device proof required" {
				t.Fatalf("expected missing proof rejection for %s, got %v", fp, err)
			}
			continue
		}
		if resp.Success {
			t.Fatalf("expected rotated fake fingerprint %s to be rejected without proof, got %+v", fp, resp)
		}
	}
}

func TestDeviceProofRejectsCopiedLicenseSpoofWithOnlyFingerprint(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	copiedFingerprint := testEd25519Fingerprint(priv)
	activateReq := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: copiedFingerprint,
	}
	activateReq.DeviceProof = testDeviceProof(t, DeviceProofPurposeActivate, &DeviceChallenge{ID: "ch-1", Nonce: "nonce-1"}, activateReq, priv)

	activateResp, err := lm.ActivateLicense(context.Background(), activateReq)
	if err != nil || !activateResp.Success {
		t.Fatalf("activation with proof failed: resp=%+v err=%v", activateResp, err)
	}

	verifyResp, err := lm.VerifyLicense(context.Background(), &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: copiedFingerprint,
	})
	if err != nil {
		t.Fatalf("VerifyLicense failed: %v", err)
	}
	if verifyResp.Success || verifyResp.Message != "device proof required" {
		t.Fatalf("expected copied fingerprint without device proof to fail, got %+v", verifyResp)
	}
}

func TestDeviceProofRejectsPublicKeyMismatch(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	req := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: testEd25519Fingerprint(priv),
	}
	req.DeviceProof = testDeviceProof(t, DeviceProofPurposeActivate, &DeviceChallenge{ID: "ch-1", Nonce: "nonce-1"}, req, priv)
	resp, err := lm.ActivateLicense(context.Background(), req)
	if err != nil || !resp.Success {
		t.Fatalf("expected v2 activation to succeed, resp=%+v err=%v", resp, err)
	}

	_, otherPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey other failed: %v", err)
	}
	verifyReq := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: req.DeviceFingerprint,
	}
	verifyReq.DeviceProof = testDeviceProof(t, DeviceProofPurposeVerify, &DeviceChallenge{ID: "ch-2", Nonce: "nonce-2"}, verifyReq, otherPriv)
	verifyResp, err := lm.VerifyLicense(context.Background(), verifyReq)
	if err != nil {
		t.Fatalf("VerifyLicense returned unexpected error: %v", err)
	}
	if verifyResp.Success || verifyResp.Message != "device proof fingerprint mismatch" {
		t.Fatalf("expected fingerprint mismatch failure, got %+v", verifyResp)
	}
}

func activateTestDevice(t *testing.T, lm *LicenseManager, client *Client, license *License, fingerprint string, priv ed25519.PrivateKey, replacementToken string) *ActivationResponse {
	t.Helper()
	if fingerprint == "" {
		fingerprint = testEd25519Fingerprint(priv)
	}
	req := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: fingerprint,
		ReplacementToken:  replacementToken,
	}
	req.DeviceProof = testDeviceProof(t, DeviceProofPurposeActivate, &DeviceChallenge{ID: "activate-" + fingerprint, Nonce: "nonce-" + fingerprint}, req, priv)
	resp, err := lm.ActivateLicense(context.Background(), req)
	if err != nil {
		t.Fatalf("ActivateLicense failed: %v", err)
	}
	return resp
}

func verifyTestDevice(t *testing.T, lm *LicenseManager, client *Client, license *License, fingerprint string, priv ed25519.PrivateKey) *ActivationResponse {
	t.Helper()
	req := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: fingerprint,
	}
	req.DeviceProof = testDeviceProof(t, DeviceProofPurposeVerify, &DeviceChallenge{ID: "verify-" + fingerprint, Nonce: "nonce-" + fingerprint}, req, priv)
	resp, err := lm.VerifyLicense(context.Background(), req)
	if err != nil {
		t.Fatalf("VerifyLicense failed: %v", err)
	}
	return resp
}

func TestDeviceLifecycleRejectsRevokedDeviceVerification(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	fp := testEd25519Fingerprint(priv)
	if resp := activateTestDevice(t, lm, client, license, fp, priv, ""); !resp.Success {
		t.Fatalf("activation failed: %+v", resp)
	}
	if _, err := lm.RevokeDevice(context.Background(), license.ID, fp, "test revoke"); err != nil {
		t.Fatalf("RevokeDevice failed: %v", err)
	}
	resp := verifyTestDevice(t, lm, client, license, fp, priv)
	if resp.Success || resp.Message != "Device is revoked" {
		t.Fatalf("expected revoked device verification failure, got %+v", resp)
	}
}

func TestDeviceReplacementTokenReplacesDeviceWithoutIncreasingCount(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)
	_, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey old failed: %v", err)
	}
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey new failed: %v", err)
	}
	oldFP := testEd25519Fingerprint(oldPriv)
	newFP := testEd25519Fingerprint(newPriv)
	if resp := activateTestDevice(t, lm, client, license, oldFP, oldPriv, ""); !resp.Success {
		t.Fatalf("old activation failed: %+v", resp)
	}
	_, tokenValue, err := lm.IssueDeviceReplacementToken(context.Background(), license.ID, oldFP, "test", time.Hour)
	if err != nil {
		t.Fatalf("IssueDeviceReplacementToken failed: %v", err)
	}
	if resp := activateTestDevice(t, lm, client, license, newFP, newPriv, tokenValue); !resp.Success {
		t.Fatalf("replacement activation failed: %+v", resp)
	}
	updated, err := lm.storage.GetLicense(context.Background(), license.ID)
	if err != nil {
		t.Fatalf("GetLicense failed: %v", err)
	}
	if updated.DeviceCount != 1 || updated.CurrentActivations != 1 {
		t.Fatalf("expected one active device after replacement, got count=%d activations=%d", updated.DeviceCount, updated.CurrentActivations)
	}
	if got := updated.Devices[oldFP].Status; got != DeviceStatusReplaced {
		t.Fatalf("expected old device replaced, got %s", got)
	}
	if got := updated.Devices[newFP].Status; got != DeviceStatusTrusted {
		t.Fatalf("expected new device trusted, got %s", got)
	}
	resp := activateTestDevice(t, lm, client, license, "", newPriv, tokenValue)
	if resp.Success || resp.Message != "replacement token has already been used" {
		t.Fatalf("expected reused replacement token rejection, got %+v", resp)
	}
}

func TestDeviceReplacementTokenRejectsExpiredAndWrongLicense(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)
	otherLM, otherClient, otherLicense := seedProofLicenseManager(t, 1)
	_, oldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey old failed: %v", err)
	}
	_, newPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey new failed: %v", err)
	}
	oldFP := testEd25519Fingerprint(oldPriv)
	if resp := activateTestDevice(t, lm, client, license, oldFP, oldPriv, ""); !resp.Success {
		t.Fatalf("old activation failed: %+v", resp)
	}
	_, expiredToken, err := lm.IssueDeviceReplacementToken(context.Background(), license.ID, oldFP, "test", time.Nanosecond)
	if err != nil {
		t.Fatalf("IssueDeviceReplacementToken expired failed: %v", err)
	}
	time.Sleep(time.Millisecond)
	resp := activateTestDevice(t, lm, client, license, "", newPriv, expiredToken)
	if resp.Success || resp.Message != "replacement token expired" {
		t.Fatalf("expected expired replacement token rejection, got %+v", resp)
	}

	_, otherOldPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey other old failed: %v", err)
	}
	otherOldFP := testEd25519Fingerprint(otherOldPriv)
	if resp := activateTestDevice(t, otherLM, otherClient, otherLicense, otherOldFP, otherOldPriv, ""); !resp.Success {
		t.Fatalf("other activation failed: %+v", resp)
	}
	_, wrongLicenseToken, err := otherLM.IssueDeviceReplacementToken(context.Background(), otherLicense.ID, otherOldFP, "test", time.Hour)
	if err != nil {
		t.Fatalf("IssueDeviceReplacementToken wrong-license failed: %v", err)
	}
	resp = activateTestDevice(t, lm, client, license, "", newPriv, wrongLicenseToken)
	if resp.Success || resp.Message != "invalid replacement token" {
		t.Fatalf("expected wrong license token rejection, got %+v", resp)
	}
}

func TestDeviceProofAcceptsRSAPSSSHA256Provider(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	req := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: testRSAFingerprint(t, priv),
	}
	req.DeviceProof = testRSADeviceProof(t, DeviceProofPurposeActivate, &DeviceChallenge{ID: "rsa-ch-1", Nonce: "rsa-nonce-1"}, req, priv)
	resp, err := lm.ActivateLicense(context.Background(), req)
	if err != nil || !resp.Success {
		t.Fatalf("expected RSA-PSS activation to succeed, resp=%+v err=%v", resp, err)
	}
	got, err := lm.storage.GetLicense(context.Background(), license.ID)
	if err != nil {
		t.Fatalf("GetLicense failed: %v", err)
	}
	device := got.Devices[req.DeviceFingerprint]
	if device == nil {
		t.Fatalf("expected RSA proof device to be registered")
	}
	if device.PublicKeyAlgorithm != DeviceProofAlgorithmRSAPSSSHA256 || device.KeyProvider != "hardware-tpm2-test" {
		t.Fatalf("unexpected stored proof metadata: %+v", device)
	}

	verifyReq := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: req.DeviceFingerprint,
	}
	verifyReq.DeviceProof = testRSADeviceProof(t, DeviceProofPurposeVerify, &DeviceChallenge{ID: "rsa-ch-2", Nonce: "rsa-nonce-2"}, verifyReq, priv)
	verifyResp, err := lm.VerifyLicense(context.Background(), verifyReq)
	if err != nil || !verifyResp.Success {
		t.Fatalf("expected RSA-PSS verify to succeed, resp=%+v err=%v", verifyResp, err)
	}
}

func TestDeviceChallengeReplayIsRejected(t *testing.T) {
	lm, client, license := seedProofLicenseManager(t, 1)
	server, err := NewServer(lm, ":0", nil, NewRateLimiter(100, time.Minute), "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	activateChallenge := requestTestChallenge(t, server, DeviceProofPurposeActivate)
	activateReq := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: testEd25519Fingerprint(priv),
	}
	activateReq.DeviceProof = testDeviceProof(t, DeviceProofPurposeActivate, activateChallenge, activateReq, priv)
	body, _ := json.Marshal(activateReq)
	w := httptest.NewRecorder()
	server.handleActivate(w, httptest.NewRequest(http.MethodPost, "/api/activate", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("activation failed: code=%d body=%s", w.Code, w.Body.String())
	}

	verifyChallenge := requestTestChallenge(t, server, DeviceProofPurposeVerify)
	verifyReq := &ActivationRequest{
		Email:             client.Email,
		ClientID:          client.ID,
		LicenseKey:        license.LicenseKey,
		DeviceFingerprint: activateReq.DeviceFingerprint,
	}
	verifyReq.DeviceProof = testDeviceProof(t, DeviceProofPurposeVerify, verifyChallenge, verifyReq, priv)
	verifyBody, _ := json.Marshal(verifyReq)
	w = httptest.NewRecorder()
	server.handleVerify(w, httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(verifyBody)))
	if w.Code != http.StatusOK {
		t.Fatalf("first verify failed: code=%d body=%s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	server.handleVerify(w, httptest.NewRequest(http.MethodPost, "/api/verify", bytes.NewReader(verifyBody)))
	if w.Code == http.StatusOK {
		t.Fatalf("expected replayed challenge to be rejected")
	}
}

func requestTestChallenge(t *testing.T, server *Server, purpose string) *DeviceChallenge {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"purpose": purpose})
	w := httptest.NewRecorder()
	server.handleDeviceChallenge(w, httptest.NewRequest(http.MethodPost, "/api/device/challenge", bytes.NewReader(body)))
	if w.Code != http.StatusCreated {
		t.Fatalf("challenge failed: code=%d body=%s", w.Code, w.Body.String())
	}
	var challenge DeviceChallenge
	if err := json.Unmarshal(w.Body.Bytes(), &challenge); err != nil {
		t.Fatalf("decode challenge failed: %v", err)
	}
	return &challenge
}

func TestSQLiteDeviceProofColumnsAddedToExistingLicenseDevicesTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "licensing.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite failed: %v", err)
	}
	if _, err := db.Exec(`CREATE TABLE license_devices (
		license_id TEXT NOT NULL,
		fingerprint TEXT NOT NULL,
		activated_at TIMESTAMP NOT NULL,
		last_seen_at TIMESTAMP NOT NULL,
		transport_key BLOB NOT NULL,
		PRIMARY KEY(license_id, fingerprint)
	);`); err != nil {
		t.Fatalf("create old license_devices failed: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite failed: %v", err)
	}

	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	defer storage.db.Close()
	for _, column := range []string{
		"status",
		"label",
		"hardware_fingerprint",
		"hardware_confidence",
		"last_ip",
		"last_user_agent",
		"app_version",
		"proof_version",
		"device_key_id",
		"device_public_key",
		"public_key_algorithm",
		"key_provider",
		"attestation_type",
		"attestation_status",
		"last_proof_at",
		"revoked_at",
		"revoked_reason",
		"replaced_by_fingerprint",
		"replacement_token_id",
	} {
		exists, err := sqliteColumnExists(storage.db, "license_devices", column)
		if err != nil {
			t.Fatalf("sqliteColumnExists(%s) failed: %v", column, err)
		}
		if !exists {
			t.Fatalf("expected license_devices.%s to be added", column)
		}
	}
	var tableName string
	if err := storage.db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'device_replacement_tokens'`).Scan(&tableName); err != nil {
		t.Fatalf("expected device_replacement_tokens table to exist: %v", err)
	}
}
