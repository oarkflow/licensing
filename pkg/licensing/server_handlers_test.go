package licensing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestClientRegisterLoginProfileFlow(t *testing.T) {
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("failed to create license manager: %v", err)
	}
	rl := NewRateLimiter(100, time.Minute)
	s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Register client
	regReq := map[string]string{"email": "test@example.com", "username": "testuser", "password": "supersecure", "name": "Test"}
	body, _ := json.Marshal(regReq)
	req := httptest.NewRequest(http.MethodPost, "/api/client/auth/register", bytes.NewReader(body))
	w := httptest.NewRecorder()
	s.handleClientRegister(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected status 201 created, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	clientObj := resp["client"]
	if clientObj == nil {
		t.Fatalf("client not returned")
	}

	// Extract cookie set
	cookie := w.Result().Cookies()
	if len(cookie) == 0 {
		t.Fatalf("expected cookie to be set on register")
	}

	// Now call profile endpoint using the cookie
	req2 := httptest.NewRequest(http.MethodGet, "/api/client/profile", nil)
	for _, c := range cookie {
		req2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	s.handleClientProfile(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected profile 200, got %d, body=%s", w2.Code, w2.Body.String())
	}

	// Test login: logout then login
	// Logout first
	req3 := httptest.NewRequest(http.MethodPost, "/api/client/auth/logout", nil)
	for _, c := range cookie {
		req3.AddCookie(c)
	}
	w3 := httptest.NewRecorder()
	s.handleClientLogout(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected logout 200, got %d, body=%s", w3.Code, w3.Body.String())
	}

	// Login
	loginReq := map[string]string{"email": "test@example.com", "password": "supersecure"}
	bl, _ := json.Marshal(loginReq)
	req4 := httptest.NewRequest(http.MethodPost, "/api/client/auth/login", bytes.NewReader(bl))
	w4 := httptest.NewRecorder()
	s.handleClientLogin(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d, body=%s", w4.Code, w4.Body.String())
	}
	// Ensure new cookie set
	cookie2 := w4.Result().Cookies()
	if len(cookie2) == 0 {
		t.Fatalf("expected cookie to be set on login")
	}

	// Refresh token
	var resp4 map[string]interface{}
	if err := json.Unmarshal(w4.Body.Bytes(), &resp4); err != nil {
		t.Fatalf("failed to decode login response: %v", err)
	}
	session := resp4["session"].(map[string]interface{})
	if session == nil {
		t.Fatalf("session missing from login response")
	}
	refresh := session["refresh_token"].(string)
	if refresh == "" {
		t.Fatalf("expected refresh token in session")
	}

	// Call refresh endpoint
	refreshReq := map[string]string{"refresh_token": refresh}
	rb, _ := json.Marshal(refreshReq)
	req5 := httptest.NewRequest(http.MethodPost, "/api/client/auth/refresh", bytes.NewReader(rb))
	w5 := httptest.NewRecorder()
	s.handleClientRefresh(w5, req5)
	if w5.Code != http.StatusOK {
		t.Fatalf("expected refresh 200, got %d, body=%s", w5.Code, w5.Body.String())
	}

	// Success - can retrieve profile with cookie from refresh
	// Get cookie
	cookieRefresh := w5.Result().Cookies()
	req6 := httptest.NewRequest(http.MethodGet, "/api/client/profile", nil)
	for _, c := range cookieRefresh {
		req6.AddCookie(c)
	}
	w6 := httptest.NewRecorder()
	s.handleClientProfile(w6, req6)
	if w6.Code != http.StatusOK {
		t.Fatalf("expected profile 200 after refresh, got %d, body=%s", w6.Code, w6.Body.String())
	}

	// Login via username
	loginReq2 := map[string]string{"username": "testuser", "password": "supersecure"}
	bl2, _ := json.Marshal(loginReq2)
	req7 := httptest.NewRequest(http.MethodPost, "/api/client/auth/login", bytes.NewReader(bl2))
	w7 := httptest.NewRecorder()
	s.handleClientLogin(w7, req7)
	if w7.Code != http.StatusOK {
		t.Fatalf("expected login 200 for username, got %d, body=%s", w7.Code, w7.Body.String())
	}
}

func TestOfflineTokenGenerateValidateFlow(t *testing.T) {
	storage := NewInMemoryStorage()
	// Create manager and server
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	rl := NewRateLimiter(100, time.Minute)
	s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()
	// create product
	product := &Product{ID: "prod-1", Name: "P1", Slug: "p1", CreatedAt: time.Now(), UpdatedAt: time.Now()}
	if err := lm.Storage().SaveProduct(ctx, product); err != nil {
		t.Fatalf("failed to save product: %v", err)
	}
	// create plan
	plan := &Plan{ID: "plan-1", ProductID: product.ID, Name: "Plan1", Slug: "p1-basic", BillingCycle: "yearly", IsActive: true, CreatedAt: time.Now(), UpdatedAt: time.Now(), DurationDays: 365}
	if err := lm.Storage().SavePlan(ctx, plan); err != nil {
		t.Fatalf("failed to save plan: %v", err)
	}
	// create client
	client, err := lm.CreateClientWithPassword(ctx, "offline@example.com", "pw12345", "", "Offline", "Corp")
	if err != nil {
		t.Fatalf("CreateClientWithPassword failed: %v", err)
	}
	// generate license
	mode, interval := lm.DefaultCheckPolicy()
	license, err := lm.GenerateLicenseWithOptions(ctx, client.ID, 365*24*time.Hour, 2, plan.Slug, mode, interval, &GenerateLicenseOptions{ProductID: product.ID, PlanID: plan.ID})
	if err != nil {
		t.Fatalf("GenerateLicenseWithOptions failed: %v", err)
	}
	// add device to license
	fp := "device-1234567890abcd"
	license.Devices = map[string]*LicenseDevice{fp: {Fingerprint: fp, ActivatedAt: time.Now(), LastSeenAt: time.Now()}}
	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		t.Fatalf("failed to update license: %v", err)
	}

	// Create admin user and API key
	admin, err := lm.CreateAdminUser(ctx, "admin", "adminpass")
	if err != nil {
		t.Fatalf("CreateAdminUser failed: %v", err)
	}
	token, _, err := lm.GenerateAPIKey(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}

	// Generate offline token via handler
	reqBody := map[string]any{"license_key": license.LicenseKey, "device_fingerprint": fp, "max_uses": 2, "validity_days": 7}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/api/licenses/offline-token", bytes.NewReader(b))
	req.Header.Set("X-API-Key", token)
	w := httptest.NewRecorder()
	s.handleGenerateOfflineToken(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 for generate offline token, got %d, body=%s", w.Code, w.Body.String())
	}
	var resp OfflineValidationToken
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to unmarshal offline token: %v", err)
	}
	if resp.Token == "" {
		t.Fatalf("expected token string created")
	}

	// Validate offline token via handler
	vreq := map[string]string{"offline_token": resp.Token, "device_fingerprint": fp}
	vb, _ := json.Marshal(vreq)
	req2 := httptest.NewRequest(http.MethodPost, "/api/licenses/offline-validate", bytes.NewReader(vb))
	w2 := httptest.NewRecorder()
	s.handleValidateOfflineToken(w2, req2)
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200 for validate offline token, got %d, body=%s", w2.Code, w2.Body.String())
	}
	var vresp map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &vresp); err != nil {
		t.Fatalf("failed to unmarshal validate response: %v", err)
	}
	if _, ok := vresp["license"]; !ok {
		t.Fatalf("validate did not return license")
	}
}

func TestClientAPIKeysCRUD(t *testing.T) {
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	rl := NewRateLimiter(100, time.Minute)
	s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Create client and register
	ctx := context.Background()
	client, err := lm.CreateClientWithPassword(ctx, "client1@example.com", "pw12345", "", "C1", "Co")
	if err != nil {
		t.Fatalf("CreateClientWithPassword failed: %v", err)
	}

	// Login to get session cookie
	loginReq := map[string]string{"email": client.Email, "password": "pw12345"}
	bl, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/api/client/auth/login", bytes.NewReader(bl))
	w := httptest.NewRecorder()
	s.handleClientLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected login 200, got %d, body=%s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()
	if len(cookie) == 0 {
		t.Fatalf("expected cookie to be set on client login")
	}

	// Create API key via client endpoint
	req2 := httptest.NewRequest(http.MethodPost, "/api/client/keys", nil)
	for _, c := range cookie {
		req2.AddCookie(c)
	}
	w2 := httptest.NewRecorder()
	s.handleClientKeys(w2, req2)
	if w2.Code != http.StatusCreated {
		t.Fatalf("expected 201 created on client key creation, got %d: %s", w2.Code, w2.Body.String())
	}
	var resp map[string]interface{}
	if err := json.Unmarshal(w2.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode create response: %v", err)
	}
	token := resp["token"].(string)
	if token == "" {
		t.Fatalf("expected token returned from create")
	}

	// List keys
	req3 := httptest.NewRequest(http.MethodGet, "/api/client/keys", nil)
	for _, c := range cookie {
		req3.AddCookie(c)
	}
	w3 := httptest.NewRecorder()
	s.handleClientKeys(w3, req3)
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200 on list client keys, got %d: %s", w3.Code, w3.Body.String())
	}
	var listResp []map[string]interface{}
	if err := json.Unmarshal(w3.Body.Bytes(), &listResp); err != nil {
		t.Fatalf("failed to decode list response: %v", err)
	}
	if len(listResp) == 0 {
		t.Fatalf("expected non-empty key list")
	}
	keyID := listResp[0]["id"].(string)

	// Delete key
	req4 := httptest.NewRequest(http.MethodDelete, "/api/client/keys/"+keyID, nil)
	for _, c := range cookie {
		req4.AddCookie(c)
	}
	w4 := httptest.NewRecorder()
	s.handleClientKeys(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("expected 200 ok on delete, got %d: %s", w4.Code, w4.Body.String())
	}
}

func TestClientAPIKeyAuthorizationHeader(t *testing.T) {
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	rl := NewRateLimiter(100, time.Minute)
	s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Create client
	ctx := context.Background()
	client, err := lm.CreateClientWithPassword(ctx, "client2@example.com", "pw12345", "client2", "C2", "Co")
	if err != nil {
		t.Fatalf("CreateClientWithPassword failed: %v", err)
	}

	// Generate API key for client via LM directly
	token, _, err := lm.GenerateClientAPIKey(ctx, client.ID)
	if err != nil {
		t.Fatalf("GenerateClientAPIKey failed: %v", err)
	}

	// Call profile endpoint using Authorization Bearer header with API key
	req := httptest.NewRequest(http.MethodGet, "/api/client/profile", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.handleClientProfile(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected profile 200 with Authorization API key, got %d, body=%s", w.Code, w.Body.String())
	}
}

func TestClientEndpointLoginPath(t *testing.T) {
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	rl := NewRateLimiter(100, time.Minute)
	s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	// Create client
	ctx := context.Background()
	client, err := lm.CreateClientWithPassword(ctx, "client3@example.com", "pw12345", "client3", "C3", "Co")
	if err != nil {
		t.Fatalf("CreateClientWithPassword failed: %v", err)
	}

	// POST /client/login using username/password
	loginReq := map[string]string{"username": client.Username, "password": "pw12345"}
	bl, _ := json.Marshal(loginReq)
	req := httptest.NewRequest(http.MethodPost, "/client/login", bytes.NewReader(bl))
	w := httptest.NewRecorder()
	s.handleClientLogin(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected login 200 on /client/login, got %d: %s", w.Code, w.Body.String())
	}
}

func TestAdminAuthorizationWithBearerToken(t *testing.T) {
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	rl := NewRateLimiter(100, time.Minute)
	s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()
	admin, err := lm.CreateAdminUser(ctx, "adminx", "password")
	if err != nil {
		t.Fatalf("CreateAdminUser failed: %v", err)
	}
	token, _, err := lm.GenerateAPIKey(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/clients", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	s.handleClients(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from /api/clients with Authorization bearer token, got %d, body=%s", w.Code, w.Body.String())
	}
}

func TestAdminDeviceLifecycleHandlers(t *testing.T) {
	storage := NewInMemoryStorage()
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	rl := NewRateLimiter(100, time.Minute)
	s, err := NewServer(lm, ":0", nil, rl, "", "", "", true)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()
	admin, err := lm.CreateAdminUser(ctx, "deviceadmin", "password")
	if err != nil {
		t.Fatalf("CreateAdminUser failed: %v", err)
	}
	apiKey, _, err := lm.GenerateAPIKey(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}
	client, err := lm.CreateClient(ctx, "device-handler@example.com")
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	license, err := lm.GenerateLicense(ctx, client.ID, 24*time.Hour, 1, "pro", LicenseCheckModeEachRun, 0)
	if err != nil {
		t.Fatalf("GenerateLicense failed: %v", err)
	}
	const fp = "handlerdevice0001"
	license.Devices = map[string]*LicenseDevice{
		fp: {Fingerprint: fp, ActivatedAt: time.Now(), LastSeenAt: time.Now(), Status: DeviceStatusTrusted, TransportKey: []byte("12345678901234567890123456789012")},
	}
	if err := lm.storage.UpdateLicense(ctx, license); err != nil {
		t.Fatalf("UpdateLicense failed: %v", err)
	}

	revokeBody, _ := json.Marshal(map[string]string{"reason": "handler test"})
	req := httptest.NewRequest(http.MethodPost, "/api/licenses/"+license.ID+"/devices/"+fp+"/revoke", bytes.NewReader(revokeBody))
	req.Header.Set("X-API-Key", apiKey)
	w := httptest.NewRecorder()
	s.handleLicenseActions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected revoke 200, got %d body=%s", w.Code, w.Body.String())
	}
	updated, err := lm.storage.GetLicense(ctx, license.ID)
	if err != nil {
		t.Fatalf("GetLicense failed: %v", err)
	}
	if got := updated.Devices[fp].Status; got != DeviceStatusRevoked {
		t.Fatalf("expected revoked device, got %s", got)
	}

	req = httptest.NewRequest(http.MethodPost, "/api/licenses/"+license.ID+"/devices/"+fp+"/reinstate", nil)
	req.Header.Set("X-API-Key", apiKey)
	w = httptest.NewRecorder()
	s.handleLicenseActions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected reinstate 200, got %d body=%s", w.Code, w.Body.String())
	}

	reqBody, _ := json.Marshal(map[string]int{"ttl_hours": 1})
	req = httptest.NewRequest(http.MethodPost, "/api/licenses/"+license.ID+"/devices/"+fp+"/replacement-token", bytes.NewReader(reqBody))
	req.Header.Set("X-API-Key", apiKey)
	w = httptest.NewRecorder()
	s.handleLicenseActions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected replacement-token 200, got %d body=%s", w.Code, w.Body.String())
	}
	var tokenResp struct {
		Token       string                  `json:"token"`
		TokenRecord *DeviceReplacementToken `json:"token_record"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &tokenResp); err != nil {
		t.Fatalf("decode token response failed: %v", err)
	}
	if tokenResp.Token == "" || tokenResp.TokenRecord == nil || tokenResp.TokenRecord.OldFingerprint != fp {
		t.Fatalf("unexpected token response: %+v", tokenResp)
	}

	req = httptest.NewRequest(http.MethodGet, "/api/licenses/"+license.ID+"/device-replacement-tokens", nil)
	req.Header.Set("X-API-Key", apiKey)
	w = httptest.NewRecorder()
	s.handleLicenseActions(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected replacement-token list 200, got %d body=%s", w.Code, w.Body.String())
	}
	var tokens []*DeviceReplacementToken
	if err := json.Unmarshal(w.Body.Bytes(), &tokens); err != nil {
		t.Fatalf("decode token list failed: %v", err)
	}
	if len(tokens) != 1 || tokens[0].ID != tokenResp.TokenRecord.ID {
		t.Fatalf("unexpected token list: %+v", tokens)
	}
}
