package licensing

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestClientRegisterLoginProfileFlow(t *testing.T) {
	storage := NewInMemoryStorage()
	// Ensure templates exist for EmailTemplateLoader, since NewServer loads them
	_ = os.MkdirAll("templates/email", 0o755)
	_ = os.WriteFile("templates/email/license_email.html", []byte("<html><body>License for {{.ClientName}}</body></html>"), 0o644)
	_ = os.WriteFile("templates/email/welcome_email.html", []byte("<html><body>Welcome {{.ClientName}}</body></html>"), 0o644)
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
	regReq := map[string]string{"email": "test@example.com", "password": "supersecure", "name": "Test"}
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
	client, err := lm.CreateClientWithPassword(ctx, "offline@example.com", "pw12345", "Offline", "Corp")
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
