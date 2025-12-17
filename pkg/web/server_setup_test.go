package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/oarkflow/licensing/pkg/licensing"
)

func TestHandleAPISetupWithSQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "licensing.db")

	storage, err := licensing.NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	lm, err := licensing.NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}

	ws, err := NewWebServer(lm)
	if err != nil {
		t.Fatalf("NewWebServer failed: %v", err)
	}

	// Call setup handler
	reqBody := map[string]string{"username": "admin", "password": "supersecure"}
	b, _ := json.Marshal(reqBody)
	req := httptest.NewRequest("POST", "/api/auth/setup", bytes.NewReader(b))
	w := httptest.NewRecorder()
	ws.handleAPISetup(w, req)
	if w.Code != 201 {
		t.Fatalf("expected 201 created, got %d, body=%s", w.Code, w.Body.String())
	}

	// Ensure an API key exists for the created user
	ctx := context.Background()
	users, err := lm.ListAdminUsers(ctx)
	if err != nil || len(users) == 0 {
		t.Fatalf("expected admin user to exist: %v", err)
	}
	keys, err := lm.ListAPIKeysByUser(ctx, users[0].ID)
	if err != nil {
		t.Fatalf("ListAPIKeysByUser failed: %v", err)
	}
	if len(keys) == 0 {
		t.Fatalf("expected API key to be created for admin user")
	}
}
