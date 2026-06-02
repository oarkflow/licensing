package licensing

import (
	"context"
	"path/filepath"
	"testing"
)

func TestSQLiteAPIKeysPersistNullableOwnerForeignKeys(t *testing.T) {
	ctx := context.Background()
	storage, err := NewSQLiteStorage(filepath.Join(t.TempDir(), "licensing.db"))
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}

	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}
	defer lm.Close()

	admin, err := lm.CreateAdminUser(ctx, "admin", "password123")
	if err != nil {
		t.Fatalf("CreateAdminUser failed: %v", err)
	}
	adminToken, adminRecord, err := lm.GenerateAPIKey(ctx, admin.ID)
	if err != nil {
		t.Fatalf("GenerateAPIKey(admin) failed: %v", err)
	}
	if adminToken == "" || adminRecord.ClientID != "" || adminRecord.UserID != admin.ID {
		t.Fatalf("unexpected admin api key record: token=%q record=%+v", adminToken, adminRecord)
	}
	adminKeys, err := lm.ListAPIKeysByUser(ctx, admin.ID)
	if err != nil {
		t.Fatalf("ListAPIKeysByUser failed: %v", err)
	}
	if len(adminKeys) != 1 || adminKeys[0].ClientID != "" || adminKeys[0].UserID != admin.ID {
		t.Fatalf("unexpected listed admin keys: %+v", adminKeys)
	}

	client, err := lm.CreateClient(ctx, "client@example.com")
	if err != nil {
		t.Fatalf("CreateClient failed: %v", err)
	}
	clientToken, clientRecord, err := lm.GenerateClientAPIKey(ctx, client.ID)
	if err != nil {
		t.Fatalf("GenerateClientAPIKey failed: %v", err)
	}
	if clientToken == "" || clientRecord.UserID != "" || clientRecord.ClientID != client.ID {
		t.Fatalf("unexpected client api key record: token=%q record=%+v", clientToken, clientRecord)
	}
	clientKeys, err := lm.ListAPIKeysByClient(ctx, client.ID)
	if err != nil {
		t.Fatalf("ListAPIKeysByClient failed: %v", err)
	}
	if len(clientKeys) != 1 || clientKeys[0].UserID != "" || clientKeys[0].ClientID != client.ID {
		t.Fatalf("unexpected listed client keys: %+v", clientKeys)
	}
}
