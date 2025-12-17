package licensing

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCreateAdminAndGenerateAPIKeySQLite(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "licensing.db")
	storage, err := NewSQLiteStorage(dbPath)
	if err != nil {
		t.Fatalf("NewSQLiteStorage failed: %v", err)
	}
	lm, err := NewLicenseManager(storage)
	if err != nil {
		t.Fatalf("NewLicenseManager failed: %v", err)
	}

	ctx := context.Background()
	admin, err := lm.CreateAdminUser(ctx, "admin", "supersecure")
	if err != nil {
		t.Fatalf("CreateAdminUser failed: %v", err)
	}
	if _, _, err := lm.GenerateAPIKey(ctx, admin.ID); err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}
}
