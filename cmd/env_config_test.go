package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDotEnvConfigSetsMissingEnvironmentValues(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("LICENSE_SERVER_ALLOW_INSECURE_HTTP=1\nLICENSE_SERVER_HTTP_ADDR=:7777\n"), 0o600); err != nil {
		t.Fatalf("write .env failed: %v", err)
	}
	t.Setenv("LICENSE_SERVER_ALLOW_INSECURE_HTTP", "")
	t.Setenv("LICENSE_SERVER_ENV_FILE", "")
	unsetenv(t, "LICENSE_SERVER_HTTP_ADDR")

	if err := loadDotEnvConfig(); err != nil {
		t.Fatalf("loadDotEnvConfig failed: %v", err)
	}

	if got := os.Getenv("LICENSE_SERVER_ALLOW_INSECURE_HTTP"); got != "" {
		t.Fatalf("expected existing env to win, got %q", got)
	}
	if got := os.Getenv("LICENSE_SERVER_HTTP_ADDR"); got != ":7777" {
		t.Fatalf("expected .env value, got %q", got)
	}
}

func TestLoadDotEnvConfigUsesConfiguredFile(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)

	custom := filepath.Join(dir, "server.env")
	if err := os.WriteFile(custom, []byte("LICENSE_SERVER_STORAGE=memory\n"), 0o600); err != nil {
		t.Fatalf("write custom dotenv failed: %v", err)
	}
	t.Setenv("LICENSE_SERVER_ENV_FILE", custom)
	unsetenv(t, "LICENSE_SERVER_STORAGE")

	if err := loadDotEnvConfig(); err != nil {
		t.Fatalf("loadDotEnvConfig failed: %v", err)
	}
	if got := os.Getenv("LICENSE_SERVER_STORAGE"); got != "memory" {
		t.Fatalf("expected custom .env value, got %q", got)
	}
}

func TestLoadDotEnvConfigIgnoresMissingDefaultFile(t *testing.T) {
	dir := t.TempDir()
	chdir(t, dir)
	t.Setenv("LICENSE_SERVER_ENV_FILE", "")

	if err := loadDotEnvConfig(); err != nil {
		t.Fatalf("expected missing default .env to be ignored, got %v", err)
	}
}

func chdir(t *testing.T, dir string) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd failed: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir failed: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(wd); err != nil {
			t.Fatalf("restore working directory failed: %v", err)
		}
	})
}

func unsetenv(t *testing.T, key string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatalf("unset %s failed: %v", key, err)
	}
	t.Cleanup(func() {
		var err error
		if existed {
			err = os.Setenv(key, old)
		} else {
			err = os.Unsetenv(key)
		}
		if err != nil {
			t.Fatalf("restore %s failed: %v", key, err)
		}
	})
}
