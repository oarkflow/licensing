package licensing

import (
	"testing"
	"time"
)

func TestRateLimitConfigFromEnvDefaults(t *testing.T) {
	cfg, err := RateLimitConfigFromEnv()
	if err != nil {
		t.Fatalf("RateLimitConfigFromEnv failed: %v", err)
	}
	if cfg.DefaultLimit != 30 || cfg.AdminLimit != 300 || cfg.ActivationLimit != 30 || cfg.VerificationLimit != 60 || cfg.ClientAuthLimit != 30 {
		t.Fatalf("unexpected defaults: %+v", cfg)
	}
	if cfg.Window != time.Minute {
		t.Fatalf("unexpected window: %v", cfg.Window)
	}
}

func TestRateLimitConfigFromEnvOverrides(t *testing.T) {
	t.Setenv("LICENSE_SERVER_RATE_LIMIT_DEFAULT", "10")
	t.Setenv("LICENSE_SERVER_RATE_LIMIT_ADMIN", "20")
	t.Setenv("LICENSE_SERVER_RATE_LIMIT_ACTIVATION", "3")
	t.Setenv("LICENSE_SERVER_RATE_LIMIT_VERIFICATION", "4")
	t.Setenv("LICENSE_SERVER_RATE_LIMIT_CLIENT_AUTH", "5")
	t.Setenv("LICENSE_SERVER_RATE_LIMIT_WINDOW", "2m")

	cfg, err := RateLimitConfigFromEnv()
	if err != nil {
		t.Fatalf("RateLimitConfigFromEnv failed: %v", err)
	}
	if cfg.DefaultLimit != 10 || cfg.AdminLimit != 20 || cfg.ActivationLimit != 3 || cfg.VerificationLimit != 4 || cfg.ClientAuthLimit != 5 {
		t.Fatalf("unexpected overrides: %+v", cfg)
	}
	if cfg.Window != 2*time.Minute {
		t.Fatalf("unexpected window: %v", cfg.Window)
	}
}

func TestRateLimitConfigFromEnvRejectsInvalid(t *testing.T) {
	t.Setenv("LICENSE_SERVER_RATE_LIMIT_DEFAULT", "0")
	if _, err := RateLimitConfigFromEnv(); err == nil {
		t.Fatalf("expected invalid zero limit to fail")
	}
}
