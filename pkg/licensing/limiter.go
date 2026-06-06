package licensing

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type RateLimiter struct {
	mu                  sync.Mutex
	requests            map[string]*clientRequestWindow
	maxRequests         int
	adminMaxReqs        int // Higher limit for admin sessions
	activationMaxReqs   int
	verificationMaxReqs int
	clientAuthMaxReqs   int
	window              time.Duration
}

type clientRequestWindow struct {
	count   int
	resetAt time.Time
}

func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	return NewRateLimiterWithConfig(RateLimitConfig{
		DefaultLimit: maxRequests,
		Window:       window,
	})
}

type RateLimitConfig struct {
	DefaultLimit      int
	AdminLimit        int
	ActivationLimit   int
	VerificationLimit int
	ClientAuthLimit   int
	Window            time.Duration
}

func NewRateLimiterWithConfig(cfg RateLimitConfig) *RateLimiter {
	maxRequests := cfg.DefaultLimit
	if maxRequests <= 0 {
		maxRequests = 60
	}
	adminMaxReqs := cfg.AdminLimit
	if adminMaxReqs <= 0 {
		adminMaxReqs = maxRequests * 10
	}
	activationMaxReqs := cfg.ActivationLimit
	if activationMaxReqs <= 0 {
		activationMaxReqs = maxRequests
	}
	verificationMaxReqs := cfg.VerificationLimit
	if verificationMaxReqs <= 0 {
		verificationMaxReqs = maxRequests
	}
	clientAuthMaxReqs := cfg.ClientAuthLimit
	if clientAuthMaxReqs <= 0 {
		clientAuthMaxReqs = maxRequests
	}
	window := cfg.Window
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{
		requests:            make(map[string]*clientRequestWindow),
		maxRequests:         maxRequests,
		adminMaxReqs:        adminMaxReqs,
		activationMaxReqs:   activationMaxReqs,
		verificationMaxReqs: verificationMaxReqs,
		clientAuthMaxReqs:   clientAuthMaxReqs,
		window:              window,
	}
}

func RateLimitConfigFromEnv() (RateLimitConfig, error) {
	cfg := RateLimitConfig{
		DefaultLimit:      30,
		AdminLimit:        300,
		ActivationLimit:   30,
		VerificationLimit: 60,
		ClientAuthLimit:   30,
		Window:            time.Minute,
	}
	var err error
	if cfg.DefaultLimit, err = envIntDefault("LICENSE_SERVER_RATE_LIMIT_DEFAULT", cfg.DefaultLimit); err != nil {
		return cfg, err
	}
	if cfg.AdminLimit, err = envIntDefault("LICENSE_SERVER_RATE_LIMIT_ADMIN", cfg.AdminLimit); err != nil {
		return cfg, err
	}
	if cfg.ActivationLimit, err = envIntDefault("LICENSE_SERVER_RATE_LIMIT_ACTIVATION", cfg.ActivationLimit); err != nil {
		return cfg, err
	}
	if cfg.VerificationLimit, err = envIntDefault("LICENSE_SERVER_RATE_LIMIT_VERIFICATION", cfg.VerificationLimit); err != nil {
		return cfg, err
	}
	if cfg.ClientAuthLimit, err = envIntDefault("LICENSE_SERVER_RATE_LIMIT_CLIENT_AUTH", cfg.ClientAuthLimit); err != nil {
		return cfg, err
	}
	if raw := strings.TrimSpace(os.Getenv("LICENSE_SERVER_RATE_LIMIT_WINDOW")); raw != "" {
		parsed, parseErr := time.ParseDuration(raw)
		if parseErr != nil || parsed <= 0 {
			if parseErr == nil {
				parseErr = fmt.Errorf("must be greater than zero")
			}
			return cfg, fmt.Errorf("invalid LICENSE_SERVER_RATE_LIMIT_WINDOW: %w", parseErr)
		}
		cfg.Window = parsed
	}
	return cfg, nil
}

func envIntDefault(key string, fallback int) (int, error) {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed <= 0 {
		if err == nil {
			err = fmt.Errorf("must be greater than zero")
		}
		return fallback, fmt.Errorf("invalid %s: %w", key, err)
	}
	return parsed, nil
}

func (rl *RateLimiter) Allow(key string) bool {
	return rl.AllowWithLimit(key, rl.maxRequests)
}

// AllowAdmin allows requests with higher limits for authenticated admin sessions
func (rl *RateLimiter) AllowAdmin(key string) bool {
	return rl.AllowWithLimit(key, rl.adminMaxReqs)
}

func (rl *RateLimiter) AllowActivation(key string) bool {
	return rl.AllowWithLimit(key, rl.activationMaxReqs)
}

func (rl *RateLimiter) AllowVerification(key string) bool {
	return rl.AllowWithLimit(key, rl.verificationMaxReqs)
}

func (rl *RateLimiter) AllowClientAuth(key string) bool {
	return rl.AllowWithLimit(key, rl.clientAuthMaxReqs)
}

func (rl *RateLimiter) AllowWithLimit(key string, limit int) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window, exists := rl.requests[key]
	if !exists || now.After(window.resetAt) {
		rl.requests[key] = &clientRequestWindow{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	if window.count >= limit {
		return false
	}

	window.count++
	return true
}
