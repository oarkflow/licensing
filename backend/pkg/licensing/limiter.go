package licensing

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu           sync.Mutex
	requests     map[string]*clientRequestWindow
	maxRequests  int
	adminMaxReqs int // Higher limit for admin sessions
	window       time.Duration
}

type clientRequestWindow struct {
	count   int
	resetAt time.Time
}

func NewRateLimiter(maxRequests int, window time.Duration) *RateLimiter {
	if maxRequests <= 0 {
		maxRequests = 60
	}
	if window <= 0 {
		window = time.Minute
	}
	return &RateLimiter{
		requests:     make(map[string]*clientRequestWindow),
		maxRequests:  maxRequests,
		adminMaxReqs: maxRequests * 10, // Admin UI gets 10x the limit
		window:       window,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	return rl.AllowWithLimit(key, rl.maxRequests)
}

// AllowAdmin allows requests with higher limits for authenticated admin sessions
func (rl *RateLimiter) AllowAdmin(key string) bool {
	return rl.AllowWithLimit(key, rl.adminMaxReqs)
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
