package licensing

import (
	"sync"
	"time"
)

type RateLimiter struct {
	mu          sync.Mutex
	requests    map[string]*clientRequestWindow
	maxRequests int
	window      time.Duration
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
		requests:    make(map[string]*clientRequestWindow),
		maxRequests: maxRequests,
		window:      window,
	}
}

func (rl *RateLimiter) Allow(key string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	window, exists := rl.requests[key]
	if !exists || now.After(window.resetAt) {
		rl.requests[key] = &clientRequestWindow{count: 1, resetAt: now.Add(rl.window)}
		return true
	}

	if window.count >= rl.maxRequests {
		return false
	}

	window.count++
	return true
}
