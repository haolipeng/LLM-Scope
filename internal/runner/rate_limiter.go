package runner

import "sync"

const maxDistinctFilesPerSec = 30

type pidLimit struct {
	currentSecond     uint64
	distinctFileCount uint32
	shouldWarnNext    bool
}

// RateLimiter limits the number of distinct file events per PID per second.
type RateLimiter struct {
	mu     sync.Mutex
	limits map[int32]*pidLimit
}

// NewRateLimiter creates a new per-PID rate limiter.
func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits: make(map[int32]*pidLimit),
	}
}

// RateLimitResult contains the result of a rate limit check.
type RateLimitResult struct {
	ShouldDrop bool // true if event should be dropped
	AddWarning bool // true if a warning message should be added
}

// Check checks if a file event for the given PID should be rate-limited.
func (r *RateLimiter) Check(pid int32, timestampNs uint64) RateLimitResult {
	r.mu.Lock()
	defer r.mu.Unlock()

	currentSecond := timestampNs / 1_000_000_000

	limit, ok := r.limits[pid]
	if !ok {
		limit = &pidLimit{}
		r.limits[pid] = limit
	}

	result := RateLimitResult{}

	// New second - reset counter
	if limit.currentSecond != currentSecond {
		if limit.shouldWarnNext {
			result.AddWarning = true
			limit.shouldWarnNext = false
		}
		limit.currentSecond = currentSecond
		limit.distinctFileCount = 0
	}

	limit.distinctFileCount++

	if limit.distinctFileCount > maxDistinctFilesPerSec {
		limit.shouldWarnNext = true
		result.ShouldDrop = true
	}

	return result
}

// FlushPID removes rate limit state for a PID and returns whether a warning should be emitted.
func (r *RateLimiter) FlushPID(pid int32) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	limit, ok := r.limits[pid]
	if ok {
		warn := limit.shouldWarnNext
		delete(r.limits, pid)
		return warn
	}
	return false
}
