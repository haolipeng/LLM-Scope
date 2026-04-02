package process

import "sync"

const maxDistinctFilesPerSec = 30

type pidLimit struct {
	currentSecond     uint64
	distinctFileCount uint32
	shouldWarnNext    bool
}

type RateLimiter struct {
	mu     sync.Mutex
	limits map[int32]*pidLimit
}

func NewRateLimiter() *RateLimiter {
	return &RateLimiter{
		limits: make(map[int32]*pidLimit),
	}
}

type RateLimitResult struct {
	ShouldDrop bool
	AddWarning bool
}

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
