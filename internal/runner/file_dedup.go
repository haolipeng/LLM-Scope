package runner

import (
	"hash/fnv"
	"sync"
	"time"
)

const (
	fileDedupWindowNs = 60_000_000_000 // 60 seconds in nanoseconds
	maxFileHashes     = 1024
)

type fileHashEntry struct {
	hash        uint64
	timestampNs uint64
	count       uint32
	pid         int32
	comm        string
	filepath    string
	flags       int32
}

// FileDedup deduplicates FILE_OPEN events within a 60-second window.
type FileDedup struct {
	mu      sync.Mutex
	entries []fileHashEntry
}

// NewFileDedup creates a new file deduplication tracker.
func NewFileDedup() *FileDedup {
	return &FileDedup{
		entries: make([]fileHashEntry, 0, 64),
	}
}

// hashFileOpen computes a hash for a FILE_OPEN event based on PID + filepath.
func hashFileOpen(pid int32, filepath string) uint64 {
	h := fnv.New64a()
	b := make([]byte, 4)
	b[0] = byte(pid)
	b[1] = byte(pid >> 8)
	b[2] = byte(pid >> 16)
	b[3] = byte(pid >> 24)
	h.Write(b)
	h.Write([]byte(filepath))
	return h.Sum64()
}

// DedupResult is returned from CheckFileOpen.
type DedupResult struct {
	ShouldEmit bool   // true if this event should be emitted (first occurrence)
	Count      uint32 // count value to use (1 for new events)
	// Expired entries that need to be flushed
	Expired []ExpiredEntry
}

// ExpiredEntry represents a dedup entry that expired and should be flushed.
type ExpiredEntry struct {
	PID      int32
	Comm     string
	Filepath string
	Flags    int32
	Count    uint32
}

// CheckFileOpen checks a FILE_OPEN event for deduplication.
// Returns whether this event should be emitted and any expired aggregations.
func (d *FileDedup) CheckFileOpen(pid int32, filepath string, flags int32, comm string, timestampNs uint64) DedupResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := DedupResult{}

	// Clean up expired entries
	now := timestampNs
	if now == 0 {
		now = uint64(time.Now().UnixNano())
	}
	for i := 0; i < len(d.entries); {
		if now-d.entries[i].timestampNs > fileDedupWindowNs {
			if d.entries[i].count > 1 {
				result.Expired = append(result.Expired, ExpiredEntry{
					PID:      d.entries[i].pid,
					Comm:     d.entries[i].comm,
					Filepath: d.entries[i].filepath,
					Flags:    d.entries[i].flags,
					Count:    d.entries[i].count,
				})
			}
			d.entries[i] = d.entries[len(d.entries)-1]
			d.entries = d.entries[:len(d.entries)-1]
		} else {
			i++
		}
	}

	hash := hashFileOpen(pid, filepath)

	// Check for existing entry
	for i := range d.entries {
		if d.entries[i].hash == hash {
			d.entries[i].count++
			d.entries[i].timestampNs = timestampNs
			return result // ShouldEmit=false, duplicate
		}
	}

	// New entry
	if len(d.entries) < maxFileHashes {
		d.entries = append(d.entries, fileHashEntry{
			hash:        hash,
			timestampNs: timestampNs,
			count:       1,
			pid:         pid,
			comm:        comm,
			filepath:    filepath,
			flags:       flags,
		})
	}
	result.ShouldEmit = true
	result.Count = 1
	return result
}

// FlushPID flushes all pending aggregations for a specific PID (called on process exit).
func (d *FileDedup) FlushPID(pid int32) []ExpiredEntry {
	d.mu.Lock()
	defer d.mu.Unlock()

	var flushed []ExpiredEntry
	for i := 0; i < len(d.entries); {
		if d.entries[i].pid == pid {
			if d.entries[i].count > 1 {
				flushed = append(flushed, ExpiredEntry{
					PID:      d.entries[i].pid,
					Comm:     d.entries[i].comm,
					Filepath: d.entries[i].filepath,
					Flags:    d.entries[i].flags,
					Count:    d.entries[i].count,
				})
			}
			d.entries[i] = d.entries[len(d.entries)-1]
			d.entries = d.entries[:len(d.entries)-1]
		} else {
			i++
		}
	}
	return flushed
}
