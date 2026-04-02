package process

import (
	"hash/fnv"
	"sync"
	"time"
)

const (
	fileDedupWindowNs = 60_000_000_000
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

type FileDedup struct {
	mu      sync.Mutex
	entries []fileHashEntry
}

func NewFileDedup() *FileDedup {
	return &FileDedup{
		entries: make([]fileHashEntry, 0, 64),
	}
}

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

type DedupResult struct {
	ShouldEmit bool
	Count      uint32
	Expired    []ExpiredEntry
}

type ExpiredEntry struct {
	PID      int32
	Comm     string
	Filepath string
	Flags    int32
	Count    uint32
}

func (d *FileDedup) CheckFileOpen(pid int32, filepath string, flags int32, comm string, timestampNs uint64) DedupResult {
	d.mu.Lock()
	defer d.mu.Unlock()

	result := DedupResult{}
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
	for i := range d.entries {
		if d.entries[i].hash == hash {
			d.entries[i].count++
			d.entries[i].timestampNs = timestampNs
			return result
		}
	}

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
