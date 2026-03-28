package runner

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// FilterMode determines how processes are filtered.
const (
	FilterModeAll    = 0 // Trace all processes and all file operations
	FilterModeProc   = 1 // Trace all processes but only file ops for tracked PIDs
	FilterModeFilter = 2 // Only trace processes matching filters
)

// PIDTracker tracks PIDs for userspace process filtering.
type PIDTracker struct {
	mu              sync.RWMutex
	tracked         map[int32]int32 // pid -> ppid
	commandFilters  []string
	filterMode      int
	targetPID       int32
}

// NewPIDTracker creates a new PID tracker.
func NewPIDTracker(commandFilters []string, filterMode int, targetPID int32) *PIDTracker {
	return &PIDTracker{
		tracked:        make(map[int32]int32),
		commandFilters: commandFilters,
		filterMode:     filterMode,
		targetPID:      targetPID,
	}
}

// Add adds a PID to the tracker. Returns true if added (or already existed).
func (t *PIDTracker) Add(pid, ppid int32) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked[pid] = ppid
	return true
}

// Remove removes a PID from the tracker.
func (t *PIDTracker) Remove(pid int32) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.tracked, pid)
}

// IsTracked checks if a PID is tracked.
func (t *PIDTracker) IsTracked(pid int32) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	_, ok := t.tracked[pid]
	return ok
}

// ShouldTrackProcess determines if a process should be tracked based on filter mode.
func (t *PIDTracker) ShouldTrackProcess(comm string, pid, ppid int32) bool {
	switch t.filterMode {
	case FilterModeAll, FilterModeProc:
		return true
	case FilterModeFilter:
		if t.targetPID > 0 && pid == t.targetPID {
			return true
		}
		t.mu.RLock()
		_, parentTracked := t.tracked[ppid]
		t.mu.RUnlock()
		if parentTracked {
			return true
		}
		if len(t.commandFilters) > 0 {
			for _, filter := range t.commandFilters {
				if comm == filter {
					return true
				}
			}
		}
		return false
	}
	return false
}

// ShouldReportFileOps determines if file operations should be reported for a PID.
func (t *PIDTracker) ShouldReportFileOps(pid int32) bool {
	if t.filterMode == FilterModeAll {
		return true
	}
	return t.IsTracked(pid)
}

// ShouldReportBashReadline determines if bash readline should be reported for a PID.
func (t *PIDTracker) ShouldReportBashReadline(pid int32) bool {
	if t.filterMode == FilterModeFilter {
		return t.IsTracked(pid)
	}
	return true
}

// PopulateFromProc scans /proc to find existing processes matching filters.
func (t *PIDTracker) PopulateFromProc() int {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}

	count := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		pid, err := strconv.ParseInt(entry.Name(), 10, 32)
		if err != nil || pid <= 0 {
			continue
		}

		comm := readProcComm(int32(pid))
		if comm == "" {
			continue
		}
		ppid := readProcPPID(int32(pid))

		if t.ShouldTrackProcess(comm, int32(pid), ppid) {
			t.Add(int32(pid), ppid)
			count++
		}
	}
	return count
}

// readProcComm reads a process's comm from /proc/PID/comm.
func readProcComm(pid int32) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "comm"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

// readProcPPID reads a process's parent PID from /proc/PID/stat.
func readProcPPID(pid int32) int32 {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(int(pid)), "stat"))
	if err != nil {
		return 0
	}
	// Format: pid (comm) state ppid ...
	// Find the closing ')' to handle comm with spaces
	line := string(data)
	idx := strings.LastIndex(line, ")")
	if idx < 0 || idx+2 >= len(line) {
		return 0
	}
	fields := strings.Fields(line[idx+2:])
	if len(fields) < 2 {
		return 0
	}
	ppid, err := strconv.ParseInt(fields[1], 10, 32)
	if err != nil {
		return 0
	}
	return int32(ppid)
}
