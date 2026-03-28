package runner

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfprocess "github.com/haolipeng/LLM-Scope/internal/bpf/process"
	"github.com/haolipeng/LLM-Scope/internal/core"
)

// Event type constants matching C enum event_type in process.h.
const (
	eventTypeProcess      = 0
	eventTypeBashReadline = 1
	eventTypeFileOp       = 2
	eventTypeCredChange   = 3
	eventTypeNetConnect   = 4
	eventTypeFileRename   = 5
	eventTypeDirCreate    = 6
)

// File operation type constants matching C enum file_op_type.
const (
	fileOpOpen   = 0
	fileOpDelete = 2
)

// Raw event field offsets for struct event on x86_64 (little-endian).
// struct event {
//   enum event_type type;         // offset 0,   4 bytes
//   int pid;                      // offset 4,   4 bytes
//   int ppid;                     // offset 8,   4 bytes
//   unsigned exit_code;           // offset 12,  4 bytes
//   unsigned long long duration;  // offset 16,  8 bytes
//   unsigned long long timestamp; // offset 24,  8 bytes
//   char comm[16];                // offset 32,  16 bytes
//   char full_command[256];       // offset 48,  256 bytes
//   union { ... };                // offset 304, 256 bytes
//   bool exit_event;              // offset 560, 1 byte + 7 padding
// };
const (
	offType        = 0
	offPid         = 4
	offPpid        = 8
	offExitCode    = 12
	offDurationNs  = 16
	offTimestampNs = 24
	offComm        = 32
	commLen        = 16
	offFullCommand = 48
	fullCommandLen = 256
	offUnion       = 304
	unionLen       = 256
	offExitEvent   = 560
	minEventSize   = 561
)

// Union sub-offsets for file_op.
const (
	fileOpFilepathLen = 127
	fileOpFdOff       = 128
	fileOpFlagsOff    = 132
	fileOpTypeOff     = 136
)

// Union sub-offsets for net_connect.
const (
	netFamilyOff = 0
	netPortOff   = 2
	netAddrOff   = 4
)

// Union sub-offsets for file_rename.
const (
	renameOldpathLen = 127
	renameNewpathOff = 127
)

// Union sub-offsets for dir_create.
const (
	dirPathLen = 127
	dirModeOff = 128
)

// ProcessConfig configures the process runner.
type ProcessConfig struct {
	MinDurationMs int64
	Commands      []string
	PID           int
	FilterMode    int // 0=all, 1=proc, 2=filter
}

// ProcessRunner loads BPF programs and reads events from ring buffer directly.
type ProcessRunner struct {
	config      ProcessConfig
	objs        bpfprocess.Objects
	links       []link.Link
	reader      *ringbuf.Reader
	tracker     *PIDTracker
	dedup       *FileDedup
	rateLimiter *RateLimiter
}

func NewProcessRunner(config ProcessConfig) *ProcessRunner {
	return &ProcessRunner{
		config:      config,
		dedup:       NewFileDedup(),
		rateLimiter: NewRateLimiter(),
	}
}

func (r *ProcessRunner) ID() string   { return "process" }
func (r *ProcessRunner) Name() string { return "process" }

func (r *ProcessRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[Process] warning: remove memlock: %v", err)
	}

	// Initialize PID tracker
	commands := r.config.Commands
	filterMode := r.config.FilterMode
	if len(commands) > 0 && filterMode == 0 {
		filterMode = FilterModeFilter
	}
	if r.config.PID > 0 && filterMode == 0 {
		filterMode = FilterModeFilter
	}
	r.tracker = NewPIDTracker(commands, filterMode, int32(r.config.PID))

	// Load BPF spec
	spec, err := bpfprocess.LoadSpec()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	// Set min_duration_ns constant
	if r.config.MinDurationMs > 0 {
		if err := spec.Variables["min_duration_ns"].Set(uint64(r.config.MinDurationMs) * 1_000_000); err != nil {
			return nil, fmt.Errorf("set min_duration_ns: %w", err)
		}
	}

	// Load BPF objects into kernel
	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	// Attach probes
	if err := r.attachProbes(); err != nil {
		r.objs.Close()
		return nil, fmt.Errorf("attach probes: %w", err)
	}

	// Populate initial PIDs from /proc
	tracked := r.tracker.PopulateFromProc()
	log.Printf("[Process] initial tracked PIDs: %d, filter_mode=%d", tracked, filterMode)

	// Create ring buffer reader
	r.reader, err = ringbuf.NewReader(r.objs.Rb)
	if err != nil {
		r.closeLinks()
		r.objs.Close()
		return nil, fmt.Errorf("create ringbuf reader: %w", err)
	}

	out := make(chan *core.Event, 100)
	go r.readLoop(ctx, out)

	return out, nil
}

func (r *ProcessRunner) attachProbes() error {
	attach := func(group, name string, prog *ebpf.Program) {
		l, err := link.Tracepoint(group, name, prog, nil)
		if err != nil {
			log.Printf("[Process] warning: tracepoint %s/%s: %v", group, name, err)
			return
		}
		r.links = append(r.links, l)
	}

	// Tracepoints
	attach("sched", "sched_process_exec", r.objs.HandleExec)
	attach("sched", "sched_process_exit", r.objs.HandleExit)
	attach("syscalls", "sys_enter_openat", r.objs.TraceOpenat)
	attach("syscalls", "sys_enter_open", r.objs.TraceOpen)
	attach("syscalls", "sys_enter_unlink", r.objs.TraceUnlink)
	attach("syscalls", "sys_enter_unlinkat", r.objs.TraceUnlinkat)
	attach("syscalls", "sys_enter_connect", r.objs.TraceConnect)
	attach("syscalls", "sys_enter_rename", r.objs.TraceRename)
	attach("syscalls", "sys_enter_renameat", r.objs.TraceRenameat)
	attach("syscalls", "sys_enter_renameat2", r.objs.TraceRenameat2)
	attach("syscalls", "sys_enter_mkdir", r.objs.TraceMkdir)
	attach("syscalls", "sys_enter_mkdirat", r.objs.TraceMkdirat)

	// Kprobe: commit_creds
	kp, err := link.Kprobe("commit_creds", r.objs.TraceCommitCreds, nil)
	if err != nil {
		log.Printf("[Process] warning: kprobe commit_creds: %v", err)
	} else {
		r.links = append(r.links, kp)
	}

	// Uretprobe: bash readline (optional, failure is just a warning)
	exe, err := link.OpenExecutable("/usr/bin/bash")
	if err != nil {
		log.Printf("[Process] warning: cannot open /usr/bin/bash for uretprobe: %v", err)
	} else {
		up, err := exe.Uretprobe("readline", r.objs.BashReadline, nil)
		if err != nil {
			log.Printf("[Process] warning: attach bash readline uretprobe: %v", err)
		} else {
			r.links = append(r.links, up)
		}
	}

	return nil
}

func (r *ProcessRunner) readLoop(ctx context.Context, out chan<- *core.Event) {
	defer close(out)
	defer r.reader.Close()

	for {
		record, err := r.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("[Process] ringbuf read error: %v", err)
			continue
		}

		raw := record.RawSample
		if len(raw) < minEventSize {
			continue
		}

		events := r.handleRawEvent(raw)
		for _, event := range events {
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (r *ProcessRunner) handleRawEvent(raw []byte) []*core.Event {
	le := binary.LittleEndian

	eventType := le.Uint32(raw[offType:])
	pid := int32(le.Uint32(raw[offPid:]))
	ppid := int32(le.Uint32(raw[offPpid:]))
	exitCode := le.Uint32(raw[offExitCode:])
	durationNs := le.Uint64(raw[offDurationNs:])
	timestampNs := le.Uint64(raw[offTimestampNs:])
	comm := cStringFromBytes(raw[offComm : offComm+commLen])
	fullCommand := cStringFromBytes(raw[offFullCommand : offFullCommand+fullCommandLen])
	exitEvent := raw[offExitEvent] != 0
	unionData := raw[offUnion : offUnion+unionLen]

	var result []*core.Event

	switch eventType {
	case eventTypeProcess:
		result = r.handleProcessEvent(pid, ppid, exitCode, durationNs, timestampNs, comm, fullCommand, exitEvent, unionData)
	case eventTypeBashReadline:
		result = r.handleBashReadline(pid, timestampNs, comm, unionData)
	case eventTypeFileOp:
		result = r.handleFileOp(pid, timestampNs, comm, unionData)
	case eventTypeCredChange:
		result = r.handleCredChange(pid, ppid, timestampNs, comm, unionData)
	case eventTypeNetConnect:
		result = r.handleNetConnect(pid, timestampNs, comm, unionData)
	case eventTypeFileRename:
		result = r.handleFileRename(pid, timestampNs, comm, unionData)
	case eventTypeDirCreate:
		result = r.handleDirCreate(pid, timestampNs, comm, unionData)
	}

	return result
}

func (r *ProcessRunner) handleProcessEvent(pid, ppid int32, exitCode uint32, durationNs, timestampNs uint64, comm, fullCommand string, exitEvent bool, unionData []byte) []*core.Event {
	var events []*core.Event

	if exitEvent {
		isTracked := r.tracker.IsTracked(pid)
		r.tracker.Remove(pid)

		if !isTracked && r.tracker.filterMode == FilterModeFilter {
			return nil
		}

		data := map[string]interface{}{
			"timestamp": timestampNs,
			"event":     "EXIT",
			"comm":      comm,
			"pid":       pid,
			"ppid":      ppid,
			"exit_code": exitCode,
		}
		if durationNs > 0 {
			data["duration_ms"] = durationNs / 1_000_000
		}

		// Check for pending rate limit warning
		if r.rateLimiter.FlushPID(pid) {
			data["rate_limit_warning"] = fmt.Sprintf("Process had %d+ file ops per second", maxDistinctFilesPerSec)
		}

		events = append(events, r.makeEvent(timestampNs, pid, comm, data))

		// Flush pending FILE_OPEN aggregations
		for _, expired := range r.dedup.FlushPID(pid) {
			expData := map[string]interface{}{
				"timestamp": timestampNs,
				"event":     "FILE_OPEN",
				"comm":      expired.Comm,
				"pid":       expired.PID,
				"count":     expired.Count,
				"filepath":  expired.Filepath,
				"flags":     expired.Flags,
				"reason":    "process_exit",
			}
			events = append(events, r.makeEvent(timestampNs, expired.PID, expired.Comm, expData))
		}
	} else {
		filename := cStringFromBytes(unionData[:fileOpFilepathLen])

		if r.tracker.ShouldTrackProcess(comm, pid, ppid) {
			r.tracker.Add(pid, ppid)

			data := map[string]interface{}{
				"timestamp":    timestampNs,
				"event":        "EXEC",
				"comm":         comm,
				"pid":          pid,
				"ppid":         ppid,
				"filename":     filename,
				"full_command": fullCommand,
			}
			events = append(events, r.makeEvent(timestampNs, pid, comm, data))
		} else if r.tracker.filterMode == FilterModeFilter {
			return nil
		} else {
			if r.tracker.filterMode == FilterModeProc {
				r.tracker.Add(pid, ppid)
			}
			data := map[string]interface{}{
				"timestamp":    timestampNs,
				"event":        "EXEC",
				"comm":         comm,
				"pid":          pid,
				"ppid":         ppid,
				"filename":     filename,
				"full_command": fullCommand,
			}
			events = append(events, r.makeEvent(timestampNs, pid, comm, data))
		}
	}

	return events
}

func (r *ProcessRunner) handleBashReadline(pid int32, timestampNs uint64, comm string, unionData []byte) []*core.Event {
	if !r.tracker.ShouldReportBashReadline(pid) {
		return nil
	}
	command := cStringFromBytes(unionData[:fullCommandLen])
	data := map[string]interface{}{
		"timestamp": timestampNs,
		"event":     "BASH_READLINE",
		"comm":      comm,
		"pid":       pid,
		"command":   command,
	}
	return []*core.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

func (r *ProcessRunner) handleFileOp(pid int32, timestampNs uint64, comm string, unionData []byte) []*core.Event {
	if !r.tracker.ShouldReportFileOps(pid) {
		return nil
	}

	le := binary.LittleEndian
	filepath := cStringFromBytes(unionData[:fileOpFilepathLen])
	flags := int32(le.Uint32(unionData[fileOpFlagsOff:]))
	opType := le.Uint32(unionData[fileOpTypeOff:])

	var events []*core.Event

	switch opType {
	case fileOpOpen:
		// Rate limiting
		rl := r.rateLimiter.Check(pid, timestampNs)
		if rl.ShouldDrop {
			return nil
		}

		// Deduplication
		dedupResult := r.dedup.CheckFileOpen(pid, filepath, flags, comm, timestampNs)

		// Flush expired aggregations
		for _, expired := range dedupResult.Expired {
			expData := map[string]interface{}{
				"timestamp":      timestampNs,
				"event":          "FILE_OPEN",
				"comm":           expired.Comm,
				"pid":            expired.PID,
				"count":          expired.Count,
				"filepath":       expired.Filepath,
				"flags":          expired.Flags,
				"window_expired": true,
			}
			events = append(events, r.makeEvent(timestampNs, expired.PID, expired.Comm, expData))
		}

		if !dedupResult.ShouldEmit {
			return events
		}

		data := map[string]interface{}{
			"timestamp": timestampNs,
			"event":     "FILE_OPEN",
			"comm":      comm,
			"pid":       pid,
			"count":     dedupResult.Count,
			"filepath":  filepath,
			"flags":     flags,
		}
		if rl.AddWarning {
			data["rate_limit_warning"] = fmt.Sprintf("Previous second exceeded %d file limit", maxDistinctFilesPerSec)
		}
		events = append(events, r.makeEvent(timestampNs, pid, comm, data))

	case fileOpDelete:
		data := map[string]interface{}{
			"timestamp": timestampNs,
			"event":     "FILE_DELETE",
			"comm":      comm,
			"pid":       pid,
			"filepath":  filepath,
			"flags":     flags,
		}
		events = append(events, r.makeEvent(timestampNs, pid, comm, data))
	}

	return events
}

func (r *ProcessRunner) handleCredChange(pid, ppid int32, timestampNs uint64, comm string, unionData []byte) []*core.Event {
	if !r.tracker.ShouldReportFileOps(pid) {
		return nil
	}

	le := binary.LittleEndian
	parseSlimCred := func(data []byte) map[string]interface{} {
		return map[string]interface{}{
			"uid":              le.Uint32(data[0:]),
			"gid":              le.Uint32(data[4:]),
			"suid":             le.Uint32(data[8:]),
			"sgid":             le.Uint32(data[12:]),
			"euid":             le.Uint32(data[16:]),
			"egid":             le.Uint32(data[20:]),
			"fsuid":            le.Uint32(data[24:]),
			"fsgid":            le.Uint32(data[28:]),
			"cap_inheritable":  le.Uint64(data[32:]),
			"cap_permitted":    le.Uint64(data[40:]),
			"cap_effective":    le.Uint64(data[48:]),
			"cap_bset":         le.Uint64(data[56:]),
			"cap_ambient":      le.Uint64(data[64:]),
		}
	}

	// slim_cred size = 8*4 + 5*8 = 72 bytes
	const slimCredSize = 72
	oldCred := parseSlimCred(unionData[0:slimCredSize])
	newCred := parseSlimCred(unionData[slimCredSize : slimCredSize*2])

	data := map[string]interface{}{
		"timestamp": timestampNs,
		"event":     "CRED_CHANGE",
		"comm":      comm,
		"pid":       pid,
		"ppid":      ppid,
		"old":       oldCred,
		"new":       newCred,
	}
	return []*core.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

func (r *ProcessRunner) handleNetConnect(pid int32, timestampNs uint64, comm string, unionData []byte) []*core.Event {
	if !r.tracker.ShouldReportFileOps(pid) {
		return nil
	}

	le := binary.LittleEndian
	family := le.Uint16(unionData[netFamilyOff:])
	port := le.Uint16(unionData[netPortOff:])

	data := map[string]interface{}{
		"timestamp": timestampNs,
		"event":     "NET_CONNECT",
		"comm":      comm,
		"pid":       pid,
		"family":    family,
		"port":      port,
	}

	if family == 2 { // AF_INET
		ip := le.Uint32(unionData[netAddrOff:])
		data["ip"] = ipv4ToString(ip)
	} else if family == 10 { // AF_INET6
		var ipv6 [16]byte
		copy(ipv6[:], unionData[netAddrOff:netAddrOff+16])
		data["ip"] = net.IP(ipv6[:]).String()
	}

	return []*core.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

func (r *ProcessRunner) handleFileRename(pid int32, timestampNs uint64, comm string, unionData []byte) []*core.Event {
	if !r.tracker.ShouldReportFileOps(pid) {
		return nil
	}

	oldpath := cStringFromBytes(unionData[:renameOldpathLen])
	newpath := cStringFromBytes(unionData[renameNewpathOff : renameNewpathOff+renameOldpathLen])

	data := map[string]interface{}{
		"timestamp": timestampNs,
		"event":     "FILE_RENAME",
		"comm":      comm,
		"pid":       pid,
		"oldpath":   oldpath,
		"newpath":   newpath,
	}
	return []*core.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

func (r *ProcessRunner) handleDirCreate(pid int32, timestampNs uint64, comm string, unionData []byte) []*core.Event {
	if !r.tracker.ShouldReportFileOps(pid) {
		return nil
	}

	le := binary.LittleEndian
	path := cStringFromBytes(unionData[:dirPathLen])
	mode := int32(le.Uint32(unionData[dirModeOff:]))

	data := map[string]interface{}{
		"timestamp": timestampNs,
		"event":     "DIR_CREATE",
		"comm":      comm,
		"pid":       pid,
		"path":      path,
		"mode":      mode,
	}
	return []*core.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

func (r *ProcessRunner) makeEvent(timestampNs uint64, pid int32, comm string, data map[string]interface{}) *core.Event {
	jsonData, _ := json.Marshal(data)
	return &core.Event{
		TimestampNs:     int64(timestampNs),
		TimestampUnixMs: core.BootNsToUnixMs(int64(timestampNs)),
		Source:          "process",
		PID:             uint32(pid),
		Comm:            comm,
		Data:            json.RawMessage(jsonData),
	}
}

// cStringFromBytes extracts a null-terminated C string from a byte slice.
func cStringFromBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return strings.TrimRight(string(b), "\x00")
}

func (r *ProcessRunner) Stop() error {
	if r.reader != nil {
		r.reader.Close()
	}
	r.closeLinks()
	r.objs.Close()
	return nil
}

func (r *ProcessRunner) closeLinks() {
	for _, l := range r.links {
		l.Close()
	}
	r.links = nil
}
