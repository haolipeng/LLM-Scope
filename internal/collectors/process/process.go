package process

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	bpfprocess "github.com/haolipeng/LLM-Scope/internal/bpf/process"
	runtimebase "github.com/haolipeng/LLM-Scope/internal/collectors/base"
	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/logging"
)

const (
	eventTypeProcess      = 0 //进程事件
	eventTypeBashReadline = 1 //bash操作事件
	eventTypeFileOp       = 2 //文件操作事件
	eventTypeCredChange   = 3 //凭证变更事件
	eventTypeNetConnect   = 4 //网络连接事件
	eventTypeFileRename   = 5 //文件重命名事件
	eventTypeDirCreate    = 6 //目录创建事件
)

const (
	fileOpOpen   = 0
	fileOpDelete = 2
)

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

const (
	fileOpFilepathLen = 127
	fileOpFdOff       = 128
	fileOpFlagsOff    = 132
	fileOpTypeOff     = 136
)

const (
	netFamilyOff = 0
	netPortOff   = 2
	netAddrOff   = 4
)

const (
	renameOldpathLen = 127
	renameNewpathOff = 127
)

const (
	dirPathLen = 127
	dirModeOff = 128
)

type Config struct {
	MinDurationMs int64
	Commands      []string
	PID           int
	FilterMode    int
}

type Runner struct {
	runtimebase.BaseRunner
	config      Config
	objs        bpfprocess.Objects
	tracker     *PIDTracker
	dedup       *FileDedup
	rateLimiter *RateLimiter
}

func New(config Config) *Runner {
	r := &Runner{
		config:      config,
		dedup:       NewFileDedup(),
		rateLimiter: NewRateLimiter(),
	}
	r.BaseRunner = runtimebase.BaseRunner{Label: "[Process]"}
	return r
}

func (r *Runner) ID() string   { return "process" }
func (r *Runner) Name() string { return "process" }

// Run 运行进程收集器
func (r *Runner) Run(ctx context.Context) (<-chan *event.Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Named("process").Warnf("remove memlock: %v", err)
	}

	commands := r.config.Commands
	filterMode := r.config.FilterMode
	if len(commands) > 0 && filterMode == 0 {
		filterMode = FilterModeFilter
	}
	if r.config.PID > 0 && filterMode == 0 {
		filterMode = FilterModeFilter
	}
	r.tracker = NewPIDTracker(commands, filterMode, int32(r.config.PID))

	spec, err := bpfprocess.LoadSpec()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	if r.config.MinDurationMs > 0 {
		if err := spec.Variables["min_duration_ns"].Set(uint64(r.config.MinDurationMs) * 1_000_000); err != nil {
			return nil, fmt.Errorf("set min_duration_ns: %w", err)
		}
	}

	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	r.Closer = &r.objs

	r.attachProbes()

	tracked := r.tracker.PopulateFromProc()
	logging.Named("process").Infof("initial tracked PIDs: %d, filter_mode=%d", tracked, filterMode)

	if err := r.InitRingBuffer(r.objs.Rb); err != nil {
		r.CloseLinks()
		r.objs.Close()
		return nil, err
	}

	out := make(chan *event.Event, 100)
	go r.ReadLoop(ctx, out, r.parseEvents)

	return out, nil
}

// attachProbes 挂载BPF探针
func (r *Runner) attachProbes() {
	r.AttachTracepoint("sched", "sched_process_exec", r.objs.HandleExec)
	r.AttachTracepoint("sched", "sched_process_exit", r.objs.HandleExit)
	r.AttachTracepoint("syscalls", "sys_enter_openat", r.objs.TraceOpenat)
	r.AttachTracepoint("syscalls", "sys_enter_open", r.objs.TraceOpen)
	r.AttachTracepoint("syscalls", "sys_enter_unlink", r.objs.TraceUnlink)
	r.AttachTracepoint("syscalls", "sys_enter_unlinkat", r.objs.TraceUnlinkat)
	r.AttachTracepoint("syscalls", "sys_enter_connect", r.objs.TraceConnect)
	r.AttachTracepoint("syscalls", "sys_enter_rename", r.objs.TraceRename)
	r.AttachTracepoint("syscalls", "sys_enter_renameat", r.objs.TraceRenameat)
	r.AttachTracepoint("syscalls", "sys_enter_renameat2", r.objs.TraceRenameat2)
	r.AttachTracepoint("syscalls", "sys_enter_mkdir", r.objs.TraceMkdir)
	r.AttachTracepoint("syscalls", "sys_enter_mkdirat", r.objs.TraceMkdirat)
	r.AttachKprobe("commit_creds", r.objs.TraceCommitCreds)

	exe, err := link.OpenExecutable("/usr/bin/bash")
	if err != nil {
		logging.Named("process").Warnf("cannot open /usr/bin/bash for uretprobe: %v", err)
	} else {
		r.AttachUretprobe(exe, "readline", r.objs.BashReadline)
	}
}

// parseEvents 解析事件
func (r *Runner) parseEvents(raw []byte) []*event.Event {
	if len(raw) < minEventSize {
		return nil
	}
	return r.handleRawEvent(raw)
}

// handleRawEvent 处理原始事件
func (r *Runner) handleRawEvent(raw []byte) []*event.Event {
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

	switch eventType {
	case eventTypeProcess:
		return r.handleProcessEvent(pid, ppid, exitCode, durationNs, timestampNs, comm, fullCommand, exitEvent, unionData)
	case eventTypeBashReadline:
		return r.handleBashReadline(pid, timestampNs, comm, unionData)
	case eventTypeFileOp:
		return r.handleFileOp(pid, timestampNs, comm, unionData)
	case eventTypeCredChange:
		return r.handleCredChange(pid, ppid, timestampNs, comm, unionData)
	case eventTypeNetConnect:
		return r.handleNetConnect(pid, timestampNs, comm, unionData)
	case eventTypeFileRename:
		return r.handleFileRename(pid, timestampNs, comm, unionData)
	case eventTypeDirCreate:
		return r.handleDirCreate(pid, timestampNs, comm, unionData)
	}

	return nil
}

// handleProcessEvent 处理进程事件
func (r *Runner) handleProcessEvent(pid, ppid int32, exitCode uint32, durationNs, timestampNs uint64, comm, fullCommand string, exitEvent bool, unionData []byte) []*event.Event {
	var events []*event.Event

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
		if r.rateLimiter.FlushPID(pid) {
			data["rate_limit_warning"] = fmt.Sprintf("Process had %d+ file ops per second", maxDistinctFilesPerSec)
		}
		events = append(events, r.makeEvent(timestampNs, pid, comm, data))
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
		shouldTrack := r.tracker.ShouldTrackProcess(comm, pid, ppid)
		if shouldTrack {
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

// handleBashReadline 处理bash读写事件
func (r *Runner) handleBashReadline(pid int32, timestampNs uint64, comm string, unionData []byte) []*event.Event {
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
	return []*event.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

// handleFileOp 处理文件操作事件
func (r *Runner) handleFileOp(pid int32, timestampNs uint64, comm string, unionData []byte) []*event.Event {
	if !r.tracker.ShouldReportFileOps(pid) {
		return nil
	}

	le := binary.LittleEndian
	filepath := cStringFromBytes(unionData[:fileOpFilepathLen])
	flags := int32(le.Uint32(unionData[fileOpFlagsOff:]))
	opType := le.Uint32(unionData[fileOpTypeOff:])

	if opType == fileOpOpen && isNoiseFilePath(filepath) {
		return nil
	}

	var events []*event.Event
	switch opType {
	case fileOpOpen:
		rl := r.rateLimiter.Check(pid, timestampNs)
		if rl.ShouldDrop {
			return nil
		}
		dedupResult := r.dedup.CheckFileOpen(pid, filepath, flags, comm, timestampNs)
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

// handleCredChange 处理凭证变更事件
func (r *Runner) handleCredChange(pid, ppid int32, timestampNs uint64, comm string, unionData []byte) []*event.Event {
	if !r.tracker.ShouldReportFileOps(pid) {
		return nil
	}

	le := binary.LittleEndian
	parseSlimCred := func(data []byte) map[string]interface{} {
		return map[string]interface{}{
			"uid":             le.Uint32(data[0:]),
			"gid":             le.Uint32(data[4:]),
			"suid":            le.Uint32(data[8:]),
			"sgid":            le.Uint32(data[12:]),
			"euid":            le.Uint32(data[16:]),
			"egid":            le.Uint32(data[20:]),
			"fsuid":           le.Uint32(data[24:]),
			"fsgid":           le.Uint32(data[28:]),
			"cap_inheritable": le.Uint64(data[32:]),
			"cap_permitted":   le.Uint64(data[40:]),
			"cap_effective":   le.Uint64(data[48:]),
			"cap_bset":        le.Uint64(data[56:]),
			"cap_ambient":     le.Uint64(data[64:]),
		}
	}

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
	return []*event.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

// handleNetConnect 处理网络连接事件
func (r *Runner) handleNetConnect(pid int32, timestampNs uint64, comm string, unionData []byte) []*event.Event {
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
	if family == 2 {
		ip := le.Uint32(unionData[netAddrOff:])
		data["ip"] = ipv4ToString(ip)
	} else if family == 10 {
		var ipv6 [16]byte
		copy(ipv6[:], unionData[netAddrOff:netAddrOff+16])
		data["ip"] = net.IP(ipv6[:]).String()
	}
	return []*event.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

// handleFileRename 处理文件重命名事件
func (r *Runner) handleFileRename(pid int32, timestampNs uint64, comm string, unionData []byte) []*event.Event {
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
	return []*event.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

// handleDirCreate 处理目录创建事件
func (r *Runner) handleDirCreate(pid int32, timestampNs uint64, comm string, unionData []byte) []*event.Event {
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
	return []*event.Event{r.makeEvent(timestampNs, pid, comm, data)}
}

// makeEvent 创建事件
func (r *Runner) makeEvent(timestampNs uint64, pid int32, comm string, data map[string]interface{}) *event.Event {
	jsonData, _ := json.Marshal(data)
	return &event.Event{
		TimestampNs:     int64(timestampNs),
		TimestampUnixMs: event.BootNsToUnixMs(int64(timestampNs)),
		Source:          "process",
		PID:             uint32(pid),
		Comm:            comm,
		Data:            json.RawMessage(jsonData),
	}
}

func cStringFromBytes(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return strings.TrimRight(string(b), "\x00")
}

func ipv4ToString(ip uint32) string {
	return net.IPv4(byte(ip), byte(ip>>8), byte(ip>>16), byte(ip>>24)).String()
}

// isNoiseFilePath 判断是否为噪声文件路径
func isNoiseFilePath(path string) bool {
	if strings.HasPrefix(path, "/proc/") {
		return true
	}
	if strings.HasPrefix(path, "/sys/") || strings.HasPrefix(path, "/dev/") {
		return true
	}
	if strings.HasPrefix(path, "/usr/lib/") ||
		strings.HasPrefix(path, "/lib/") ||
		strings.HasPrefix(path, "/usr/share/") {
		return true
	}
	if strings.HasPrefix(path, "/etc/") {
		// only filter linker cache; /etc/passwd, /etc/shadow etc. are security-sensitive
		return path == "/etc/ld.so.cache" || strings.HasPrefix(path, "/etc/ld.so")
	}
	if strings.HasSuffix(path, ".so") || strings.Contains(path, ".so.") {
		return true
	}
	if strings.Contains(path, ".cursor-server/") {
		return true
	}
	if strings.Contains(path, "/node_modules/") {
		return true
	}
	if strings.HasPrefix(path, ".git/objects/") || strings.Contains(path, "/.git/objects/") {
		return true
	}
	if strings.HasSuffix(path, ".lock") || strings.HasSuffix(path, ".pid") {
		return true
	}
	return false
}
