package stdio

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/ebpf/rlimit"

	bpfstdio "github.com/haolipeng/LLM-Scope/internal/bpf/stdiocap"
	runtimebase "github.com/haolipeng/LLM-Scope/internal/collectors/base"
	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/logging"
)

// Stdio event field offsets for struct stdiocap_event_t on x86_64.
const (
	stdioOffTimestampNs = 0
	stdioOffDeltaNs     = 8
	stdioOffPid         = 16
	stdioOffTid         = 20
	stdioOffUid         = 24
	stdioOffFd          = 28
	stdioOffLen         = 32
	stdioOffBufSize     = 36
	stdioOffIsRead      = 40
	stdioOffComm        = 41
	stdioCommLen        = 16
	stdioOffBuf         = 57
	stdioMaxBufSize     = 8192
	stdioMinEventSize   = 57
)

// Config configures the stdio runner.
type Config struct {
	PID      int
	UID      int
	Comm     string
	AllFDs   bool
	MaxBytes int
}

// Runner loads stdiocap BPF program and reads stdio events via ring buffer.
type Runner struct {
	runtimebase.BaseRunner
	config Config
	objs   bpfstdio.Objects
}

func New(config Config) *Runner {
	if config.MaxBytes <= 0 {
		config.MaxBytes = stdioMaxBufSize
	}
	r := &Runner{config: config}
	r.BaseRunner = runtimebase.BaseRunner{Label: "[Stdio]"}
	return r
}

func (r *Runner) ID() string   { return "stdio" }
func (r *Runner) Name() string { return "stdio" }

func (r *Runner) Run(ctx context.Context) (<-chan *event.Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Named("stdio").Warnf("remove memlock: %v", err)
	}

	spec, err := bpfstdio.LoadSpec()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	if r.config.PID > 0 {
		if err := spec.Variables["targ_pid"].Set(uint32(r.config.PID)); err != nil {
			return nil, fmt.Errorf("set targ_pid: %w", err)
		}
	}
	if r.config.UID > 0 {
		if err := spec.Variables["targ_uid"].Set(uint32(r.config.UID)); err != nil {
			return nil, fmt.Errorf("set targ_uid: %w", err)
		}
	}
	if r.config.AllFDs {
		if err := spec.Variables["trace_stdio_only"].Set(false); err != nil {
			return nil, fmt.Errorf("set trace_stdio_only: %w", err)
		}
	}
	if r.config.MaxBytes > 0 && r.config.MaxBytes < stdioMaxBufSize {
		if err := spec.Variables["max_capture_bytes"].Set(uint32(r.config.MaxBytes)); err != nil {
			return nil, fmt.Errorf("set max_capture_bytes: %w", err)
		}
	}

	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}
	r.Closer = &r.objs

	r.AttachTracepoint("syscalls", "sys_enter_read", r.objs.TraceEnterRead)
	r.AttachTracepoint("syscalls", "sys_exit_read", r.objs.TraceExitRead)
	r.AttachTracepoint("syscalls", "sys_enter_write", r.objs.TraceEnterWrite)
	r.AttachTracepoint("syscalls", "sys_exit_write", r.objs.TraceExitWrite)

	if len(r.Links) == 0 {
		r.objs.Close()
		return nil, fmt.Errorf("no tracepoints attached")
	}

	if err := r.InitRingBuffer(r.objs.Rb); err != nil {
		r.CloseLinks()
		r.objs.Close()
		return nil, err
	}

	out := make(chan *event.Event, 100)
	go r.ReadLoop(ctx, out, r.parseEvents)

	return out, nil
}

func (r *Runner) parseEvents(raw []byte) []*event.Event {
	evt := r.parseStdioEvent(raw)
	if evt == nil {
		return nil
	}
	return []*event.Event{evt}
}

func (r *Runner) parseStdioEvent(raw []byte) *event.Event {
	if len(raw) < stdioMinEventSize {
		return nil
	}

	le := binary.LittleEndian
	timestampNs := le.Uint64(raw[stdioOffTimestampNs:])
	deltaNs := le.Uint64(raw[stdioOffDeltaNs:])
	pid := le.Uint32(raw[stdioOffPid:])
	tid := le.Uint32(raw[stdioOffTid:])
	uid := le.Uint32(raw[stdioOffUid:])
	fd := int32(le.Uint32(raw[stdioOffFd:]))
	dataLen := le.Uint32(raw[stdioOffLen:])
	bufSize := le.Uint32(raw[stdioOffBufSize:])
	isRead := raw[stdioOffIsRead] != 0
	comm := cStringFromBytes(raw[stdioOffComm : stdioOffComm+stdioCommLen])

	if r.config.Comm != "" && comm != r.config.Comm {
		return nil
	}

	direction := "write"
	if isRead {
		direction = "read"
	}

	data := map[string]interface{}{
		"timestamp_ns": timestampNs,
		"comm":         comm,
		"pid":          pid,
		"tid":          tid,
		"uid":          uid,
		"fd":           fd,
		"len":          dataLen,
		"direction":    direction,
	}

	if deltaNs > 0 {
		data["latency_ms"] = float64(deltaNs) / 1_000_000.0
	}

	if bufSize > 0 {
		actualSize := int(bufSize)
		if actualSize > stdioMaxBufSize {
			actualSize = stdioMaxBufSize
		}
		if stdioOffBuf+actualSize <= len(raw) {
			bufData := raw[stdioOffBuf : stdioOffBuf+actualSize]
			data["data"] = runtimebase.SanitizeBufferData(bufData)
			data["buf_size"] = bufSize
		}
	}

	jsonData, _ := json.Marshal(data)
	return &event.Event{
		TimestampNs:     int64(timestampNs),
		TimestampUnixMs: event.BootNsToUnixMs(int64(timestampNs)),
		Source:          "stdio",
		PID:             pid,
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
