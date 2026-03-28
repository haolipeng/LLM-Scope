package runner

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	bpfstdio "github.com/haolipeng/LLM-Scope/internal/bpf/stdiocap"
	"github.com/haolipeng/LLM-Scope/internal/core"
)

// Stdio event field offsets for struct stdiocap_event_t on x86_64.
// struct stdiocap_event_t {
//   __u64 timestamp_ns;  // offset 0,  8 bytes
//   __u64 delta_ns;      // offset 8,  8 bytes
//   __u32 pid;           // offset 16, 4 bytes
//   __u32 tid;           // offset 20, 4 bytes
//   __u32 uid;           // offset 24, 4 bytes
//   __s32 fd;            // offset 28, 4 bytes
//   __u32 len;           // offset 32, 4 bytes
//   __u32 buf_size;      // offset 36, 4 bytes
//   __u8 is_read;        // offset 40, 1 byte
//   char comm[16];       // offset 41, 16 bytes
//   __u8 buf[8192];      // offset 57, up to 8192 bytes
// };
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

// StdioConfig configures the stdio runner.
type StdioConfig struct {
	PID      int
	UID      int
	Comm     string
	AllFDs   bool
	MaxBytes int
}

// StdioRunner loads stdiocap BPF program and reads stdio events via ring buffer.
type StdioRunner struct {
	config StdioConfig
	objs   bpfstdio.Objects
	links  []link.Link
	reader *ringbuf.Reader
}

func NewStdioRunner(config StdioConfig) *StdioRunner {
	if config.MaxBytes <= 0 {
		config.MaxBytes = stdioMaxBufSize
	}
	return &StdioRunner{config: config}
}

func (r *StdioRunner) ID() string   { return "stdio" }
func (r *StdioRunner) Name() string { return "stdio" }

func (r *StdioRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[Stdio] warning: remove memlock: %v", err)
	}

	spec, err := bpfstdio.LoadSpec()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	// Set const volatile filters
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

	// Attach 4 syscall tracepoints
	tracepoints := []struct {
		group string
		name  string
		prog  *ebpf.Program
	}{
		{"syscalls", "sys_enter_read", r.objs.TraceEnterRead},
		{"syscalls", "sys_exit_read", r.objs.TraceExitRead},
		{"syscalls", "sys_enter_write", r.objs.TraceEnterWrite},
		{"syscalls", "sys_exit_write", r.objs.TraceExitWrite},
	}

	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.group, tp.name, tp.prog, nil)
		if err != nil {
			r.closeLinks()
			r.objs.Close()
			return nil, fmt.Errorf("tracepoint %s/%s: %w", tp.group, tp.name, err)
		}
		r.links = append(r.links, l)
	}

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

func (r *StdioRunner) readLoop(ctx context.Context, out chan<- *core.Event) {
	defer close(out)
	defer r.reader.Close()

	for {
		record, err := r.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("[Stdio] ringbuf read error: %v", err)
			continue
		}

		event := r.parseStdioEvent(record.RawSample)
		if event == nil {
			continue
		}

		select {
		case out <- event:
		case <-ctx.Done():
			return
		}
	}
}

func (r *StdioRunner) parseStdioEvent(raw []byte) *core.Event {
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

	// Comm filter
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

	// Extract buf data
	if bufSize > 0 {
		actualSize := int(bufSize)
		if actualSize > stdioMaxBufSize {
			actualSize = stdioMaxBufSize
		}
		if stdioOffBuf+actualSize <= len(raw) {
			bufData := raw[stdioOffBuf : stdioOffBuf+actualSize]
			data["data"] = sanitizeStdioData(bufData)
			data["buf_size"] = bufSize
		}
	}

	jsonData, _ := json.Marshal(data)
	return &core.Event{
		TimestampNs:     int64(timestampNs),
		TimestampUnixMs: core.BootNsToUnixMs(int64(timestampNs)),
		Source:          "stdio",
		PID:             pid,
		Comm:            comm,
		Data:            json.RawMessage(jsonData),
	}
}

func sanitizeStdioData(buf []byte) string {
	var sb strings.Builder
	sb.Grow(len(buf))

	for i := 0; i < len(buf); {
		b := buf[i]
		if b < 128 {
			if b >= 32 && b <= 126 {
				sb.WriteByte(b)
			} else {
				switch b {
				case '\n':
					sb.WriteString("\\n")
				case '\r':
					sb.WriteString("\\r")
				case '\t':
					sb.WriteString("\\t")
				default:
					fmt.Fprintf(&sb, "\\u%04x", b)
				}
			}
			i++
		} else {
			r, size := utf8.DecodeRune(buf[i:])
			if r == utf8.RuneError && size <= 1 {
				fmt.Fprintf(&sb, "\\u%04x", b)
				i++
			} else {
				sb.Write(buf[i : i+size])
				i += size
			}
		}
	}
	return sb.String()
}

func (r *StdioRunner) Stop() error {
	if r.reader != nil {
		r.reader.Close()
	}
	r.closeLinks()
	r.objs.Close()
	return nil
}

func (r *StdioRunner) closeLinks() {
	for _, l := range r.links {
		l.Close()
	}
	r.links = nil
}
