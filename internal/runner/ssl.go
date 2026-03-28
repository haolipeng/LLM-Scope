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

	bpfssl "github.com/haolipeng/LLM-Scope/internal/bpf/sslsniff"
	"github.com/haolipeng/LLM-Scope/internal/core"
)

// SSL event field offsets for struct probe_SSL_data_t on x86_64.
// struct probe_SSL_data_t {
//   __u64 timestamp_ns;    // offset 0,  8 bytes
//   __u64 delta_ns;        // offset 8,  8 bytes
//   __u32 pid;             // offset 16, 4 bytes
//   __u32 tid;             // offset 20, 4 bytes
//   __u32 uid;             // offset 24, 4 bytes
//   __u32 len;             // offset 28, 4 bytes
//   __u32 buf_size;        // offset 32, 4 bytes
//   int buf_filled;        // offset 36, 4 bytes
//   int rw;                // offset 40, 4 bytes
//   char comm[16];         // offset 44, 16 bytes
//   __u8 buf[MAX_BUF_SIZE]; // offset 60, up to 524288 bytes
//   int is_handshake;      // offset 60+buf_size area
// };
//
// IMPORTANT: Do NOT instantiate the full generated Go struct (524KB+).
// Parse directly from RawSample []byte.
const (
	sslOffTimestampNs = 0
	sslOffDeltaNs     = 8
	sslOffPid         = 16
	sslOffTid         = 20
	sslOffUid         = 24
	sslOffLen         = 28
	sslOffBufSize     = 32
	sslOffBufFilled   = 36
	sslOffRw          = 40
	sslOffComm        = 44
	sslCommLen        = 16
	sslOffBuf         = 60
	sslMaxBufSize     = 512 * 1024
	// is_handshake is at sslOffBuf + sslMaxBufSize, but we read it relative to end
	sslMinEventSize = 60 // minimum header size before buf
)

var rwEventNames = []string{"READ/RECV", "WRITE/SEND", "HANDSHAKE"}

// SSLConfig configures the SSL runner.
type SSLConfig struct {
	PID        int
	UID        int
	Comm       string
	BinaryPath string // custom SSL binary path (e.g., statically linked Node.js)
	OpenSSL    bool
	GnuTLS     bool
	NSS        bool
	Handshake  bool // whether to emit handshake events
}

// SSLRunner loads sslsniff BPF program and reads SSL events via ring buffer.
type SSLRunner struct {
	config SSLConfig
	objs   bpfssl.Objects
	links  []link.Link
	reader *ringbuf.Reader
}

func NewSSLRunner(config SSLConfig) *SSLRunner {
	// Default: enable OpenSSL if nothing specified
	if !config.OpenSSL && !config.GnuTLS && !config.NSS && config.BinaryPath == "" {
		config.OpenSSL = true
	}
	return &SSLRunner{config: config}
}

func (r *SSLRunner) ID() string   { return "ssl" }
func (r *SSLRunner) Name() string { return "ssl" }

func (r *SSLRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[SSL] warning: remove memlock: %v", err)
	}

	spec, err := bpfssl.LoadSpec()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	// Set const volatile filters
	if r.config.PID > 0 {
		if err := spec.Variables["targ_pid"].Set(int32(r.config.PID)); err != nil {
			return nil, fmt.Errorf("set targ_pid: %w", err)
		}
	}
	if r.config.UID >= 0 {
		uid := uint32(0xFFFFFFFF) // -1 = all UIDs
		if r.config.UID > 0 {
			uid = uint32(r.config.UID)
		}
		if err := spec.Variables["targ_uid"].Set(uid); err != nil {
			return nil, fmt.Errorf("set targ_uid: %w", err)
		}
	}

	if err := spec.LoadAndAssign(&r.objs, nil); err != nil {
		return nil, fmt.Errorf("load BPF objects: %w", err)
	}

	// Attach uprobes
	if err := r.attachUprobes(); err != nil {
		r.objs.Close()
		return nil, fmt.Errorf("attach uprobes: %w", err)
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

func (r *SSLRunner) attachUprobes() error {
	libs := discoverSSLLibraries(r.config.OpenSSL, r.config.GnuTLS, r.config.NSS)
	log.Printf("[SSL] discovered libraries: %s", formatSSLLibInfo(libs))

	// Attach to discovered libraries
	if path, ok := libs["openssl"]; ok {
		r.attachLibUprobes(path, opensslUprobes)
	}
	if path, ok := libs["gnutls"]; ok {
		r.attachLibUprobes(path, gnutlsUprobes)
	}
	if path, ok := libs["nss"]; ok {
		r.attachLibUprobes(path, nssUprobes)
	}

	// Attach to custom binary path (for statically-linked SSL)
	if r.config.BinaryPath != "" {
		log.Printf("[SSL] attaching to binary: %s", r.config.BinaryPath)
		r.attachLibUprobes(r.config.BinaryPath, opensslUprobes)
	}

	if len(r.links) == 0 {
		return fmt.Errorf("no SSL libraries found and no uprobes attached")
	}
	return nil
}

func (r *SSLRunner) attachLibUprobes(libPath string, specs []sslUprobeSpec) {
	exe, err := link.OpenExecutable(libPath)
	if err != nil {
		log.Printf("[SSL] warning: cannot open %s: %v", libPath, err)
		return
	}

	for _, spec := range specs {
		prog := r.getProgramByName(spec.prog)
		if prog == nil {
			continue
		}

		var l link.Link
		if spec.isRetprobe {
			l, err = exe.Uretprobe(spec.symbol, prog, nil)
		} else {
			l, err = exe.Uprobe(spec.symbol, prog, nil)
		}
		if err != nil {
			log.Printf("[SSL] warning: attach %s/%s on %s: %v", spec.symbol, spec.prog, libPath, err)
			continue
		}
		r.links = append(r.links, l)
	}
}

func (r *SSLRunner) getProgramByName(name string) *ebpf.Program {
	switch name {
	case "ProbeSSL_rwEnter":
		return r.objs.ProbeSSL_rwEnter
	case "ProbeSSL_writeExit":
		return r.objs.ProbeSSL_writeExit
	case "ProbeSSL_readExit":
		return r.objs.ProbeSSL_readExit
	case "ProbeSSL_writeExEnter":
		return r.objs.ProbeSSL_writeExEnter
	case "ProbeSSL_writeExExit":
		return r.objs.ProbeSSL_writeExExit
	case "ProbeSSL_readExEnter":
		return r.objs.ProbeSSL_readExEnter
	case "ProbeSSL_readExExit":
		return r.objs.ProbeSSL_readExExit
	case "ProbeSSL_doHandshakeEnter":
		return r.objs.ProbeSSL_doHandshakeEnter
	case "ProbeSSL_doHandshakeExit":
		return r.objs.ProbeSSL_doHandshakeExit
	default:
		return nil
	}
}

func (r *SSLRunner) readLoop(ctx context.Context, out chan<- *core.Event) {
	defer close(out)
	defer r.reader.Close()

	for {
		record, err := r.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("[SSL] ringbuf read error: %v", err)
			continue
		}

		event := r.parseSSLEvent(record.RawSample)
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

func (r *SSLRunner) parseSSLEvent(raw []byte) *core.Event {
	if len(raw) < sslMinEventSize {
		return nil
	}

	le := binary.LittleEndian
	timestampNs := le.Uint64(raw[sslOffTimestampNs:])
	deltaNs := le.Uint64(raw[sslOffDeltaNs:])
	pid := le.Uint32(raw[sslOffPid:])
	tid := le.Uint32(raw[sslOffTid:])
	uid := le.Uint32(raw[sslOffUid:])
	dataLen := le.Uint32(raw[sslOffLen:])
	bufSize := le.Uint32(raw[sslOffBufSize:])
	bufFilled := int32(le.Uint32(raw[sslOffBufFilled:]))
	rw := int32(le.Uint32(raw[sslOffRw:]))
	comm := cStringFromBytes(raw[sslOffComm : sslOffComm+sslCommLen])

	// Read is_handshake: it's at offset sslOffBuf + sslMaxBufSize
	isHandshakeOff := sslOffBuf + sslMaxBufSize
	isHandshake := false
	if len(raw) > isHandshakeOff+4 {
		isHandshake = int32(le.Uint32(raw[isHandshakeOff:])) != 0
	}

	// Comm filter
	if r.config.Comm != "" && comm != r.config.Comm {
		return nil
	}

	// Skip handshake if not requested
	if isHandshake && !r.config.Handshake {
		return nil
	}

	// Get rw event name
	rwName := "UNKNOWN"
	if rw >= 0 && rw < int32(len(rwEventNames)) {
		rwName = rwEventNames[rw]
	}

	// Build JSON data - compatible with sslsniff.c output format
	data := map[string]interface{}{
		"function":     rwName,
		"timestamp_ns": timestampNs,
		"comm":         comm,
		"pid":          pid,
		"len":          dataLen,
		"buf_size":     bufSize,
		"uid":          uid,
		"tid":          tid,
		"is_handshake": isHandshake,
	}

	// Latency
	if deltaNs > 0 {
		data["latency_ms"] = float64(deltaNs) / 1_000_000.0
	} else {
		data["latency_ms"] = 0
	}

	// Extract buf data - DO NOT copy the full 512KB, only the actual data
	if bufFilled == 1 && bufSize > 0 {
		actualSize := bufSize
		if actualSize > sslMaxBufSize {
			actualSize = sslMaxBufSize
		}
		if sslOffBuf+int(actualSize) <= len(raw) {
			bufData := raw[sslOffBuf : sslOffBuf+int(actualSize)]
			data["data"] = sanitizeSSLData(bufData)
			data["truncated"] = bufSize < dataLen
			if bufSize < dataLen {
				data["bytes_lost"] = dataLen - bufSize
			}
		} else {
			data["data"] = nil
			data["truncated"] = false
		}
	} else {
		data["data"] = nil
		data["truncated"] = false
	}

	jsonData, _ := json.Marshal(data)
	return &core.Event{
		TimestampNs:     int64(timestampNs),
		TimestampUnixMs: core.BootNsToUnixMs(int64(timestampNs)),
		Source:          "ssl",
		PID:             pid,
		Comm:            comm,
		Data:            json.RawMessage(jsonData),
	}
}

// sanitizeSSLData produces a JSON-safe string from raw SSL buffer data,
// handling UTF-8 validation and control character escaping.
func sanitizeSSLData(buf []byte) string {
	var sb strings.Builder
	sb.Grow(len(buf))

	for i := 0; i < len(buf); {
		b := buf[i]
		if b < 128 {
			// ASCII range
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
			// Check for valid UTF-8 sequence
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

func (r *SSLRunner) Stop() error {
	if r.reader != nil {
		r.reader.Close()
	}
	r.closeLinks()
	r.objs.Close()
	return nil
}

func (r *SSLRunner) closeLinks() {
	for _, l := range r.links {
		l.Close()
	}
	r.links = nil
}
