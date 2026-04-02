package ssl

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	bpfssl "github.com/haolipeng/LLM-Scope/internal/bpf/sslsniff"
	runtimebase "github.com/haolipeng/LLM-Scope/internal/collectors/base"
	"github.com/haolipeng/LLM-Scope/internal/event"
)

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
	sslMinEventSize   = 60
)

var rwEventNames = []string{"READ/RECV", "WRITE/SEND", "HANDSHAKE"}

// Config configures the SSL runner.
type Config struct {
	PID        int
	UID        int
	Comm       string
	BinaryPath string
	OpenSSL    bool
	GnuTLS     bool
	NSS        bool
	Handshake  bool
}

// Runner loads sslsniff BPF program and reads SSL events via ring buffer.
type Runner struct {
	runtimebase.BaseRunner
	config Config
	objs   bpfssl.Objects
}

func New(config Config) *Runner {
	if !config.OpenSSL && !config.GnuTLS && !config.NSS && config.BinaryPath == "" {
		config.OpenSSL = true
	}
	r := &Runner{config: config}
	r.BaseRunner = runtimebase.BaseRunner{Label: "[SSL]"}
	return r
}

func (r *Runner) ID() string   { return "ssl" }
func (r *Runner) Name() string { return "ssl" }

func (r *Runner) Run(ctx context.Context) (<-chan *event.Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("[SSL] warning: remove memlock: %v", err)
	}

	spec, err := bpfssl.LoadSpec()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	if r.config.PID > 0 {
		if err := spec.Variables["targ_pid"].Set(int32(r.config.PID)); err != nil {
			return nil, fmt.Errorf("set targ_pid: %w", err)
		}
	}
	if r.config.UID >= 0 {
		uid := uint32(0xFFFFFFFF)
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
	r.Closer = &r.objs

	if err := r.attachUprobes(); err != nil {
		r.objs.Close()
		return nil, fmt.Errorf("attach uprobes: %w", err)
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

func (r *Runner) attachUprobes() error {
	libs := discoverSSLLibraries(r.config.OpenSSL, r.config.GnuTLS, r.config.NSS)
	log.Printf("[SSL] discovered libraries: %s", formatSSLLibInfo(libs))

	if path, ok := libs["openssl"]; ok {
		r.attachLibUprobes(path, opensslUprobes)
	}
	if path, ok := libs["gnutls"]; ok {
		r.attachLibUprobes(path, gnutlsUprobes)
	}
	if path, ok := libs["nss"]; ok {
		r.attachLibUprobes(path, nssUprobes)
	}

	if r.config.BinaryPath != "" {
		log.Printf("[SSL] attaching to binary: %s", r.config.BinaryPath)
		r.attachLibUprobes(r.config.BinaryPath, opensslUprobes)
	}

	if len(r.Links) == 0 {
		return fmt.Errorf("no SSL libraries found and no uprobes attached")
	}
	return nil
}

func (r *Runner) attachLibUprobes(libPath string, specs []sslUprobeSpec) {
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

		if spec.isRetprobe {
			r.AttachUretprobe(exe, spec.symbol, prog)
		} else {
			r.AttachUprobe(exe, spec.symbol, prog)
		}
	}
}

func (r *Runner) getProgramByName(name string) *ebpf.Program {
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

func (r *Runner) parseEvents(raw []byte) []*event.Event {
	evt := r.parseSSLEvent(raw)
	if evt == nil {
		return nil
	}
	return []*event.Event{evt}
}

func (r *Runner) parseSSLEvent(raw []byte) *event.Event {
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

	isHandshakeOff := sslOffBuf + sslMaxBufSize
	isHandshake := false
	if len(raw) > isHandshakeOff+4 {
		isHandshake = int32(le.Uint32(raw[isHandshakeOff:])) != 0
	}

	if r.config.Comm != "" && comm != r.config.Comm {
		return nil
	}
	if isHandshake && !r.config.Handshake {
		return nil
	}

	rwName := "UNKNOWN"
	if rw >= 0 && rw < int32(len(rwEventNames)) {
		rwName = rwEventNames[rw]
	}

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

	if deltaNs > 0 {
		data["latency_ms"] = float64(deltaNs) / 1_000_000.0
	} else {
		data["latency_ms"] = 0
	}

	if bufFilled == 1 && bufSize > 0 {
		actualSize := bufSize
		if actualSize > sslMaxBufSize {
			actualSize = sslMaxBufSize
		}
		if sslOffBuf+int(actualSize) <= len(raw) {
			bufData := raw[sslOffBuf : sslOffBuf+int(actualSize)]
			data["data"] = runtimebase.SanitizeBufferData(bufData)
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
	return &event.Event{
		TimestampNs:     int64(timestampNs),
		TimestampUnixMs: event.BootNsToUnixMs(int64(timestampNs)),
		Source:          "ssl",
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
