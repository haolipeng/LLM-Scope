package ssl

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"

	bpf "github.com/haolipeng/LLM-Scope/internal/bpf/agentsight"
	runtimebase "github.com/haolipeng/LLM-Scope/internal/collectors/base"
	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/logging"
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
	Comm       string // 逗号分隔的进程名列表，如 "node,claude"
	BinaryPath string
	OpenSSL    bool
	GnuTLS     bool
	NSS        bool
	Handshake  bool
}

// commSet 将逗号分隔的 Comm 拆分为 set，用于快速查找。
func (c Config) commSet() map[string]struct{} {
	if c.Comm == "" {
		return nil
	}
	set := make(map[string]struct{})
	for _, s := range strings.Split(c.Comm, ",") {
		s = strings.TrimSpace(s)
		if s != "" {
			set[s] = struct{}{}
		}
	}
	return set
}

// Runner loads sslsniff BPF program and reads SSL events via ring buffer.
type Runner struct {
	runtimebase.BaseRunner
	config  Config
	objs    bpf.Objects
	commSet map[string]struct{} // 预计算的 comm 集合
}

func New(config Config) *Runner {
	if !config.OpenSSL && !config.GnuTLS && !config.NSS && config.BinaryPath == "" {
		config.OpenSSL = true
	}
	r := &Runner{config: config, commSet: config.commSet()}
	r.BaseRunner = runtimebase.BaseRunner{Label: "[SSL]"}
	return r
}

func (r *Runner) ID() string   { return "ssl" }
func (r *Runner) Name() string { return "ssl" }

func (r *Runner) Run(ctx context.Context) (<-chan *event.Event, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		logging.Named("ssl").Warnf("remove memlock: %v", err)
	}

	spec, err := bpf.LoadSpec()
	if err != nil {
		return nil, fmt.Errorf("load BPF spec: %w", err)
	}

	if r.config.PID > 0 {
		if err := spec.Variables["ssl_targ_pid"].Set(int32(r.config.PID)); err != nil {
			return nil, fmt.Errorf("set ssl_targ_pid: %w", err)
		}
	}
	if r.config.UID >= 0 {
		uid := uint32(0xFFFFFFFF)
		if r.config.UID > 0 {
			uid = uint32(r.config.UID)
		}
		if err := spec.Variables["ssl_targ_uid"].Set(uid); err != nil {
			return nil, fmt.Errorf("set ssl_targ_uid: %w", err)
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

	if err := r.InitRingBuffer(r.objs.RbSsl); err != nil {
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
	logging.Named("ssl").Infof("discovered libraries: %s", formatSSLLibInfo(libs))

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
		logging.Named("ssl").Infof("attaching to binary: %s", r.config.BinaryPath)
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
		logging.Named("ssl").Warnf("cannot open %s: %v", libPath, err)
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

	if r.commSet != nil {
		if _, ok := r.commSet[comm]; !ok {
			return nil
		}
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

	latencyMs := float64(0)
	if deltaNs > 0 {
		latencyMs = float64(deltaNs) / 1_000_000.0
	}
	data["latency_ms"] = latencyMs

	bf := extractSSLBufferFields(raw, bufFilled, bufSize, dataLen)
	data["data"] = bf.data
	data["truncated"] = bf.truncated
	if bf.bytesLost > 0 {
		data["bytes_lost"] = bf.bytesLost
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

type sslBufferFields struct {
	data      interface{} // string or nil
	truncated bool
	bytesLost uint32 // 0 means no loss
}

func extractSSLBufferFields(raw []byte, bufFilled int32, bufSize, dataLen uint32) sslBufferFields {
	if bufFilled != 1 || bufSize == 0 {
		return sslBufferFields{}
	}
	actualSize := bufSize
	if actualSize > sslMaxBufSize {
		actualSize = sslMaxBufSize
	}
	if sslOffBuf+int(actualSize) > len(raw) {
		return sslBufferFields{}
	}
	bufData := raw[sslOffBuf : sslOffBuf+int(actualSize)]
	bf := sslBufferFields{
		data:      runtimebase.SanitizeBufferData(bufData),
		truncated: bufSize < dataLen,
	}
	if bufSize < dataLen {
		bf.bytesLost = dataLen - bufSize
	}
	return bf
}
