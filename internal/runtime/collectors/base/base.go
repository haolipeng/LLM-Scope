package base

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// BaseRunner provides shared BPF runner infrastructure: ring buffer reading,
// link management, and probe attachment helpers with warning-only error handling.
type BaseRunner struct {
	Label  string // log prefix, e.g. "[Process]"
	Reader *ringbuf.Reader
	Links  []link.Link
	Closer io.Closer // typically &objs for Objects.Close()
}

// Stop closes the reader, all links, and the BPF objects in order.
func (b *BaseRunner) Stop() error {
	if b.Reader != nil {
		b.Reader.Close()
	}
	b.CloseLinks()
	if b.Closer != nil {
		b.Closer.Close()
	}
	return nil
}

// CloseLinks closes all attached BPF links and resets the slice.
func (b *BaseRunner) CloseLinks() {
	for _, l := range b.Links {
		l.Close()
	}
	b.Links = nil
}

// InitRingBuffer creates a ring buffer reader from the given BPF map.
func (b *BaseRunner) InitRingBuffer(rbMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}
	b.Reader = rd
	return nil
}

// ReadLoop reads events from the ring buffer in a loop, calls parseFn for each
// record, and sends resulting events to the out channel. It closes the channel
// and the reader when done.
func (b *BaseRunner) ReadLoop(ctx context.Context, out chan<- *runtimeevent.Event, parseFn func([]byte) []*runtimeevent.Event) {
	defer close(out)
	defer b.Reader.Close()

	for {
		record, err := b.Reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("%s ringbuf read error: %v", b.Label, err)
			continue
		}

		events := parseFn(record.RawSample)
		for _, event := range events {
			select {
			case out <- event:
			case <-ctx.Done():
				return
			}
		}
	}
}

// AttachTracepoint attaches a tracepoint probe, logging a warning on failure.
func (b *BaseRunner) AttachTracepoint(group, name string, prog *ebpf.Program) {
	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		log.Printf("%s warning: tracepoint %s/%s: %v", b.Label, group, name, err)
		return
	}
	b.Links = append(b.Links, l)
}

// AttachKprobe attaches a kprobe, logging a warning on failure.
func (b *BaseRunner) AttachKprobe(symbol string, prog *ebpf.Program) {
	l, err := link.Kprobe(symbol, prog, nil)
	if err != nil {
		log.Printf("%s warning: kprobe %s: %v", b.Label, symbol, err)
		return
	}
	b.Links = append(b.Links, l)
}

// AttachUprobe attaches a uprobe on the given executable, logging a warning on failure.
func (b *BaseRunner) AttachUprobe(exe *link.Executable, symbol string, prog *ebpf.Program) {
	l, err := exe.Uprobe(symbol, prog, nil)
	if err != nil {
		log.Printf("%s warning: uprobe %s: %v", b.Label, symbol, err)
		return
	}
	b.Links = append(b.Links, l)
}

// AttachUretprobe attaches a uretprobe on the given executable, logging a warning on failure.
func (b *BaseRunner) AttachUretprobe(exe *link.Executable, symbol string, prog *ebpf.Program) {
	l, err := exe.Uretprobe(symbol, prog, nil)
	if err != nil {
		log.Printf("%s warning: uretprobe %s: %v", b.Label, symbol, err)
		return
	}
	b.Links = append(b.Links, l)
}

// SanitizeBufferData produces a JSON-safe string from raw buffer data,
// handling UTF-8 validation and control character escaping.
func SanitizeBufferData(buf []byte) string {
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
