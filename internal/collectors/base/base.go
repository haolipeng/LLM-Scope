package base

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/haolipeng/LLM-Scope/internal/event"
	"github.com/haolipeng/LLM-Scope/internal/logging"

	"go.uber.org/zap"
)

// BaseRunner 提供共享的 BPF 运行器基础设施：环形缓冲区读取、
// 链路管理，以及探针挂载辅助函数（失败时仅记录警告，不中断）。
type BaseRunner struct {
	Label  string // 日志前缀，例如 "[Process]"
	Reader *ringbuf.Reader
	Links  []link.Link
	Closer io.Closer // 通常是 &objs，用于调用 Objects.Close()
}

const (
	asciiByteLimit = 128
	asciiPrintMin  = 32
	asciiPrintMax  = 126
)

func (b *BaseRunner) logPrefix() string {
	if b.Label == "" {
		return "[BaseRunner]"
	}
	return b.Label
}

// log 返回带组件名的 SugaredLogger；全项目约定见 internal/logging/doc.go。
func (b *BaseRunner) log() *zap.SugaredLogger {
	return logging.Named(b.logPrefix())
}

// Stop 依次关闭 Reader、所有链接以及 BPF 对象。
func (b *BaseRunner) Stop() error {
	if b.Reader != nil {
		if err := b.Reader.Close(); err != nil {
			b.log().Errorf("关闭 ringbuf Reader 失败：%v", err)
		}
	}
	b.CloseLinks()
	if b.Closer != nil {
		if err := b.Closer.Close(); err != nil {
			b.log().Errorf("关闭对象 Close() 失败：%v", err)
		}
	}
	return nil
}

// CloseLinks 关闭所有已挂载的 BPF 链路，并重置链接列表。
func (b *BaseRunner) CloseLinks() {
	for _, l := range b.Links {
		l.Close()
	}
	b.Links = nil
}

// InitRingBuffer 从指定的 BPF map 创建环形缓冲区 Reader。
func (b *BaseRunner) InitRingBuffer(rbMap *ebpf.Map) error {
	rd, err := ringbuf.NewReader(rbMap)
	if err != nil {
		return fmt.Errorf("create ringbuf reader: %w", err)
	}
	b.Reader = rd
	return nil
}

// ReadLoop 在循环中从环形缓冲区读取事件，针对每条记录调用 parseFn，
// 并将解析得到的事件发送到 out 通道。完成后会关闭 out 通道并关闭 Reader。
func (b *BaseRunner) ReadLoop(ctx context.Context, out chan<- *event.Event, parseFn func([]byte) []*event.Event) {
	defer close(out)

	if b.Reader == nil {
		b.log().Warnf("ReadLoop 被调用但 Reader 为 nil，直接返回")
		return
	}
	defer b.Reader.Close()

	b.log().Infof("ReadLoop 启动")

	for {
		record, err := b.Reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				b.log().Infof("ringbuf 已关闭，ReadLoop 退出")
				return
			}
			b.log().Warnf("ringbuf 读取失败：%v", err)
			continue
		}

		events := parseFn(record.RawSample)
		for _, event := range events {
			select {
			case out <- event:
			case <-ctx.Done():
				b.log().Infof("上下文已取消，ReadLoop 退出")
				return
			}
		}
	}
}

// AttachTracepoint 挂载 tracepoint 探针；失败时记录警告日志。
func (b *BaseRunner) AttachTracepoint(group, name string, prog *ebpf.Program) {
	l, err := link.Tracepoint(group, name, prog, nil)
	if err != nil {
		b.log().Warnf("tracepoint 挂载失败 %s/%s：%v", group, name, err)
		return
	}
	b.Links = append(b.Links, l)
}

// AttachKprobe 挂载 kprobe；失败时记录警告日志。
func (b *BaseRunner) AttachKprobe(symbol string, prog *ebpf.Program) {
	l, err := link.Kprobe(symbol, prog, nil)
	if err != nil {
		b.log().Warnf("kprobe 挂载失败 %s：%v", symbol, err)
		return
	}
	b.Links = append(b.Links, l)
}

// AttachUprobe 在指定可执行文件上挂载 uprobe；失败时记录警告日志。
func (b *BaseRunner) AttachUprobe(exe *link.Executable, symbol string, prog *ebpf.Program) {
	l, err := exe.Uprobe(symbol, prog, nil)
	if err != nil {
		b.log().Warnf("uprobe 挂载失败 %s：%v", symbol, err)
		return
	}
	b.Links = append(b.Links, l)
}

// AttachUretprobe 在指定可执行文件上挂载 uretprobe；失败时记录警告日志。
func (b *BaseRunner) AttachUretprobe(exe *link.Executable, symbol string, prog *ebpf.Program) {
	l, err := exe.Uretprobe(symbol, prog, nil)
	if err != nil {
		b.log().Warnf("uretprobe 挂载失败 %s：%v", symbol, err)
		return
	}
	b.Links = append(b.Links, l)
}

// SanitizeBufferData 从原始缓冲区数据生成适合 JSON 的字符串，
// 处理 UTF-8 校验以及控制字符转义。
// CR/LF/TAB 会按字节原样保留（`json.Marshal` 在把字符串序列化为 JSON 时会处理编码）。
func SanitizeBufferData(buf []byte) string {
	var sb strings.Builder
	sb.Grow(len(buf))

	for i := 0; i < len(buf); {
		b := buf[i]
		if b < asciiByteLimit {
			if b >= asciiPrintMin && b <= asciiPrintMax {
				sb.WriteByte(b)
			} else {
				switch b {
				case '\n':
					sb.WriteByte('\n')
				case '\r':
					sb.WriteByte('\r')
				case '\t':
					sb.WriteByte('\t')
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
