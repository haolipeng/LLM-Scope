package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sync"

	"github.com/eunomia-bpf/agentsight/internal/core"
)

// FileLogger appends each event as JSONL to a file.
type FileLogger struct {
	path      string
	rotate    bool
	maxSizeMB int
	mu        sync.Mutex
}

func NewFileLogger(path string, rotate bool, maxSizeMB int) *FileLogger {
	return &FileLogger{
		path:      path,
		rotate:    rotate,
		maxSizeMB: maxSizeMB,
	}
}

func (f *FileLogger) Name() string {
	return "file_logger"
}

func (f *FileLogger) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
	out := make(chan *core.Event)

	go func() {
		defer close(out)

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-in:
				if !ok {
					return
				}

				f.writeEvent(event)

				out <- event
			}
		}
	}()

	return out
}

func (f *FileLogger) writeEvent(event *core.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.rotate {
		f.maybeRotate()
	}

	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr, "file logger: %v\n", err)
		return
	}
	defer file.Close()

	payload, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "file logger: marshal error: %v\n", err)
		return
	}

	payload = normalizeBinaryData(payload)
	_, _ = file.Write(append(payload, '\n'))
}

func (f *FileLogger) maybeRotate() {
	info, err := os.Stat(f.path)
	if err != nil {
		return
	}

	if info.Size() <= int64(f.maxSizeMB)*1024*1024 {
		return
	}

	rotated := fmt.Sprintf("%s.1", f.path)
	_ = os.Remove(rotated)
	_ = os.Rename(f.path, rotated)
}

func normalizeBinaryData(payload []byte) []byte {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return payload
	}

	dataField, ok := data["data"].(map[string]interface{})
	if !ok {
		return payload
	}

	value, ok := dataField["data"].(string)
	if !ok {
		return payload
	}

	dataField["data"] = dataToString(value)
	data["data"] = dataField

	updated, err := json.Marshal(data)
	if err != nil {
		return payload
	}
	return updated
}
