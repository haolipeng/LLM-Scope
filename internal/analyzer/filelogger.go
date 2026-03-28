package analyzer

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/haolipeng/LLM-Scope/internal/core"
)

// FileLogger appends each event as JSONL to a file.
type FileLogger struct {
	path          string
	rotate        bool
	maxSizeMB     int
	maxFiles      int
	checkInterval int
	eventCount    int
	mu            sync.Mutex
	file          *os.File
	writer        *bufio.Writer
}

func NewFileLogger(path string, rotate bool, maxSizeMB int) *FileLogger {
	return NewFileLoggerWithOptions(path, rotate, maxSizeMB, 5, 100)
}

func NewFileLoggerWithOptions(path string, rotate bool, maxSizeMB, maxFiles, checkInterval int) *FileLogger {
	if maxFiles <= 0 {
		maxFiles = 5
	}
	if checkInterval <= 0 {
		checkInterval = 100
	}
	return &FileLogger{
		path:          path,
		rotate:        rotate,
		maxSizeMB:     maxSizeMB,
		maxFiles:      maxFiles,
		checkInterval: checkInterval,
	}
}

func (f *FileLogger) Name() string {
	return "file_logger"
}

func (f *FileLogger) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
	out := make(chan *core.Event)

	go func() {
		defer close(out)
		defer f.closeFile()

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

func (f *FileLogger) openFile() error {
	file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	f.file = file
	f.writer = bufio.NewWriterSize(file, 64*1024)
	return nil
}

func (f *FileLogger) closeFile() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.flushAndClose()
}

func (f *FileLogger) flushAndClose() {
	if f.writer != nil {
		_ = f.writer.Flush()
		f.writer = nil
	}
	if f.file != nil {
		_ = f.file.Close()
		f.file = nil
	}
}

func (f *FileLogger) writeEvent(event *core.Event) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.eventCount++
	if f.rotate && f.eventCount%f.checkInterval == 0 {
		f.maybeRotate()
	}

	if f.file == nil {
		if err := f.openFile(); err != nil {
			fmt.Fprintf(os.Stderr, "file logger: %v\n", err)
			return
		}
	}

	payload, err := json.Marshal(event)
	if err != nil {
		fmt.Fprintf(os.Stderr, "file logger: marshal error: %v\n", err)
		return
	}

	payload = normalizeBinaryData(payload)
	_, _ = f.writer.Write(append(payload, '\n'))
}

func (f *FileLogger) maybeRotate() {
	info, err := os.Stat(f.path)
	if err != nil {
		return
	}

	if info.Size() <= int64(f.maxSizeMB)*1024*1024 {
		return
	}

	// Flush and close current file before rotating
	f.flushAndClose()

	// Chain rotation: .N-1 → .N, ..., .1 → .2, current → .1
	// Remove the oldest file if it exceeds maxFiles
	oldest := fmt.Sprintf("%s.%d", f.path, f.maxFiles)
	_ = os.Remove(oldest)

	// Shift existing rotated files
	for i := f.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", f.path, i)
		dst := fmt.Sprintf("%s.%d", f.path, i+1)
		_ = os.Rename(src, dst)
	}

	// Rotate current → .1
	rotated := fmt.Sprintf("%s.1", f.path)
	if err := os.Rename(f.path, rotated); err != nil {
		log.Printf("file logger: rotate error: %v", err)
	}

	// Reopen file after rotation
	if err := f.openFile(); err != nil {
		fmt.Fprintf(os.Stderr, "file logger: reopen after rotate: %v\n", err)
	}
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
