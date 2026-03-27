package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/haolipeng/LLM-Scope/internal/core"
)

// StdioConfig configures the stdio runner.
type StdioConfig struct {
	PID      int
	UID      int
	Comm     string
	AllFDs   bool
	MaxBytes int
}

// StdioRunner executes the stdiocap binary and converts JSON output to Events.
type StdioRunner struct {
	config   StdioConfig
	executor *BinaryExecutor
}

func NewStdioRunner(config StdioConfig) *StdioRunner {
	if config.MaxBytes <= 0 {
		config.MaxBytes = 8192
	}

	args := buildStdioArgs(config)

	return &StdioRunner{
		config:   config,
		executor: NewBinaryExecutor("bpf/stdiocap", args).WithRunnerName("Stdio"),
	}
}

func buildStdioArgs(config StdioConfig) []string {
	var args []string
	if config.PID != 0 {
		args = append(args, "-p", fmt.Sprintf("%d", config.PID))
	}
	if config.UID != 0 {
		args = append(args, "-u", fmt.Sprintf("%d", config.UID))
	}
	if config.Comm != "" {
		args = append(args, "-c", config.Comm)
	}
	if config.AllFDs {
		args = append(args, "--all-fds")
	}
	if config.MaxBytes > 0 {
		args = append(args, "--max-bytes", fmt.Sprintf("%d", config.MaxBytes))
	}
	return args
}

func (r *StdioRunner) ID() string {
	return "stdio"
}

func (r *StdioRunner) Name() string {
	return "stdio"
}

func (r *StdioRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	rawStream, err := r.executor.Run(ctx)
	if err != nil {
		return nil, err
	}

	out := make(chan *core.Event, 100)
	go func() {
		defer close(out)

		for {
			select {
			case <-ctx.Done():
				return
			case raw, ok := <-rawStream:
				if !ok {
					return
				}

				var header struct {
					TimestampNs int64  `json:"timestamp_ns"`
					PID         uint32 `json:"pid"`
					Comm        string `json:"comm"`
				}

				if err := json.Unmarshal(raw, &header); err != nil {
					fmt.Fprintf(os.Stderr, "stdio runner: failed to parse event header: %v\n", err)
					continue
				}

				event := &core.Event{
					TimestampNs:     header.TimestampNs,
					TimestampUnixMs: core.BootNsToUnixMs(header.TimestampNs),
					Source:          "stdio",
					PID:             header.PID,
					Comm:            header.Comm,
					Data:            json.RawMessage(raw),
				}

				select {
				case out <- event:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	return out, nil
}

func (r *StdioRunner) Stop() error {
	return r.executor.Stop()
}
