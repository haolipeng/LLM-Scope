package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/eunomia-bpf/agentsight/internal/core"
)

// ProcessConfig configures the process runner.
type ProcessConfig struct {
	Args []string
}

// ProcessRunner executes the process binary and converts JSON output to Events.
type ProcessRunner struct {
	config   ProcessConfig
	executor *BinaryExecutor
}

func NewProcessRunner(config ProcessConfig) *ProcessRunner {
	binaryPath := "bpf/process"
	return &ProcessRunner{
		config:   config,
		executor: NewBinaryExecutor(binaryPath, config.Args).WithRunnerName("Process"),
	}
}

func (r *ProcessRunner) ID() string {
	return "process"
}

func (r *ProcessRunner) Name() string {
	return "process"
}

func (r *ProcessRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
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
					Timestamp int64  `json:"timestamp"`
					PID       uint32 `json:"pid"`
					Comm      string `json:"comm"`
				}

				if err := json.Unmarshal(raw, &header); err != nil {
					fmt.Fprintf(os.Stderr, "process runner: failed to parse event header: %v\n", err)
					continue
				}

				event := &core.Event{
					TimestampNs:     header.Timestamp,
					TimestampUnixMs: core.BootNsToUnixMs(header.Timestamp),
					Source:          "process",
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

func (r *ProcessRunner) Stop() error {
	return r.executor.Stop()
}
