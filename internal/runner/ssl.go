package runner

import (
    "context"
    "encoding/json"
    "fmt"
    "os"

    "github.com/eunomia-bpf/agentsight/internal/core"
)

// SSLConfig configures the SSL runner.
type SSLConfig struct {
    BinaryPath string
    Args       []string
}

// SSLRunner executes the sslsniff binary and converts JSON output to Events.
type SSLRunner struct {
    config   SSLConfig
    executor *BinaryExecutor
}

func NewSSLRunner(config SSLConfig) *SSLRunner {
    binaryPath := config.BinaryPath
    if binaryPath == "" {
        binaryPath = "bpf/sslsniff"
    }

    return &SSLRunner{
        config:   config,
        executor: NewBinaryExecutor(binaryPath, config.Args),
    }
}

func (r *SSLRunner) Name() string {
    return "ssl"
}

func (r *SSLRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
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
                    fmt.Fprintf(os.Stderr, "ssl runner: failed to parse event header: %v\n", err)
                    continue
                }

                event := &core.Event{
                    TimestampNs:     header.TimestampNs,
                    TimestampUnixMs: core.BootNsToUnixMs(header.TimestampNs),
                    Source:          "ssl",
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

func (r *SSLRunner) Stop() error {
    return r.executor.Stop()
}
