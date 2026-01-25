package runner

import (
    "context"

    "github.com/eunomia-bpf/agentsight/internal/core"
)

// Runner produces events from a data source (eBPF binary, /proc, etc.).
type Runner interface {
    Name() string
    Run(ctx context.Context) (<-chan *core.Event, error)
    Stop() error
}

// Config captures common runner settings.
type Config struct {
    BinaryPath string
    Args       []string
    Comm       string
    PID        int
}
