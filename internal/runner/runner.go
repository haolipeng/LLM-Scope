package runner

import (
    "context"

    "github.com/haolipeng/LLM-Scope/internal/core"
)

// Runner produces events from a data source (eBPF binary, /proc, etc.).
type Runner interface {
    ID() string
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
