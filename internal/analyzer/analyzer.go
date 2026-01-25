package analyzer

import (
	"context"

	"github.com/eunomia-bpf/agentsight/internal/core"
)

// Analyzer processes events and emits transformed events.
type Analyzer interface {
	Name() string
	Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event
}

type chain struct {
	analyzers []Analyzer
}

// Chain composes multiple analyzers in order.
func Chain(analyzers ...Analyzer) Analyzer {
	return chain{analyzers: analyzers}
}

func (c chain) Name() string {
	return "chain"
}

func (c chain) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
	out := in
	for _, analyzer := range c.analyzers {
		out = analyzer.Process(ctx, out)
	}
	return out
}
