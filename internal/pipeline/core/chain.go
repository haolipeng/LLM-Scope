package core

import (
	"context"

	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

type chain struct {
	analyzers []pipelinetypes.Analyzer
}

// Chain 按顺序串联多个 Analyzer。
func Chain(analyzers ...pipelinetypes.Analyzer) pipelinetypes.Analyzer {
	return chain{analyzers: analyzers}
}

func (c chain) Name() string {
	return "chain"
}

func (c chain) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
	out := in
	for _, a := range c.analyzers {
		out = a.Process(ctx, out)
	}
	return out
}
