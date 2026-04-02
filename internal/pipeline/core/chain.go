package core

import (
	"context"

	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	"github.com/haolipeng/LLM-Scope/internal/event"
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

func (c chain) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	out := in
	for _, a := range c.analyzers {
		out = a.Process(ctx, out)
	}
	return out
}
