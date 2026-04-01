package stream

import (
	"context"

	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// CombinedRunner 将多个 Runner 合并为单一事件流。
type CombinedRunner struct {
	runners []pipelinetypes.Runner
}

func NewCombinedRunner(runners ...pipelinetypes.Runner) *CombinedRunner {
	return &CombinedRunner{runners: runners}
}

func (c *CombinedRunner) ID() string {
	return "combined"
}

func (c *CombinedRunner) Name() string {
	return "combined"
}

func (c *CombinedRunner) Run(ctx context.Context) (<-chan *runtimeevent.Event, error) {
	streams := make([]<-chan *runtimeevent.Event, 0, len(c.runners))
	for _, runner := range c.runners {
		stream, err := runner.Run(ctx)
		if err != nil {
			return nil, err
		}
		streams = append(streams, stream)
	}
	return MergeStreams(ctx, streams...), nil
}

func (c *CombinedRunner) Stop() error {
	for _, runner := range c.runners {
		_ = runner.Stop()
	}
	return nil
}
