package stream

import (
	"context"

	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// ChannelRunner 将已有事件流包装成一个 Runner。
type ChannelRunner struct {
	name   string
	stream <-chan *runtimeevent.Event
}

func FromChannel(name string, stream <-chan *runtimeevent.Event) pipelinetypes.Runner {
	return &ChannelRunner{name: name, stream: stream}
}

func (c *ChannelRunner) ID() string {
	return c.name
}

func (c *ChannelRunner) Name() string {
	return c.name
}

func (c *ChannelRunner) Run(ctx context.Context) (<-chan *runtimeevent.Event, error) {
	out := make(chan *runtimeevent.Event)
	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-c.stream:
				if !ok {
					return
				}
				out <- event
			}
		}
	}()

	return out, nil
}

func (c *ChannelRunner) Stop() error {
	return nil
}
