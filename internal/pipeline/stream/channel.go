package stream

import (
	"context"

	pipelinetypes "github.com/haolipeng/LLM-Scope/internal/pipeline/types"
	"github.com/haolipeng/LLM-Scope/internal/event"
)

// ChannelRunner 将已有事件流包装成一个 Runner。
type ChannelRunner struct {
	name   string
	stream <-chan *event.Event
}

func FromChannel(name string, stream <-chan *event.Event) pipelinetypes.Runner {
	return &ChannelRunner{name: name, stream: stream}
}

func (c *ChannelRunner) ID() string {
	return c.name
}

func (c *ChannelRunner) Name() string {
	return c.name
}

func (c *ChannelRunner) Run(ctx context.Context) (<-chan *event.Event, error) {
	out := make(chan *event.Event)
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
