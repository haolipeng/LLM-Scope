package runner

import (
	"context"

	"github.com/eunomia-bpf/agentsight/internal/core"
)

// channelRunner wraps an existing event stream as a Runner.
type channelRunner struct {
	name   string
	stream <-chan *core.Event
}

func FromChannel(name string, stream <-chan *core.Event) Runner {
	return &channelRunner{name: name, stream: stream}
}

func (c *channelRunner) Name() string {
	return c.name
}

func (c *channelRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	out := make(chan *core.Event)
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

func (c *channelRunner) Stop() error {
	return nil
}
