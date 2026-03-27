package runner

import (
	"context"
	"sync"

	"github.com/haolipeng/LLM-Scope/internal/core"
)

// CombinedRunner merges multiple runners into a single event stream.
type CombinedRunner struct {
	runners []Runner
}

func NewCombinedRunner(runners ...Runner) *CombinedRunner {
	return &CombinedRunner{runners: runners}
}

func (c *CombinedRunner) ID() string {
	return "combined"
}

func (c *CombinedRunner) Name() string {
	return "combined"
}

func (c *CombinedRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	out := make(chan *core.Event, 100)
	var wg sync.WaitGroup

	for _, runner := range c.runners {
		stream, err := runner.Run(ctx)
		if err != nil {
			return nil, err
		}

		wg.Add(1)
		go func(ch <-chan *core.Event) {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case event, ok := <-ch:
					if !ok {
						return
					}
					select {
					case out <- event:
					case <-ctx.Done():
						return
					}
				}
			}
		}(stream)
	}

	go func() {
		wg.Wait()
		close(out)
	}()

	return out, nil
}

func (c *CombinedRunner) Stop() error {
	for _, runner := range c.runners {
		_ = runner.Stop()
	}
	return nil
}
