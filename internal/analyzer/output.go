package analyzer

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/eunomia-bpf/agentsight/internal/core"
)

// Output writes events as JSON to stdout.
type Output struct{}

func NewOutput() *Output {
	return &Output{}
}

func (o *Output) Name() string {
	return "output"
}

func (o *Output) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
	out := make(chan *core.Event)

	go func() {
		defer close(out)
		encoder := json.NewEncoder(ConsoleWriter{})

		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-in:
				if !ok {
					return
				}
				if err := encoder.Encode(event); err != nil {
					fmt.Printf("{\"error\":%q}\n", err.Error())
				}
				out <- event
			}
		}
	}()

	return out
}

type ConsoleWriter struct{}

func (ConsoleWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
