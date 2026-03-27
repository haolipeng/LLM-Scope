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
				normalized := normalizeBinaryForOutput(event)
				if err := encoder.Encode(normalized); err != nil {
					fmt.Printf("{\"error\":%q}\n", err.Error())
				}
				// Pass original event (unmodified) to downstream
				out <- event
			}
		}
	}()

	return out
}

// normalizeBinaryForOutput creates a copy of the event with binary data converted to HEX for display.
func normalizeBinaryForOutput(event *core.Event) *core.Event {
	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return event
	}

	value, ok := data["data"].(string)
	if !ok {
		return event
	}

	converted := dataToString(value)
	if converted == value {
		return event
	}

	data["data"] = converted
	updated, err := json.Marshal(data)
	if err != nil {
		return event
	}

	return &core.Event{
		TimestampNs:     event.TimestampNs,
		TimestampUnixMs: event.TimestampUnixMs,
		Source:          event.Source,
		PID:             event.PID,
		Comm:            event.Comm,
		Data:            updated,
	}
}

type ConsoleWriter struct{}

func (ConsoleWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
