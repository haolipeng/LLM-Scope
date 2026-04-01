package sink

import (
	"context"
	"encoding/json"
	"fmt"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// Output 将事件以 JSON 形式输出到标准输出。
type Output struct{}

func NewOutput() *Output {
	return &Output{}
}

func (o *Output) Name() string {
	return "output"
}

func (o *Output) Consume(ctx context.Context, in <-chan *runtimeevent.Event) {
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
		}
	}
}

func normalizeBinaryForOutput(event *runtimeevent.Event) *runtimeevent.Event {
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

	return &runtimeevent.Event{
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
