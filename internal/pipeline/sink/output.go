package sink

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// Output 将事件以 JSON 形式输出到标准输出。
type Output struct{}

func NewOutput() *Output {
	return &Output{}
}

func (o *Output) Name() string {
	return "output"
}

func (o *Output) Consume(ctx context.Context, in <-chan *event.Event) {
	encoder := json.NewEncoder(ConsoleWriter{})
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-in:
			if !ok {
				return
			}
			normalized := normalizeBinaryForOutput(evt)
			if err := encoder.Encode(normalized); err != nil {
				fmt.Printf("{\"error\":%q}\n", err.Error())
			}
		}
	}
}

func normalizeBinaryForOutput(evt *event.Event) *event.Event {
	var data map[string]interface{}
	if err := json.Unmarshal(evt.Data, &data); err != nil {
		return evt
	}

	value, ok := data["data"].(string)
	if !ok {
		return evt
	}

	converted := dataToString(value)
	if converted == value {
		return evt
	}

	data["data"] = converted
	updated, err := json.Marshal(data)
	if err != nil {
		return evt
	}

	return &event.Event{
		TimestampNs:     evt.TimestampNs,
		TimestampUnixMs: evt.TimestampUnixMs,
		Source:          evt.Source,
		PID:             evt.PID,
		Comm:            evt.Comm,
		Data:            updated,
	}
}

type ConsoleWriter struct{}

func (ConsoleWriter) Write(p []byte) (int, error) {
	return fmt.Print(string(p))
}
