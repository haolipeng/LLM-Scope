package runner

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/core"
)

// FakeRunner generates simulated SSL request/response event pairs for testing.
type FakeRunner struct {
	eventCount int
	delay      time.Duration
}

// NewFakeRunner creates a new FakeRunner with the given event count and delay.
func NewFakeRunner(eventCount int, delay time.Duration) *FakeRunner {
	if eventCount <= 0 {
		eventCount = 5
	}
	if delay <= 0 {
		delay = 100 * time.Millisecond
	}
	return &FakeRunner{
		eventCount: eventCount,
		delay:      delay,
	}
}

func (r *FakeRunner) ID() string {
	return "fake"
}

func (r *FakeRunner) Name() string {
	return "fake"
}

func (r *FakeRunner) Run(ctx context.Context) (<-chan *core.Event, error) {
	out := make(chan *core.Event, 100)

	go func() {
		defer close(out)

		for i := 0; i < r.eventCount; i++ {
			select {
			case <-ctx.Done():
				return
			default:
			}

			// Generate request event
			reqEvent := r.generateRequest(i)
			select {
			case out <- reqEvent:
			case <-ctx.Done():
				return
			}

			time.Sleep(r.delay)

			// Generate response event
			respEvent := r.generateResponse(i)
			select {
			case out <- respEvent:
			case <-ctx.Done():
				return
			}

			time.Sleep(r.delay)
		}
	}()

	return out, nil
}

func (r *FakeRunner) Stop() error {
	return nil
}

func (r *FakeRunner) generateRequest(index int) *core.Event {
	timestamp := int64(getBootTimeNs())
	pid := uint32(1000 + rand.Intn(9000))
	tid := uint64(pid) + uint64(rand.Intn(100))

	paths := []string{
		"/v1/chat/completions",
		"/v1/messages",
		"/v1/completions",
		"/api/generate",
	}
	hosts := []string{
		"api.openai.com",
		"api.anthropic.com",
		"api.cohere.com",
	}

	path := paths[index%len(paths)]
	host := hosts[index%len(hosts)]

	body := fmt.Sprintf(`{"model":"gpt-4","messages":[{"role":"user","content":"Hello, this is test message %d"}],"stream":true}`, index)

	httpRequest := fmt.Sprintf("POST %s HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\nAuthorization: Bearer sk-fake-key-1234\r\nContent-Length: %d\r\n\r\n%s",
		path, host, len(body), body)

	payload := map[string]interface{}{
		"pid":          pid,
		"tid":          tid,
		"uid":          0,
		"timestamp_ns": timestamp,
		"comm":         "python3",
		"len":          len(httpRequest),
		"data":         httpRequest,
		"function":     "SSL_write",
		"is_handshake": false,
	}

	data, _ := json.Marshal(payload)

	return &core.Event{
		TimestampNs:     timestamp,
		TimestampUnixMs: core.BootNsToUnixMs(timestamp),
		Source:          "ssl",
		PID:             pid,
		Comm:            "python3",
		Data:            data,
	}
}

func (r *FakeRunner) generateResponse(index int) *core.Event {
	timestamp := int64(getBootTimeNs())
	pid := uint32(1000 + rand.Intn(9000))
	tid := uint64(pid) + uint64(rand.Intn(100))

	body := fmt.Sprintf(`{"id":"chatcmpl-fake%d","object":"chat.completion","created":%d,"model":"gpt-4","choices":[{"index":0,"message":{"role":"assistant","content":"This is a fake response for test message %d."},"finish_reason":"stop"}]}`,
		index, time.Now().Unix(), index)

	httpResponse := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s",
		len(body), body)

	payload := map[string]interface{}{
		"pid":          pid,
		"tid":          tid,
		"uid":          0,
		"timestamp_ns": timestamp,
		"comm":         "python3",
		"len":          len(httpResponse),
		"data":         httpResponse,
		"function":     "SSL_read",
		"is_handshake": false,
	}

	data, _ := json.Marshal(payload)

	return &core.Event{
		TimestampNs:     timestamp,
		TimestampUnixMs: core.BootNsToUnixMs(timestamp),
		Source:          "ssl",
		PID:             pid,
		Comm:            "python3",
		Data:            data,
	}
}
