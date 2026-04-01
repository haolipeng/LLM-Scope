package transforms

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// SSEMerger merges SSE fragments into a single event.
type SSEMerger struct {
	timeout time.Duration
	mu      sync.Mutex
	buffers map[string]*sseAccumulator
}

func NewSSEMerger() *SSEMerger {
	return NewSSEMergerWithTimeout(30 * time.Second)
}

func NewSSEMergerWithTimeout(timeout time.Duration) *SSEMerger {
	return &SSEMerger{
		timeout: timeout,
		buffers: make(map[string]*sseAccumulator),
	}
}

func (s *SSEMerger) Name() string {
	return "sse_merger"
}

func (s *SSEMerger) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
	out := make(chan *runtimeevent.Event)

	go func() {
		defer close(out)
		ticker := time.NewTicker(s.timeout)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				s.flushAll(out)
				return
			case <-ticker.C:
				s.flushExpired(out)
			case event, ok := <-in:
				if !ok {
					s.flushAll(out)
					return
				}
				if event.Source != "ssl" {
					out <- event
					continue
				}
				s.handleEvent(event, out)
			}
		}
	}()

	return out
}

func (s *SSEMerger) handleEvent(event *runtimeevent.Event, out chan<- *runtimeevent.Event) {
	var payload map[string]interface{}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		out <- event
		return
	}

	data, _ := payload["data"].(string)
	if data == "" || !isSSEData(data) {
		out <- event
		return
	}

	sseEvents := parseSSEEvents(data)
	if len(sseEvents) == 0 {
		out <- event
		return
	}

	allMetadata := true
	for _, e := range sseEvents {
		if !isMetadataOnlyChunk(e) {
			allMetadata = false
			break
		}
	}
	if allMetadata {
		return
	}

	key, messageID := s.connectionID(event, sseEvents, payload)
	if key == "" {
		out <- event
		return
	}

	s.mu.Lock()
	acc, ok := s.buffers[key]
	if !ok {
		acc = &sseAccumulator{
			connectionID: key,
			messageID:    messageID,
			startTime:    event.TimestampNs,
			function:     getString(payload["function"], "unknown"),
			tid:          getUint64(payload["tid"]),
		}
		s.buffers[key] = acc
	}
	if acc.messageID == "" {
		acc.messageID = messageID
	}
	acc.update(event.TimestampNs, sseEvents)
	completed := acc.isComplete()
	s.mu.Unlock()

	if completed {
		if acc.hasMeaningfulContent() {
			merged := acc.toEvent(event)
			s.mu.Lock()
			delete(s.buffers, key)
			s.mu.Unlock()
			if merged != nil {
				out <- merged
			}
		} else {
			s.mu.Lock()
			delete(s.buffers, key)
			s.mu.Unlock()
		}
	}
}

func (s *SSEMerger) flushAll(out chan<- *runtimeevent.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, acc := range s.buffers {
		if acc.hasMeaningfulContent() {
			event := acc.toEvent(nil)
			if event != nil {
				out <- event
			}
		}
		delete(s.buffers, key)
	}
}

func (s *SSEMerger) flushExpired(out chan<- *runtimeevent.Event) {
	now := time.Now()
	s.mu.Lock()
	for key, acc := range s.buffers {
		if now.Sub(acc.lastUpdate) >= s.timeout {
			if acc.hasMeaningfulContent() {
				event := acc.toEvent(nil)
				if event != nil {
					out <- event
				}
			}
			delete(s.buffers, key)
		}
	}
	s.mu.Unlock()
}

func (s *SSEMerger) connectionID(event *runtimeevent.Event, events []sseEvent, payload map[string]interface{}) (string, string) {
	pid := event.PID
	tid := getUint64(payload["tid"])

	if msgID := extractMessageID(events); msgID != "" {
		return fmt.Sprintf("%d:%d:%s", pid, tid, msgID), msgID
	}

	window := event.TimestampNs / 600_000_000_000
	return fmt.Sprintf("%d:%d:%d", pid, tid, window), ""
}

func emptyToNil(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}

func getString(value interface{}, fallback string) string {
	if value == nil {
		return fallback
	}
	if s, ok := value.(string); ok {
		return s
	}
	return fallback
}

func getUint64(value interface{}) uint64 {
	if value == nil {
		return 0
	}
	if parsed, ok := toUint64(value); ok {
		return parsed
	}
	return 0
}
