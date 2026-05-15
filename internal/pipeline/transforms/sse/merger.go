package sse

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
	transforms "github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
)

// SSEMerger merges SSE fragments into a single event.
type SSEMerger struct {
	timeout time.Duration
	mu      sync.Mutex
	buffers map[string]*sseAccumulator
	inner   *transforms.StatefulAnalyzer
}

func NewSSEMerger() *SSEMerger {
	return NewSSEMergerWithTimeout(30 * time.Second)
}

func NewSSEMergerWithTimeout(timeout time.Duration) *SSEMerger {
	s := &SSEMerger{
		timeout: timeout,
		buffers: make(map[string]*sseAccumulator),
	}
	s.inner = transforms.NewStatefulAnalyzer("sse_merger", transforms.StatefulOpts{
		TickInterval: timeout,
		OnEvent: func(ev *event.Event, emit func(*event.Event)) {
			if ev.Source != "ssl" {
				emit(ev)
				return
			}
			s.handleEvent(ev, emit)
		},
		OnTick: func(emit func(*event.Event)) {
			s.flushExpired(emit)
		},
		OnClose: func(emit func(*event.Event)) {
			s.flushAll(emit)
		},
	})
	return s
}

func (s *SSEMerger) Name() string {
	return "sse_merger"
}

func (s *SSEMerger) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	return s.inner.Process(ctx, in)
}

func (s *SSEMerger) handleEvent(event *event.Event, emit func(*event.Event)) {
	var payload map[string]interface{}
	if err := json.Unmarshal(event.Data, &payload); err != nil {
		emit(event)
		return
	}

	data, _ := payload["data"].(string)
	if data == "" || !isSSEData(data) {
		emit(event)
		return
	}

	sseEvents := parseSSEEvents(data)
	if len(sseEvents) == 0 {
		emit(event)
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
		emit(event)
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
		s.tryComplete(key, acc, event, emit)
	}
}

func (s *SSEMerger) tryComplete(key string, acc *sseAccumulator, ev *event.Event, emit func(*event.Event)) {
	if acc.hasMeaningfulContent() {
		merged := acc.toEvent(ev)
		s.mu.Lock()
		delete(s.buffers, key)
		s.mu.Unlock()
		if merged != nil {
			emit(merged)
		}
		return
	}
	s.mu.Lock()
	delete(s.buffers, key)
	s.mu.Unlock()
}

func (s *SSEMerger) flushAll(emit func(*event.Event)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for key, acc := range s.buffers {
		if acc.hasMeaningfulContent() {
			event := acc.toEvent(nil)
			if event != nil {
				emit(event)
			}
		}
		delete(s.buffers, key)
	}
}

func (s *SSEMerger) flushExpired(emit func(*event.Event)) {
	now := time.Now()
	s.mu.Lock()
	for key, acc := range s.buffers {
		if now.Sub(acc.lastUpdate) >= s.timeout {
			if acc.hasMeaningfulContent() {
				event := acc.toEvent(nil)
				if event != nil {
					emit(event)
				}
			}
			delete(s.buffers, key)
		}
	}
	s.mu.Unlock()
}

func (s *SSEMerger) connectionID(event *event.Event, events []sseEvent, payload map[string]interface{}) (string, string) {
	pid := event.PID
	tid := getUint64(payload["tid"])
	msgID := extractMessageID(events)

	window := event.TimestampNs / 600_000_000_000
	return fmt.Sprintf("%d:%d:%d", pid, tid, window), msgID
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
	if parsed, ok := transforms.ToUint64(value); ok {
		return parsed
	}
	return 0
}
