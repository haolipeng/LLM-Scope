package transforms

import (
	"context"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"strings"
	"sync"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

type toolCallConfig struct {
	idleGap time.Duration
	maxSpan time.Duration
}

type toolCallKey struct {
	pid      uint32
	tid      uint32
	toolName string
	keyField string
}

type toolCallState struct {
	key         toolCallKey
	startNs     int64
	lastNs      int64
	bytes       int64
	argsHash    string
	argsSummary string
	comm        string
}

// ToolCallAggregator converts low-level eBPF events into tool_call_* spans.
type ToolCallAggregator struct {
	cfg        toolCallConfig
	mu         sync.Mutex
	live       map[toolCallKey]*toolCallState
	extractors map[string]toolCallExtractor
	inner      *statefulAnalyzer
}

func NewToolCallAggregator() *ToolCallAggregator {
	t := &ToolCallAggregator{
		cfg: toolCallConfig{
			idleGap: 1 * time.Second,
			maxSpan: 60 * time.Second,
		},
		live:       make(map[toolCallKey]*toolCallState),
		extractors: make(map[string]toolCallExtractor),
	}
	t.extractors["process"] = &processToolCallExtractor{}
	t.extractors["http_parser"] = &httpToolCallExtractor{}
	t.inner = NewStatefulAnalyzer("tool_call_aggregator", StatefulOpts{
		TickInterval: t.cfg.idleGap,
		OnEvent: func(ev *event.Event, emit func(*event.Event)) {
			extractor, ok := t.extractors[ev.Source]
			if !ok {
				emit(ev)
				return
			}
			extractions := extractor.Extract(ev.Data)
			if len(extractions) == 0 {
				emit(ev)
				return
			}
			t.handleExtractions(ev, extractions, emit)
		},
		OnTick: func(emit func(*event.Event)) {
			t.flushExpired(emit, time.Now())
		},
		OnClose: func(emit func(*event.Event)) {
			t.flushAll(emit)
		},
	})
	return t
}

func (t *ToolCallAggregator) Name() string {
	return "tool_call_aggregator"
}

func (t *ToolCallAggregator) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	return t.inner.Process(ctx, in)
}

func (t *ToolCallAggregator) flushAll(emit func(*event.Event)) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, state := range t.live {
		emit(t.finishState(state, "timeout", "flush"))
	}
	t.live = make(map[toolCallKey]*toolCallState)
}

func (t *ToolCallAggregator) flushExpired(emit func(*event.Event), now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()

	cutoff := now.Add(-t.cfg.idleGap)
	for key, state := range t.live {
		last := event.BootNsToTime(state.lastNs)
		if last.Before(cutoff) {
			emit(t.finishState(state, "timeout", "idle_gap"))
			delete(t.live, key)
		}
	}
}

func (t *ToolCallAggregator) handleExtractions(ev *event.Event, extractions []toolCallExtraction, emit func(*event.Event)) {
	for _, ex := range extractions {
		state, isNew, rolled := t.startOrUpdate(ev, ex.toolName, ex.keyField, ex.argsSummary, ex.bytes)
		if rolled != nil {
			emit(rolled)
		}
		if isNew {
			emit(t.startEvent(ev, state))
		}
		if ex.immediate {
			emit(t.finishState(state, "success", "exec"))
			t.removeState(state.key)
		}
	}
}

func (t *ToolCallAggregator) startOrUpdate(event *event.Event, toolName, keyField, argsSummary string, bytes int64) (*toolCallState, bool, *event.Event) {
	tid := extractTid(event)
	key := toolCallKey{
		pid:      event.PID,
		tid:      tid,
		toolName: toolName,
		keyField: keyField,
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if existing, ok := t.live[key]; ok {
		maxNs := existing.startNs + int64(t.cfg.maxSpan)
		if event.TimestampNs > maxNs {
			rolled := t.finishState(existing, "timeout", "max_span")
			delete(t.live, key)
			state := &toolCallState{
				key:         key,
				startNs:     event.TimestampNs,
				lastNs:      event.TimestampNs,
				bytes:       bytes,
				argsSummary: argsSummary,
				argsHash:    hashArgs(argsSummary),
				comm:        event.Comm,
			}
			t.live[key] = state
			return state, true, rolled
		}
		existing.lastNs = event.TimestampNs
		if bytes > 0 {
			existing.bytes += bytes
		}
		return existing, false, nil
	}

	state := &toolCallState{
		key:         key,
		startNs:     event.TimestampNs,
		lastNs:      event.TimestampNs,
		bytes:       bytes,
		argsSummary: argsSummary,
		argsHash:    hashArgs(argsSummary),
		comm:        event.Comm,
	}
	t.live[key] = state
	return state, true, nil
}

func (t *ToolCallAggregator) removeState(key toolCallKey) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.live, key)
}

func (t *ToolCallAggregator) startEvent(event *event.Event, state *toolCallState) *event.Event {
	payload := map[string]interface{}{
		"tool_name":    state.key.toolName,
		"args_summary": state.argsSummary,
		"args_hash":    state.argsHash,
		"key_field":    state.key.keyField,
		"tid":          state.key.tid,
	}
	return newToolCallEvent(event, "tool_call_start", payload)
}

func (t *ToolCallAggregator) finishState(state *toolCallState, status, reason string) *event.Event {
	payload := map[string]interface{}{
		"event_type":  "tool_call_end",
		"tool_name":   state.key.toolName,
		"status":      status,
		"reason":      reason,
		"duration_ms": nsToMs(state.lastNs - state.startNs),
		"bytes":       state.bytes,
		"args_hash":   state.argsHash,
		"key_field":   state.key.keyField,
		"tid":         state.key.tid,
	}
	return &event.Event{
		TimestampNs:     state.lastNs,
		TimestampUnixMs: event.BootNsToUnixMs(state.lastNs),
		Source:          "tool_call",
		PID:             state.key.pid,
		Comm:            state.comm,
		Data:            mustJSON(payload),
	}
}

func newToolCallEvent(original *event.Event, eventType string, payload map[string]interface{}) *event.Event {
	payload["event_type"] = eventType
	return &event.Event{
		TimestampNs:     original.TimestampNs,
		TimestampUnixMs: original.TimestampUnixMs,
		Source:          "tool_call",
		PID:             original.PID,
		Comm:            original.Comm,
		Data:            mustJSON(payload),
	}
}

func classifyFileTool(flags uint64) string {
	if flags&0x3 == 0 {
		return "fs.read"
	}
	return "fs.write"
}

func extractTid(event *event.Event) uint32 {
	if event.Source == "process" {
		return 0
	}
	if event.Source == "http_parser" {
		var payload map[string]interface{}
		if err := json.Unmarshal(event.Data, &payload); err != nil {
			return 0
		}
		if value, ok := toUint64(payload["tid"]); ok {
			return uint32(value)
		}
	}
	return 0
}

func hashArgs(value string) string {
	h := fnv.New64a()
	_, _ = h.Write([]byte(value))
	return fmt.Sprintf("%x", h.Sum64())
}

func nsToMs(ns int64) int64 {
	if ns <= 0 {
		return 0
	}
	return ns / int64(time.Millisecond)
}

func getStringValue(value interface{}, fallback string) string {
	if value == nil {
		return fallback
	}
	if s, ok := value.(string); ok {
		return strings.TrimSpace(s)
	}
	return fallback
}

func mustJSON(payload map[string]interface{}) json.RawMessage {
	encoded, err := json.Marshal(payload)
	if err != nil {
		return json.RawMessage("{}")
	}
	return encoded
}
