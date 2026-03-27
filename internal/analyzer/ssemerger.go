package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/core"
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

func (s *SSEMerger) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
	out := make(chan *core.Event)

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

func (s *SSEMerger) handleEvent(event *core.Event, out chan<- *core.Event) {
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

	// Skip metadata-only chunks
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

func (s *SSEMerger) flushAll(out chan<- *core.Event) {
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

func (s *SSEMerger) flushExpired(out chan<- *core.Event) {
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

type sseAccumulator struct {
	connectionID    string
	messageID       string
	events          []sseEvent
	accumulatedText string
	accumulatedJSON string
	hasMessageStart bool
	startTime       int64
	endTime         int64
	lastUpdate      time.Time
	function        string
	tid             uint64
}

func (a *sseAccumulator) update(timestamp int64, events []sseEvent) {
	if a.startTime == 0 {
		a.startTime = timestamp
	}
	a.endTime = timestamp
	a.lastUpdate = time.Now()

	for _, event := range events {
		a.events = append(a.events, event)
		if event.Event == "message_start" {
			a.hasMessageStart = true
		}
		if event.Event == "content_block_delta" && event.ParsedData != nil {
			a.accumulateContentDelta(event.ParsedData)
		}
	}

	if a.messageID == "" {
		a.messageID = extractMessageID(events)
	}
}

// accumulateContentDelta extracts text and partial_json from a content_block_delta event,
// matching the Rust SSEProcessor::accumulate_content logic.
func (a *sseAccumulator) accumulateContentDelta(parsedData map[string]interface{}) {
	delta, ok := parsedData["delta"].(map[string]interface{})
	if !ok {
		return
	}

	deltaType, _ := delta["type"].(string)

	switch deltaType {
	case "text_delta":
		if text, ok := delta["text"].(string); ok && text != "" {
			a.accumulatedText += text
		}
	case "thinking_delta":
		if thinking, ok := delta["thinking"].(string); ok && thinking != "" {
			a.accumulatedText += thinking
		}
	}

	// Handle partial_json (for tool_use content blocks)
	if partialJSON, ok := delta["partial_json"].(string); ok && partialJSON != "" {
		a.accumulatedJSON += partialJSON
	}
}

func (a *sseAccumulator) isComplete() bool {
	for _, event := range a.events {
		if event.Event == "message_stop" || event.Event == "error" {
			return true
		}
	}

	if len(a.accumulatedText) > 50000 || len(a.accumulatedJSON) > 50000 {
		return true
	}

	return false
}

// hasMeaningfulContent checks whether the accumulated content has
// meaningful data. A stream is meaningful if it has text/json content,
// or if it contains a complete message (message_start was seen).
func (a *sseAccumulator) hasMeaningfulContent() bool {
	if a.hasMessageStart {
		return true
	}
	if strings.TrimSpace(a.accumulatedJSON) != "" {
		return true
	}
	if strings.TrimSpace(a.accumulatedText) != "" {
		return true
	}
	return false
}

// isMetadataOnlyChunk identifies SSE events that are purely ping or metadata.
func isMetadataOnlyChunk(e sseEvent) bool {
	if e.Event == "ping" || e.Event == "heartbeat" {
		return true
	}
	if e.Data == "" && e.Event == "" {
		return true
	}
	trimmed := strings.TrimSpace(e.Data)
	if trimmed == "" || trimmed == ":" || trimmed == ": " {
		return true
	}
	return false
}

func (a *sseAccumulator) toEvent(original *core.Event) *core.Event {
	if len(a.events) == 0 {
		return nil
	}

	jsonContent := a.accumulatedJSON
	if jsonContent != "" {
		var parsed map[string]interface{}
		if err := json.Unmarshal([]byte(jsonContent), &parsed); err == nil {
			if pretty, err := json.MarshalIndent(parsed, "", "  "); err == nil {
				jsonContent = string(pretty)
			}
		}
	}

	payload := map[string]interface{}{
		"connection_id":     a.connectionID,
		"message_id":        emptyToNil(a.messageID),
		"start_time":        a.startTime,
		"end_time":          a.endTime,
		"duration_ns":       a.endTime - a.startTime,
		"original_source":   "ssl",
		"function":          a.function,
		"tid":               a.tid,
		"json_content":      jsonContent,
		"text_content":      a.accumulatedText,
		"total_size":        len(jsonContent) + len(a.accumulatedText),
		"event_count":       len(a.events),
		"has_message_start": a.hasMessageStart,
		"sse_events":        a.events,
	}

	data, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	event := &core.Event{
		TimestampNs:     a.endTime,
		TimestampUnixMs: core.BootNsToUnixMs(a.endTime),
		Source:          "sse_processor",
		Data:            data,
	}

	if original != nil {
		event.PID = original.PID
		event.Comm = original.Comm
	}

	return event
}

type sseEvent struct {
	Event      string                 `json:"event,omitempty"`
	Data       string                 `json:"data,omitempty"`
	ID         string                 `json:"id,omitempty"`
	ParsedData map[string]interface{} `json:"parsed_data,omitempty"`
	RawData    string                 `json:"raw_data,omitempty"`
}

func isSSEData(data string) bool {
	hasPatterns := strings.Contains(data, "event:") && strings.Contains(data, "data:")
	hasContentType := strings.Contains(data, "text/event-stream")
	hasChunked := strings.Contains(data, "Transfer-Encoding: chunked") && (strings.Contains(data, "event:") || strings.Contains(data, "data:"))
	hasDataOnly := strings.Contains(data, "data:") && (strings.Contains(data, "\r\n\r\n") || strings.Contains(data, "\n\n"))

	return hasPatterns || hasContentType || hasChunked || hasDataOnly
}

func parseSSEEvents(data string) []sseEvent {
	clean := cleanChunkedContent(data)
	return parseSSEEventsFromChunk(clean)
}

func parseSSEEventsFromChunk(chunk string) []sseEvent {
	blocks := strings.Split(chunk, "\n\n")
	events := make([]sseEvent, 0, len(blocks))

	for _, block := range blocks {
		if strings.TrimSpace(block) == "" {
			continue
		}

		event := sseEvent{}
		var dataLines []string

		for _, line := range strings.Split(block, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "event:"):
				event.Event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			case strings.HasPrefix(line, "data:"):
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			case strings.HasPrefix(line, "id:"):
				event.ID = strings.TrimSpace(strings.TrimPrefix(line, "id:"))
			}
		}

		if len(dataLines) > 0 {
			combined := strings.Join(dataLines, "\n")
			event.Data = combined
			var parsed map[string]interface{}
			if err := json.Unmarshal([]byte(combined), &parsed); err == nil {
				event.ParsedData = parsed
			} else {
				event.RawData = combined
			}
		}

		if event.Event != "" || event.Data != "" {
			events = append(events, event)
		}
	}

	return events
}

func cleanChunkedContent(content string) string {
	lines := strings.Split(content, "\r\n")
	var parts []string
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		if isHex(line) {
			if i+1 < len(lines) {
				parts = append(parts, lines[i+1])
				i++
			}
			continue
		}
	}
	return strings.Join(parts, "\n")
}

func isHex(value string) bool {
	for _, r := range value {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return false
		}
	}
	return value != ""
}

func extractMessageID(events []sseEvent) string {
	for _, event := range events {
		if event.Event != "message_start" || event.ParsedData == nil {
			continue
		}
		msg, ok := event.ParsedData["message"].(map[string]interface{})
		if !ok {
			continue
		}
		if id, ok := msg["id"].(string); ok {
			return id
		}
	}
	return ""
}

func (s *SSEMerger) connectionID(event *core.Event, events []sseEvent, payload map[string]interface{}) (string, string) {
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
