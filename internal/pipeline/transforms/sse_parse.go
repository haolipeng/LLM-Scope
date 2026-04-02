package transforms

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

type sseEvent struct {
	Event      string                 `json:"event,omitempty"`
	Data       string                 `json:"data,omitempty"`
	ID         string                 `json:"id,omitempty"`
	ParsedData map[string]interface{} `json:"parsed_data,omitempty"`
	RawData    string                 `json:"raw_data,omitempty"`
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

func (a *sseAccumulator) toEvent(original *event.Event) *event.Event {
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

	event := &event.Event{
		TimestampNs:     a.endTime,
		TimestampUnixMs: event.BootNsToUnixMs(a.endTime),
		Source:          "sse_processor",
		Data:            data,
	}
	if original != nil {
		event.PID = original.PID
		event.Comm = original.Comm
	}
	return event
}

func isSSEData(data string) bool {
	hasPatterns := strings.Contains(data, "event:") && strings.Contains(data, "data:")
	hasContentType := strings.Contains(data, "text/event-stream")
	hasChunked := strings.Contains(data, "Transfer-Encoding: chunked") && (strings.Contains(data, "event:") || strings.Contains(data, "data:"))
	hasDataOnly := strings.Contains(data, "data:") && (strings.Contains(data, "\r\n\r\n") || strings.Contains(data, "\n\n"))
	return hasPatterns || hasContentType || hasChunked || hasDataOnly
}

func isMetadataOnlyChunk(e sseEvent) bool {
	if e.Event == "ping" || e.Event == "heartbeat" {
		return true
	}
	if e.Data == "" && e.Event == "" {
		return true
	}
	trimmed := strings.TrimSpace(e.Data)
	return trimmed == "" || trimmed == ":" || trimmed == ": "
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
			if line == "0" {
				break
			}
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
