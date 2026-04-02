package transforms

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// makeHTTPResponse builds an http_parser response event with a JSON body.
func makeHTTPResponse(body map[string]interface{}) *event.Event {
	bodyJSON, _ := json.Marshal(body)
	data := map[string]interface{}{
		"message_type": "response",
		"status_code":  float64(200),
		"body":         string(bodyJSON),
	}
	d, _ := json.Marshal(data)
	return &event.Event{
		TimestampNs:     1000000,
		TimestampUnixMs: 1700000000000,
		Source:          "http_parser",
		PID:             100,
		Comm:            "claude",
		Data:            d,
	}
}

// makeHTTPRequest builds an http_parser request event with a JSON body.
func makeHTTPRequest(body map[string]interface{}, tsNs int64) *event.Event {
	bodyJSON, _ := json.Marshal(body)
	data := map[string]interface{}{
		"message_type": "request",
		"method":       "POST",
		"path":         "/v1/messages",
		"body":         string(bodyJSON),
	}
	d, _ := json.Marshal(data)
	return &event.Event{
		TimestampNs:     tsNs,
		TimestampUnixMs: 1700000001000,
		Source:          "http_parser",
		PID:             100,
		Comm:            "claude",
		Data:            d,
	}
}

// makeProcessEvent builds a process event.
func makeProcessEvent(eventType string, extra map[string]interface{}, tsNs int64) *event.Event {
	data := map[string]interface{}{
		"event": eventType,
	}
	for k, v := range extra {
		data[k] = v
	}
	d, _ := json.Marshal(data)
	return &event.Event{
		TimestampNs:     tsNs,
		TimestampUnixMs: 1700000000500,
		Source:          "process",
		PID:             200,
		Comm:            "node",
		Data:            d,
	}
}

// toolUseResponse builds a Claude API response with tool_use content.
func toolUseResponse(id, name string, input map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{
				"type":  "tool_use",
				"id":    id,
				"name":  name,
				"input": input,
			},
		},
	}
}

// toolResultRequest builds a Claude API request with tool_result content.
func toolResultRequest(toolUseID string, resultContent string) map[string]interface{} {
	return map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{
				"role": "user",
				"content": []interface{}{
					map[string]interface{}{
						"type":        "tool_result",
						"tool_use_id": toolUseID,
						"content":     resultContent,
					},
				},
			},
		},
	}
}

func TestClaudeToolCall_FullLifecycle(t *testing.T) {
	analyzer := NewClaudeToolCallAnalyzer()

	in := make(chan *event.Event, 10)

	// 1. Response with tool_use
	in <- makeHTTPResponse(toolUseResponse("toolu_001", "Read", map[string]interface{}{"file_path": "/tmp/test.go"}))

	// 2. Process event (file open during tool execution)
	in <- makeProcessEvent("FILE_OPEN", map[string]interface{}{"filepath": "/tmp/test.go"}, 1500000)

	// 3. Request with tool_result
	in <- makeHTTPRequest(toolResultRequest("toolu_001", "file content here"), 2000000)

	close(in)

	out := analyzer.Process(context.Background(), in)
	events := collectAll(out)

	// Expect: 3 original pass-through + 1 tool_call_complete = 4
	if len(events) != 4 {
		t.Fatalf("expected 4 events, got %d", len(events))
	}

	// Find the tool_call event.
	var toolCallEvent *event.Event
	for _, e := range events {
		if e.Source == "tool_call" {
			toolCallEvent = e
			break
		}
	}

	if toolCallEvent == nil {
		t.Fatal("expected a tool_call event")
	}

	var data map[string]interface{}
	json.Unmarshal(toolCallEvent.Data, &data)

	if data["event_type"] != "tool_call_complete" {
		t.Errorf("expected event_type=tool_call_complete, got %v", data["event_type"])
	}
	if data["tool_use_id"] != "toolu_001" {
		t.Errorf("expected tool_use_id=toolu_001, got %v", data["tool_use_id"])
	}
	if data["tool_name"] != "Read" {
		t.Errorf("expected tool_name=Read, got %v", data["tool_name"])
	}
	if data["status"] != "success" {
		t.Errorf("expected status=success, got %v", data["status"])
	}

	// Verify os_activities contains the file open.
	activitiesRaw, ok := data["os_activities"]
	if !ok {
		t.Fatal("missing os_activities")
	}
	activitiesJSON, _ := json.Marshal(activitiesRaw)
	var activities []osActivity
	json.Unmarshal(activitiesJSON, &activities)

	if len(activities) != 1 {
		t.Errorf("expected 1 os_activity, got %d", len(activities))
	} else if activities[0].EventType != "FILE_OPEN" {
		t.Errorf("expected FILE_OPEN activity, got %s", activities[0].EventType)
	}
}

func TestClaudeToolCall_ParallelTools(t *testing.T) {
	analyzer := NewClaudeToolCallAnalyzer()

	in := make(chan *event.Event, 10)

	// Response with two parallel tool_use blocks.
	resp := map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{
				"type":  "tool_use",
				"id":    "toolu_A",
				"name":  "Read",
				"input": map[string]interface{}{"file_path": "/a.txt"},
			},
			map[string]interface{}{
				"type":  "tool_use",
				"id":    "toolu_B",
				"name":  "Write",
				"input": map[string]interface{}{"file_path": "/b.txt"},
			},
		},
	}
	in <- makeHTTPResponse(resp)

	// Process events.
	in <- makeProcessEvent("FILE_OPEN", map[string]interface{}{"filepath": "/a.txt"}, 1500000)
	in <- makeProcessEvent("FILE_OPEN", map[string]interface{}{"filepath": "/b.txt", "flags": float64(1)}, 1600000)

	// Two separate tool_result requests.
	in <- makeHTTPRequest(toolResultRequest("toolu_A", "content of a"), 2000000)
	in <- makeHTTPRequest(toolResultRequest("toolu_B", "written b"), 2100000)

	close(in)

	out := analyzer.Process(context.Background(), in)
	events := collectAll(out)

	// Count tool_call events.
	var toolCalls []*event.Event
	for _, e := range events {
		if e.Source == "tool_call" {
			toolCalls = append(toolCalls, e)
		}
	}

	if len(toolCalls) != 2 {
		t.Fatalf("expected 2 tool_call events (parallel), got %d", len(toolCalls))
	}

	// Verify both tool_use_ids are present.
	ids := map[string]bool{}
	for _, tc := range toolCalls {
		var data map[string]interface{}
		json.Unmarshal(tc.Data, &data)
		ids[data["tool_use_id"].(string)] = true
	}
	if !ids["toolu_A"] || !ids["toolu_B"] {
		t.Errorf("expected both toolu_A and toolu_B, got %v", ids)
	}
}

func TestClaudeToolCall_Timeout(t *testing.T) {
	analyzer := NewClaudeToolCallAnalyzerWithConfig(ClaudeToolCallConfig{
		Timeout: 100 * time.Millisecond,
	})

	in := make(chan *event.Event, 5)

	// Send a tool_use response but never send tool_result.
	in <- makeHTTPResponse(toolUseResponse("toolu_timeout", "Bash", map[string]interface{}{"command": "sleep 100"}))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	out := analyzer.Process(ctx, in)

	// Collect events until context expires.
	var events []*event.Event
	for e := range out {
		events = append(events, e)
	}

	// Should have: 1 original HTTP + 1 timeout tool_call
	var toolCalls []*event.Event
	for _, e := range events {
		if e.Source == "tool_call" {
			toolCalls = append(toolCalls, e)
		}
	}

	if len(toolCalls) < 1 {
		t.Fatalf("expected at least 1 timed-out tool_call, got %d", len(toolCalls))
	}

	var data map[string]interface{}
	json.Unmarshal(toolCalls[0].Data, &data)
	status, _ := data["status"].(string)
	if status != "timeout" && status != "context_cancelled" {
		t.Errorf("expected status=timeout or context_cancelled, got %s", status)
	}
}

func TestClaudeToolCall_NoProcessEvents(t *testing.T) {
	analyzer := NewClaudeToolCallAnalyzer()

	in := make(chan *event.Event, 5)

	// tool_use + immediate tool_result (no process events in between).
	in <- makeHTTPResponse(toolUseResponse("toolu_net", "WebSearch", map[string]interface{}{"query": "test"}))
	in <- makeHTTPRequest(toolResultRequest("toolu_net", "search results"), 2000000)

	close(in)

	out := analyzer.Process(context.Background(), in)
	events := collectAll(out)

	var toolCallEvent *event.Event
	for _, e := range events {
		if e.Source == "tool_call" {
			toolCallEvent = e
		}
	}

	if toolCallEvent == nil {
		t.Fatal("expected a tool_call event")
	}

	var data map[string]interface{}
	json.Unmarshal(toolCallEvent.Data, &data)

	// os_activities should be empty.
	activitiesRaw, _ := data["os_activities"]
	activitiesJSON, _ := json.Marshal(activitiesRaw)
	var activities []osActivity
	json.Unmarshal(activitiesJSON, &activities)

	if len(activities) != 0 {
		t.Errorf("expected 0 os_activities, got %d", len(activities))
	}
}

func TestClaudeToolCall_ProcessCorrelation(t *testing.T) {
	analyzer := NewClaudeToolCallAnalyzer()

	in := make(chan *event.Event, 10)

	// Tool use at t=1000000.
	in <- makeHTTPResponse(toolUseResponse("toolu_corr", "Read", map[string]interface{}{"file_path": "/test"}))

	// Process events: one before tool_use time (should be skipped), two after.
	in <- makeProcessEvent("FILE_OPEN", map[string]interface{}{"filepath": "/before"}, 500000)   // before
	in <- makeProcessEvent("FILE_OPEN", map[string]interface{}{"filepath": "/test"}, 1500000)     // after
	in <- makeProcessEvent("EXEC", map[string]interface{}{"full_command": "cat /test"}, 1600000) // after

	// tool_result.
	in <- makeHTTPRequest(toolResultRequest("toolu_corr", "file content"), 2000000)

	close(in)

	out := analyzer.Process(context.Background(), in)
	events := collectAll(out)

	var toolCallEvent *event.Event
	for _, e := range events {
		if e.Source == "tool_call" {
			toolCallEvent = e
		}
	}

	if toolCallEvent == nil {
		t.Fatal("expected a tool_call event")
	}

	var data map[string]interface{}
	json.Unmarshal(toolCallEvent.Data, &data)

	activitiesRaw, _ := data["os_activities"]
	activitiesJSON, _ := json.Marshal(activitiesRaw)
	var activities []osActivity
	json.Unmarshal(activitiesJSON, &activities)

	// Only the 2 events after tool_use time should be correlated.
	if len(activities) != 2 {
		t.Errorf("expected 2 correlated activities, got %d", len(activities))
		for _, a := range activities {
			t.Logf("  activity: %+v", a)
		}
	}
}

func TestClaudeToolCall_NonToolResponse(t *testing.T) {
	analyzer := NewClaudeToolCallAnalyzer()

	in := make(chan *event.Event, 5)

	// Response without tool_use (normal text response).
	body := map[string]interface{}{
		"content": []interface{}{
			map[string]interface{}{
				"type": "text",
				"text": "Hello, how can I help?",
			},
		},
	}
	in <- makeHTTPResponse(body)

	// Some process events.
	in <- makeProcessEvent("FILE_OPEN", map[string]interface{}{"filepath": "/tmp/log"}, 1500000)

	// Another request (not tool_result).
	reqBody := map[string]interface{}{
		"messages": []interface{}{
			map[string]interface{}{
				"role":    "user",
				"content": "What is 2+2?",
			},
		},
	}
	in <- makeHTTPRequest(reqBody, 2000000)

	close(in)

	out := analyzer.Process(context.Background(), in)
	events := collectAll(out)

	// No tool_call events should be generated.
	for _, e := range events {
		if e.Source == "tool_call" {
			t.Error("unexpected tool_call event for non-tool response")
		}
	}

	// All 3 original events should pass through.
	if len(events) != 3 {
		t.Errorf("expected 3 pass-through events, got %d", len(events))
	}
}

func TestClaudeToolCall_PassThroughOtherSources(t *testing.T) {
	analyzer := NewClaudeToolCallAnalyzer()

	in := make(chan *event.Event, 5)

	// SSL, system, security events should pass through unchanged.
	in <- makeEvent("ssl", map[string]interface{}{"function": "SSL_read"})
	in <- makeEvent("system", map[string]interface{}{"type": "system_metrics"})
	in <- makeEvent("security", map[string]interface{}{"alert_type": "test"})

	close(in)

	out := analyzer.Process(context.Background(), in)
	events := collectAll(out)

	if len(events) != 3 {
		t.Errorf("expected 3 pass-through events, got %d", len(events))
	}

	sources := map[string]int{}
	for _, e := range events {
		sources[e.Source]++
	}
	if sources["ssl"] != 1 || sources["system"] != 1 || sources["security"] != 1 {
		t.Errorf("unexpected source distribution: %v", sources)
	}
}
