package toolcall

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
	transforms "github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
)

// ClaudeToolCallAnalyzer identifies tool calls from Claude API HTTP traffic
// and correlates OS-level process events as context (os_activities).
//
// It follows the Claude API tool-use protocol:
//  1. Response from Claude contains tool_use content blocks
//  2. Agent executes the tool (generating FILE_OPEN, EXEC, etc.)
//  3. Agent sends tool_result back to Claude
//
// Non-HTTP/non-process events pass through unmodified.
type ClaudeToolCallAnalyzer struct {
	mu       sync.Mutex
	pending  map[string]*pendingToolCall // keyed by tool_use_id
	timeout  time.Duration
	agentPID uint32 // track the main agent PID for process event correlation
	inner    *transforms.StatefulAnalyzer
}

type pendingToolCall struct {
	toolUseID    string
	toolName     string
	toolInput    json.RawMessage
	responseTime int64 // timestamp_ns when tool_use was seen
	pid          uint32
	comm         string
	activities   []osActivity
}

type osActivity struct {
	EventType   string `json:"event_type"`
	Filepath    string `json:"filepath,omitempty"`
	Command     string `json:"command,omitempty"`
	PID         uint32 `json:"pid"`
	TimestampNs int64  `json:"timestamp_ns"`
}

// ClaudeToolCallConfig holds configurable parameters.
type ClaudeToolCallConfig struct {
	Timeout time.Duration // max wait for tool_result before forced output
}

// NewClaudeToolCallAnalyzer creates an analyzer with default settings.
func NewClaudeToolCallAnalyzer() *ClaudeToolCallAnalyzer {
	c := newClaudeToolCallBase(30 * time.Second)
	c.initInner()
	return c
}

// NewClaudeToolCallAnalyzerWithConfig creates an analyzer with custom config.
func NewClaudeToolCallAnalyzerWithConfig(cfg ClaudeToolCallConfig) *ClaudeToolCallAnalyzer {
	timeout := 30 * time.Second
	if cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}
	c := newClaudeToolCallBase(timeout)
	c.initInner()
	return c
}

func newClaudeToolCallBase(timeout time.Duration) *ClaudeToolCallAnalyzer {
	return &ClaudeToolCallAnalyzer{
		pending: make(map[string]*pendingToolCall),
		timeout: timeout,
	}
}

func (c *ClaudeToolCallAnalyzer) initInner() {
	c.inner = transforms.NewStatefulAnalyzer("claude_tool_call_analyzer", transforms.StatefulOpts{
		BufSize:      100,
		TickInterval: 5 * time.Second,
		OnEvent: func(ev *event.Event, emit func(*event.Event)) {
			c.handleEvent(ev, emit)
		},
		OnTick: func(emit func(*event.Event)) {
			c.flushExpired(emit)
		},
		OnClose: func(emit func(*event.Event)) {
			c.flushAll(emit, "context_cancelled")
		},
	})
}

func (c *ClaudeToolCallAnalyzer) Name() string { return "claude_tool_call_analyzer" }

func (c *ClaudeToolCallAnalyzer) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	return c.inner.Process(ctx, in)
}

func (c *ClaudeToolCallAnalyzer) handleEvent(event *event.Event, emit func(*event.Event)) {
	switch event.Source {
	case "http_parser":
		c.handleHTTP(event, emit)
	case "process":
		c.handleProcess(event, emit)
	default:
		// Pass through all other events.
		emit(event)
	}
}

func (c *ClaudeToolCallAnalyzer) handleHTTP(event *event.Event, emit func(*event.Event)) {
	// Always forward the original HTTP event.
	emit(event)

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return
	}

	msgType, _ := data["message_type"].(string)

	switch msgType {
	case "response":
		// Look for tool_use blocks in response body.
		c.extractToolUseFromResponse(event, data)
	case "request":
		// Look for tool_result blocks in request body.
		c.extractToolResultFromRequest(event, data, emit)
	}
}

func (c *ClaudeToolCallAnalyzer) extractToolUseFromResponse(event *event.Event, data map[string]interface{}) {
	body, _ := data["body"].(string)
	if body == "" {
		return
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return
	}

	content, ok := parsed["content"].([]interface{})
	if !ok {
		return
	}

	for _, item := range content {
		block, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if block["type"] != "tool_use" {
			continue
		}

		toolUseID, _ := block["id"].(string)
		toolName, _ := block["name"].(string)
		if toolUseID == "" || toolName == "" {
			continue
		}

		var inputJSON json.RawMessage
		if input, ok := block["input"]; ok {
			inputJSON, _ = json.Marshal(input)
		}

		c.mu.Lock()
		c.pending[toolUseID] = &pendingToolCall{
			toolUseID:    toolUseID,
			toolName:     toolName,
			toolInput:    inputJSON,
			responseTime: event.TimestampNs,
			pid:          event.PID,
			comm:         event.Comm,
		}
		c.mu.Unlock()
	}
}

// toolResultMatch represents a tool_result found in a Claude API request body.
type toolResultMatch struct {
	toolUseID     string
	resultSummary string
}

// findToolResults scans the request body for tool_result content blocks.
func findToolResults(body string) []toolResultMatch {
	var parsed map[string]interface{}
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		return nil
	}
	messages, ok := parsed["messages"].([]interface{})
	if !ok {
		return nil
	}

	var results []toolResultMatch
	for _, msg := range messages {
		results = append(results, extractToolResultsFromMessage(msg)...)
	}
	return results
}

// extractToolResultsFromMessage extracts tool_result blocks from a single user message.
func extractToolResultsFromMessage(msg interface{}) []toolResultMatch {
	msgMap, ok := msg.(map[string]interface{})
	if !ok || msgMap["role"] != "user" {
		return nil
	}
	content, ok := msgMap["content"].([]interface{})
	if !ok {
		return nil
	}
	var results []toolResultMatch
	for _, item := range content {
		block, ok := item.(map[string]interface{})
		if !ok || block["type"] != "tool_result" {
			continue
		}
		toolUseID, _ := block["tool_use_id"].(string)
		if toolUseID == "" {
			continue
		}
		results = append(results, toolResultMatch{
			toolUseID:     toolUseID,
			resultSummary: extractResultSummary(block),
		})
	}
	return results
}

func (c *ClaudeToolCallAnalyzer) extractToolResultFromRequest(event *event.Event, data map[string]interface{}, emit func(*event.Event)) {
	body, _ := data["body"].(string)
	if body == "" {
		return
	}
	for _, r := range findToolResults(body) {
		c.mu.Lock()
		pending, exists := c.pending[r.toolUseID]
		if exists {
			delete(c.pending, r.toolUseID)
		}
		c.mu.Unlock()
		if exists {
			emit(c.buildCompleteEvent(pending, event.TimestampNs, r.resultSummary, "success"))
		}
	}
}

func (c *ClaudeToolCallAnalyzer) handleProcess(event *event.Event, emit func(*event.Event)) {
	// Always forward the original process event.
	emit(event)

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return
	}

	et, _ := data["event"].(string)

	// Build an OS activity record.
	activity := osActivity{
		EventType:   et,
		PID:         event.PID,
		TimestampNs: event.TimestampNs,
	}

	switch et {
	case "FILE_OPEN", "FILE_DELETE":
		activity.Filepath, _ = data["filepath"].(string)
	case "FILE_RENAME":
		oldpath, _ := data["oldpath"].(string)
		newpath, _ := data["newpath"].(string)
		activity.Filepath = oldpath + " -> " + newpath
	case "EXEC":
		activity.Command, _ = data["full_command"].(string)
	case "NET_CONNECT":
		ip, _ := data["ip"].(string)
		port := uint32(0)
		if p, ok := data["port"].(float64); ok {
			port = uint32(p)
		}
		activity.Filepath = fmt.Sprintf("%s:%d", ip, port)
	default:
		return // Skip irrelevant process events.
	}

	// Append to all pending tool calls within the time window.
	c.mu.Lock()
	for _, pending := range c.pending {
		if event.TimestampNs >= pending.responseTime {
			pending.activities = append(pending.activities, activity)
		}
	}
	c.mu.Unlock()
}

func (c *ClaudeToolCallAnalyzer) buildCompleteEvent(pending *pendingToolCall, resultTimestampNs int64, resultSummary string, status string) *event.Event {
	durationNs := resultTimestampNs - pending.responseTime
	durationMs := int64(0)
	if durationNs > 0 {
		durationMs = durationNs / int64(time.Millisecond)
	}

	activitiesJSON, _ := json.Marshal(pending.activities)

	payload := map[string]interface{}{
		"event_type":     "tool_call_complete",
		"tool_use_id":    pending.toolUseID,
		"tool_name":      pending.toolName,
		"tool_input":     json.RawMessage(pending.toolInput),
		"result_summary": resultSummary,
		"status":         status,
		"duration_ms":    durationMs,
		"os_activities":  json.RawMessage(activitiesJSON),
	}

	data, _ := json.Marshal(payload)

	return &event.Event{
		TimestampNs:     pending.responseTime,
		TimestampUnixMs: event.BootNsToUnixMs(pending.responseTime),
		Source:          "tool_call",
		PID:             pending.pid,
		Comm:            pending.comm,
		Data:            data,
	}
}

func (c *ClaudeToolCallAnalyzer) flushExpired(emit func(*event.Event)) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	for id, pending := range c.pending {
		elapsed := now.Sub(event.BootNsToTime(pending.responseTime))
		if elapsed > c.timeout {
			emit(c.buildCompleteEvent(pending, pending.responseTime+int64(c.timeout), "", "timeout"))
			delete(c.pending, id)
		}
	}
}

func (c *ClaudeToolCallAnalyzer) flushAll(emit func(*event.Event), reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for id, pending := range c.pending {
		emit(c.buildCompleteEvent(pending, pending.responseTime, "", reason))
		delete(c.pending, id)
	}
}

// extractResultSummary gets a short text summary from a tool_result block.
func extractResultSummary(block map[string]interface{}) string {
	// Content can be a string or array of content blocks.
	if content, ok := block["content"].(string); ok {
		return truncate(content, 200)
	}
	if content, ok := block["content"].([]interface{}); ok {
		for _, item := range content {
			if m, ok := item.(map[string]interface{}); ok {
				if text, ok := m["text"].(string); ok {
					return truncate(text, 200)
				}
			}
		}
	}
	return ""
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}
