package analyzer

import (
    "context"
    "encoding/json"
    "fmt"
    "hash/fnv"
    "strings"
    "sync"
    "time"

    "github.com/haolipeng/LLM-Scope/internal/core"
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
    key       toolCallKey
    startNs   int64
    lastNs    int64
    bytes     int64
    argsHash  string
    argsSummary string
    comm      string
}

// ToolCallAggregator converts low-level eBPF events into tool_call_* spans.
type ToolCallAggregator struct {
    cfg toolCallConfig
    mu  sync.Mutex
    live map[toolCallKey]*toolCallState
}

func NewToolCallAggregator() *ToolCallAggregator {
    return &ToolCallAggregator{
        cfg: toolCallConfig{
            idleGap: 1 * time.Second,
            maxSpan: 60 * time.Second,
        },
        live: make(map[toolCallKey]*toolCallState),
    }
}

func (t *ToolCallAggregator) Name() string {
    return "tool_call_aggregator"
}

func (t *ToolCallAggregator) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
    out := make(chan *core.Event)

    go func() {
        defer close(out)
        ticker := time.NewTicker(t.cfg.idleGap)
        defer ticker.Stop()

        for {
            select {
    case <-ctx.Done():
        t.flushAll(out)
        return
            case <-ticker.C:
                t.flushExpired(out, time.Now())
    case event, ok := <-in:
        if !ok {
            t.flushAll(out)
            return
        }
                if event.Source != "process" && event.Source != "http_parser" {
                    out <- event
                    continue
                }
                t.handleEvent(event, out)
                out <- event
            }
        }
    }()

    return out
}

func (t *ToolCallAggregator) flushAll(out chan<- *core.Event) {
    t.mu.Lock()
    defer t.mu.Unlock()
    for _, state := range t.live {
        out <- t.finishState(state, "timeout", "flush")
    }
    t.live = make(map[toolCallKey]*toolCallState)
}

func (t *ToolCallAggregator) flushExpired(out chan<- *core.Event, now time.Time) {
    t.mu.Lock()
    defer t.mu.Unlock()

    cutoff := now.Add(-t.cfg.idleGap)
    for key, state := range t.live {
        last := core.BootNsToTime(state.lastNs)
        if last.Before(cutoff) {
            out <- t.finishState(state, "timeout", "idle_gap")
            delete(t.live, key)
        }
    }
}

func (t *ToolCallAggregator) handleEvent(event *core.Event, out chan<- *core.Event) {
    switch event.Source {
    case "process":
        t.handleProcessEvent(event, out)
    case "http_parser":
        t.handleHTTPEvent(event, out)
    }
}

func (t *ToolCallAggregator) handleProcessEvent(event *core.Event, out chan<- *core.Event) {
    var payload map[string]interface{}
    if err := json.Unmarshal(event.Data, &payload); err != nil {
        return
    }

    eventType, _ := payload["event"].(string)
    if eventType == "EXEC" {
        filename := getStringValue(payload["filename"], "")
        fullCommand := getStringValue(payload["full_command"], "")
        if filename == "" {
            return
        }
        keyField := filename
        argsSummary := fullCommand
        if argsSummary == "" {
            argsSummary = filename
        }
        state, isNew, rolled := t.startOrUpdate(event, "proc.exec", keyField, argsSummary, 0)
        if rolled != nil {
            out <- rolled
        }
        if isNew {
            out <- t.startEvent(event, state)
        }
        out <- t.finishState(state, "success", "exec")
        t.removeState(state.key)
        return
    }

    if eventType != "FILE_OPEN" {
        return
    }

    flagsValue, _ := toUint64(payload["flags"])
    filepath := getStringValue(payload["filepath"], "")
    if filepath == "" {
        return
    }

    toolName := classifyFileTool(flagsValue)
    if toolName == "" {
        return
    }

    argsSummary := fmt.Sprintf("path=%s flags=%d", filepath, flagsValue)
    state, isNew, rolled := t.startOrUpdate(event, toolName, filepath, argsSummary, 0)
    if rolled != nil {
        out <- rolled
    }
    if isNew {
        out <- t.startEvent(event, state)
    }
}

func (t *ToolCallAggregator) handleHTTPEvent(event *core.Event, out chan<- *core.Event) {
    var payload map[string]interface{}
    if err := json.Unmarshal(event.Data, &payload); err != nil {
        return
    }

    messageType := getStringValue(payload["message_type"], "")
    if messageType != "request" {
        return
    }

    host := ""
    if headers, ok := payload["headers"].(map[string]interface{}); ok {
        host = getStringValue(headers["host"], "")
    }
    method := getStringValue(payload["method"], "")
    path := getStringValue(payload["path"], "")
    if host == "" && path == "" {
        return
    }

    argsSummary := fmt.Sprintf("method=%s host=%s path=%s", method, host, path)
    keyField := host + path
    state, isNew, rolled := t.startOrUpdate(event, "net.http", keyField, argsSummary, 0)
    if rolled != nil {
        out <- rolled
    }
    if isNew {
        out <- t.startEvent(event, state)
    }
}

func (t *ToolCallAggregator) startOrUpdate(event *core.Event, toolName, keyField, argsSummary string, bytes int64) (*toolCallState, bool, *core.Event) {
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

func (t *ToolCallAggregator) startEvent(event *core.Event, state *toolCallState) *core.Event {
    payload := map[string]interface{}{
        "tool_name":   state.key.toolName,
        "args_summary": state.argsSummary,
        "args_hash":   state.argsHash,
        "key_field":   state.key.keyField,
        "tid":         state.key.tid,
    }
    return newToolCallEvent(event, "tool_call_start", payload)
}

func (t *ToolCallAggregator) finishState(state *toolCallState, status, reason string) *core.Event {
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
    event := &core.Event{
        TimestampNs:     state.lastNs,
        TimestampUnixMs: core.BootNsToUnixMs(state.lastNs),
        Source:          "tool_call",
        PID:             state.key.pid,
        Comm:            state.comm,
        Data:            mustJSON(payload),
    }
    return event
}

func newToolCallEvent(original *core.Event, eventType string, payload map[string]interface{}) *core.Event {
    payload["event_type"] = eventType
    data := mustJSON(payload)
    return &core.Event{
        TimestampNs:     original.TimestampNs,
        TimestampUnixMs: original.TimestampUnixMs,
        Source:          "tool_call",
        PID:             original.PID,
        Comm:            original.Comm,
        Data:            data,
    }
}

func classifyFileTool(flags uint64) string {
    if flags&0x3 == 0 {
        return "fs.read"
    }
    return "fs.write"
}

func extractTid(event *core.Event) uint32 {
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

func mustJSON(payload map[string]interface{}) json.RawMessage {
    encoded, err := json.Marshal(payload)
    if err != nil {
        return json.RawMessage("{}")
    }
    return encoded
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
