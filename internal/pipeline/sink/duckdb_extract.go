package sink

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// ---------- Per-table row types ----------

type baseRow struct {
	sessionID     string
	timestampNs   int64
	timestampUnix int64
	eventTime     time.Time
	pid           uint32
	comm          string
	dataJSON      string
}

type processRow struct {
	baseRow
	eventType   *string
	ppid        *uint32
	exitCode    *int32
	durationMs  *int64
	filename    *string
	fullCommand *string
	filepath    *string
	filepath2   *string
	fileFlags   *uint32
	netIP       *string
	netPort     *uint32
	netFamily   *uint32
	dirMode     *uint32
	bashCommand *string
}

type toolCallRow struct {
	baseRow
	toolEventType *string
	toolName      *string
	toolStatus    *string
	toolReason    *string
	toolBytes     *int64
	toolKeyField  *string
	toolArgsHash  *string
	toolTID       *uint32
	durationMs    *int64
}

type systemRow struct {
	baseRow
	sysType       *string
	cpuPercent    *float64
	cpuCores      *uint32
	memRssKB      *uint64
	memVszKB      *uint64
	threadCount   *uint32
	childrenCount *uint32
	sysAlert      *bool
}

type sslRow struct {
	baseRow
	sslFunction    *string
	sslLen         *uint32
	sslIsHandshake *bool
	sslLatencyMs   *float64
	sslTID         *uint32
}

type httpRow struct {
	baseRow
	httpMessageType *string
	httpMethod      *string
	httpPath        *string
	httpStatusCode  *uint16
	httpTotalSize   *uint32
	httpTID         *uint32
}

type sseRow struct {
	baseRow
	sseConnectionID *string
	sseDurationNs   *int64
	sseEventCount   *uint32
	sseTotalSize    *uint32
}

type securityRow struct {
	baseRow
	alertType     *string
	riskLevel     *string
	description   *string
	sourceTable   *string
	sourceEventID *uint64
	evidenceJSON  *string
}

// ---------- Extraction functions ----------

func extractBase(event *event.Event, sessionID string) baseRow {
	return baseRow{
		sessionID:     sessionID,
		timestampNs:   event.TimestampNs,
		timestampUnix: event.TimestampUnixMs,
		eventTime:     event.Time(),
		pid:           event.PID,
		comm:          event.Comm,
		dataJSON:      string(event.Data),
	}
}

func extractProcessRow(event *event.Event, sessionID string) processRow {
	row := processRow{baseRow: extractBase(event, sessionID)}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	row.eventType = getStringPtr(data, "event")
	row.ppid = getUint32Ptr(data, "ppid")
	row.exitCode = getInt32Ptr(data, "exit_code")
	row.durationMs = getInt64Ptr(data, "duration_ms")
	row.filename = getStringPtr(data, "filename")
	row.fullCommand = getStringPtr(data, "full_command")

	et := getString(data, "event")
	switch et {
	case "FILE_OPEN":
		row.filepath = getStringPtr(data, "filepath")
		row.fileFlags = getUint32Ptr(data, "flags")
	case "FILE_DELETE":
		row.filepath = getStringPtr(data, "filepath")
		row.fileFlags = getUint32Ptr(data, "flags")
	case "FILE_RENAME":
		row.filepath = getStringPtr(data, "oldpath")
		row.filepath2 = getStringPtr(data, "newpath")
	case "DIR_CREATE":
		row.filepath2 = getStringPtr(data, "path")
		row.dirMode = getUint32Ptr(data, "mode")
	case "NET_CONNECT":
		row.netIP = getStringPtr(data, "ip")
		row.netPort = getUint32Ptr(data, "port")
		row.netFamily = getUint32Ptr(data, "family")
	case "BASH_READLINE":
		row.bashCommand = getStringPtr(data, "command")
	}

	return row
}

func extractToolCallRow(event *event.Event, sessionID string) toolCallRow {
	row := toolCallRow{baseRow: extractBase(event, sessionID)}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	row.toolEventType = getStringPtr(data, "event_type")
	row.toolName = getStringPtr(data, "tool_name")
	row.toolStatus = getStringPtr(data, "status")
	row.toolReason = getStringPtr(data, "reason")
	row.toolBytes = getInt64Ptr(data, "bytes")
	row.toolKeyField = getStringPtr(data, "key_field")
	row.toolArgsHash = getStringPtr(data, "args_hash")
	row.toolTID = getUint32Ptr(data, "tid")
	row.durationMs = getInt64Ptr(data, "duration_ms")

	return row
}

func extractSystemRow(event *event.Event, sessionID string) systemRow {
	row := systemRow{baseRow: extractBase(event, sessionID)}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	row.sysType = getStringPtr(data, "type")

	if cpu, ok := data["cpu"].(map[string]interface{}); ok {
		row.cpuPercent = getFloat64Ptr(cpu, "percent")
		row.cpuCores = getUint32Ptr(cpu, "cores")
	}

	if mem, ok := data["memory"].(map[string]interface{}); ok {
		row.memRssKB = getUint64Ptr(mem, "rss_kb")
		row.memVszKB = getUint64Ptr(mem, "vsz_kb")
	}

	if proc, ok := data["process"].(map[string]interface{}); ok {
		row.threadCount = getUint32Ptr(proc, "threads")
		row.childrenCount = getUint32Ptr(proc, "children")
	}

	if alert, ok := data["alert"].(bool); ok {
		row.sysAlert = &alert
	}

	return row
}

func extractSSLRow(event *event.Event, sessionID string) sslRow {
	row := sslRow{baseRow: extractBase(event, sessionID)}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	row.sslFunction = getStringPtr(data, "function")
	row.sslLen = getUint32Ptr(data, "len")
	row.sslIsHandshake = getBoolPtr(data, "is_handshake")
	row.sslLatencyMs = getFloat64Ptr(data, "latency_ms")
	row.sslTID = getUint32Ptr(data, "tid")

	return row
}

func extractHTTPRow(event *event.Event, sessionID string) httpRow {
	row := httpRow{baseRow: extractBase(event, sessionID)}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	row.httpMessageType = getStringPtr(data, "message_type")
	row.httpMethod = getStringPtr(data, "method")
	row.httpPath = getStringPtr(data, "path")
	row.httpStatusCode = getUint16Ptr(data, "status_code")
	row.httpTotalSize = getUint32Ptr(data, "total_size")
	row.httpTID = getUint32Ptr(data, "tid")

	return row
}

func extractSSERow(event *event.Event, sessionID string) sseRow {
	row := sseRow{baseRow: extractBase(event, sessionID)}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	row.sseConnectionID = getStringPtr(data, "connection_id")
	row.sseDurationNs = getInt64Ptr(data, "duration_ns")
	row.sseEventCount = getUint32Ptr(data, "event_count")
	row.sseTotalSize = getUint32Ptr(data, "total_size")

	return row
}

func extractSecurityRow(event *event.Event, sessionID string) securityRow {
	row := securityRow{baseRow: extractBase(event, sessionID)}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	row.alertType = getStringPtr(data, "alert_type")
	row.riskLevel = getStringPtr(data, "risk_level")
	row.description = getStringPtr(data, "description")
	row.sourceTable = getStringPtr(data, "source_table")

	if eid, ok := data["source_event_id"].(float64); ok {
		u := uint64(eid)
		row.sourceEventID = &u
	}
	if ej := getStringPtr(data, "evidence_json"); ej != nil {
		row.evidenceJSON = ej
	} else if ev, ok := data["evidence"]; ok {
		b, _ := json.Marshal(ev)
		s := string(b)
		row.evidenceJSON = &s
	}

	return row
}

// ---------- JSON field helpers ----------

func getString(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok {
		return ""
	}
	s, ok := v.(string)
	if ok {
		return s
	}
	return ""
}

func getStringPtr(m map[string]interface{}, key string) *string {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		return &val
	default:
		s := strings.TrimSpace(jsonStr(v))
		if s == "" {
			return nil
		}
		return &s
	}
}

func getFloat64Ptr(m map[string]interface{}, key string) *float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		return &val
	case json.Number:
		f, err := val.Float64()
		if err != nil {
			return nil
		}
		return &f
	case string:
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return nil
		}
		return &f
	}
	return nil
}

func getInt64Ptr(m map[string]interface{}, key string) *int64 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		i := int64(val)
		return &i
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return nil
		}
		return &i
	}
	return nil
}

func getInt32Ptr(m map[string]interface{}, key string) *int32 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		i := int32(val)
		return &i
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return nil
		}
		i32 := int32(i)
		return &i32
	}
	return nil
}

func getUint32Ptr(m map[string]interface{}, key string) *uint32 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		u := uint32(val)
		return &u
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return nil
		}
		u := uint32(i)
		return &u
	}
	return nil
}

func getUint16Ptr(m map[string]interface{}, key string) *uint16 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		u := uint16(val)
		return &u
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return nil
		}
		u := uint16(i)
		return &u
	}
	return nil
}

func getUint64Ptr(m map[string]interface{}, key string) *uint64 {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	switch val := v.(type) {
	case float64:
		u := uint64(val)
		return &u
	case json.Number:
		i, err := val.Int64()
		if err != nil {
			return nil
		}
		u := uint64(i)
		return &u
	}
	return nil
}

func getBoolPtr(m map[string]interface{}, key string) *bool {
	v, ok := m[key]
	if !ok || v == nil {
		return nil
	}
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

func jsonStr(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}
