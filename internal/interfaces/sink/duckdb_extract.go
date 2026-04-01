package sink

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"time"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// eventRow holds extracted column values for a single DuckDB INSERT.
type eventRow struct {
	// universal
	sessionID     string
	timestampNs   int64
	timestampUnix int64
	eventTime     time.Time
	source        string
	pid           uint32
	comm          string

	// process
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

	// tool_call
	toolEventType *string
	toolName      *string
	toolStatus    *string
	toolReason    *string
	toolBytes     *int64
	toolKeyField  *string
	toolArgsHash  *string
	toolTID       *uint32

	// system
	sysType       *string
	cpuPercent    *float64
	cpuCores      *uint32
	memRssKB      *uint64
	memVszKB      *uint64
	threadCount   *uint32
	childrenCount *uint32
	sysAlert      *bool

	// ssl
	sslFunction    *string
	sslLen         *uint32
	sslIsHandshake *bool
	sslLatencyMs   *float64
	sslTID         *uint32

	// http_parser
	httpMessageType *string
	httpMethod      *string
	httpPath        *string
	httpStatusCode  *uint16
	httpTotalSize   *uint32
	httpTID         *uint32

	// sse_processor
	sseConnectionID *string
	sseDurationNs   *int64
	sseEventCount   *uint32
	sseTotalSize    *uint32

	// raw JSON
	dataJSON string

	// security
	isSensitiveFile bool
	isDangerousCmd  bool
}

// extractRow parses an Event into column values for the events table.
func extractRow(event *runtimeevent.Event, sessionID string) eventRow {
	row := eventRow{
		sessionID:     sessionID,
		timestampNs:   event.TimestampNs,
		timestampUnix: event.TimestampUnixMs,
		eventTime:     event.Time(),
		source:        event.Source,
		pid:           event.PID,
		comm:          event.Comm,
		dataJSON:      string(event.Data),
	}

	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return row
	}

	switch event.Source {
	case "process":
		extractProcess(&row, data)
	case "tool_call":
		extractToolCall(&row, data)
	case "system":
		extractSystem(&row, data)
	case "ssl":
		extractSSL(&row, data)
	case "http_parser":
		extractHTTP(&row, data)
	case "sse_processor":
		extractSSE(&row, data)
	}

	return row
}

func extractProcess(row *eventRow, data map[string]interface{}) {
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

	// security checks
	if fp := row.filepath; fp != nil {
		row.isSensitiveFile = isSensitivePath(*fp)
	}
	if fp2 := row.filepath2; fp2 != nil && !row.isSensitiveFile {
		row.isSensitiveFile = isSensitivePath(*fp2)
	}
	if cmd := row.fullCommand; cmd != nil {
		row.isDangerousCmd = isDangerousCommand(*cmd)
	}
}

func extractToolCall(row *eventRow, data map[string]interface{}) {
	row.toolEventType = getStringPtr(data, "event_type")
	row.toolName = getStringPtr(data, "tool_name")
	row.toolStatus = getStringPtr(data, "status")
	row.toolReason = getStringPtr(data, "reason")
	row.toolBytes = getInt64Ptr(data, "bytes")
	row.toolKeyField = getStringPtr(data, "key_field")
	row.toolArgsHash = getStringPtr(data, "args_hash")
	row.toolTID = getUint32Ptr(data, "tid")
	row.durationMs = getInt64Ptr(data, "duration_ms")

	if kf := row.toolKeyField; kf != nil {
		row.isSensitiveFile = isSensitivePath(*kf)
	}
}

func extractSystem(row *eventRow, data map[string]interface{}) {
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
}

func extractSSL(row *eventRow, data map[string]interface{}) {
	row.sslFunction = getStringPtr(data, "function")
	row.sslLen = getUint32Ptr(data, "len")
	row.sslIsHandshake = getBoolPtr(data, "is_handshake")
	row.sslLatencyMs = getFloat64Ptr(data, "latency_ms")
	row.sslTID = getUint32Ptr(data, "tid")
}

func extractHTTP(row *eventRow, data map[string]interface{}) {
	row.httpMessageType = getStringPtr(data, "message_type")
	row.httpMethod = getStringPtr(data, "method")
	row.httpPath = getStringPtr(data, "path")
	row.httpStatusCode = getUint16Ptr(data, "status_code")
	row.httpTotalSize = getUint32Ptr(data, "total_size")
	row.httpTID = getUint32Ptr(data, "tid")
}

func extractSSE(row *eventRow, data map[string]interface{}) {
	row.sseConnectionID = getStringPtr(data, "connection_id")
	row.sseDurationNs = getInt64Ptr(data, "duration_ns")
	row.sseEventCount = getUint32Ptr(data, "event_count")
	row.sseTotalSize = getUint32Ptr(data, "total_size")
}

// --- Sensitive path / dangerous command detection ---

var sensitivePathPatterns = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/sudoers",
	".env",
	".ssh/",
	"id_rsa",
	"id_ed25519",
	"credentials",
	"secret",
	".aws/",
	".kube/config",
	"/proc/self/",
}

func isSensitivePath(path string) bool {
	lower := strings.ToLower(path)
	for _, pattern := range sensitivePathPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

var dangerousCmdPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\brm\s+(-[^\s]*)?-r`),
	regexp.MustCompile(`\bchmod\s+777\b`),
	regexp.MustCompile(`\bcurl\b.*\|\s*\bbash\b`),
	regexp.MustCompile(`\bwget\b.*\|\s*\bbash\b`),
	regexp.MustCompile(`\bmkfifo\b`),
	regexp.MustCompile(`\bnc\s+-[^\s]*l`),
	regexp.MustCompile(`/dev/tcp/`),
	regexp.MustCompile(`\bdd\s+.*of=/dev/`),
	regexp.MustCompile(`\b>\s*/etc/`),
}

func isDangerousCommand(cmd string) bool {
	for _, re := range dangerousCmdPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

// --- JSON field helpers ---

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
