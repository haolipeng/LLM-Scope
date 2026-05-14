package transforms

import (
	"context"
	"encoding/json"
	"strings"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

// HTTPParser parses SSL events into HTTP request/response events.
type HTTPParser struct {
	includeRaw bool
	inner      *mapAnalyzer
}

func NewHTTPParser(includeRaw bool) *HTTPParser {
	p := &HTTPParser{includeRaw: includeRaw}
	p.inner = NewMapAnalyzer("http_parser", p.processEvent)
	return p
}

func (p *HTTPParser) Name() string {
	return "http_parser"
}

func (p *HTTPParser) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	return p.inner.Process(ctx, in)
}

func (p *HTTPParser) processEvent(ev *event.Event) []*event.Event {
	if ev.Source != "ssl" {
		return []*event.Event{ev}
	}
	parsed := p.parseEvent(ev)
	if parsed != nil {
		return []*event.Event{parsed}
	}
	return []*event.Event{ev}
}

func (p *HTTPParser) parseEvent(event *event.Event) *event.Event {
	var data map[string]interface{}
	if err := json.Unmarshal(event.Data, &data); err != nil {
		return nil
	}

	dataStr, _ := data["data"].(string)
	if dataStr == "" || !isHTTPData(dataStr) {
		return nil
	}

	parsed := parseHTTPMessage(dataStr)
	if parsed == nil {
		return nil
	}

	tid := uint64(0)
	if value, ok := toUint64(data["tid"]); ok {
		tid = value
	}

	return buildHTTPEvent(parsed, tid, event, p.includeRaw)
}

var httpRequestMethods = []string{"GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "}
var httpCommonHeaders = []string{"Content-Type:", "content-type:", "Host:", "host:", "User-Agent:", "user-agent:"}

func containsAny(s string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

func isHTTPData(data string) bool {
	hasRequest := strings.Contains(data, "HTTP/1.") && containsAny(data, httpRequestMethods)
	hasResponse := strings.HasPrefix(data, "HTTP/1.") || strings.Contains(data, "\r\nHTTP/1.")
	hasHeaders := containsAny(data, httpCommonHeaders)
	return hasRequest || hasResponse || hasHeaders
}

type httpMessage struct {
	messageType string
	firstLine   string
	headers     map[string]string
	body        *string
	rawData     string
	method      *string
	path        *string
	protocol    *string
	statusCode  *uint16
	statusText  *string
}

type firstLineResult struct {
	msgType    string
	method     *string
	path       *string
	protocol   *string
	statusCode *uint16
	statusText *string
}

func parseFirstLine(line string) firstLineResult {
	if strings.HasPrefix(line, "HTTP/") {
		return parseResponseLine(line)
	}
	return parseRequestLine(line)
}

func parseResponseLine(line string) firstLineResult {
	r := firstLineResult{msgType: "response"}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 2 {
		if code, err := parseUint(parts[1]); err == nil {
			c := uint16(code)
			r.statusCode = &c
		}
		if len(parts) >= 3 {
			st := parts[2]
			r.statusText = &st
		}
		proto := parts[0]
		r.protocol = &proto
	}
	return r
}

func parseRequestLine(line string) firstLineResult {
	r := firstLineResult{msgType: "request"}
	parts := strings.SplitN(line, " ", 3)
	if len(parts) >= 3 {
		m := parts[0]
		r.method = &m
		p := parts[1]
		r.path = &p
		proto := parts[2]
		r.protocol = &proto
	}
	return r
}

func parseHTTPMessage(data string) *httpMessage {
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]
	headers := map[string]string{}
	bodyStart := -1

	fl := parseFirstLine(firstLine)

	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			bodyStart = i + 1
			break
		}
		if idx := strings.Index(line, ":"); idx != -1 {
			key := strings.ToLower(strings.TrimSpace(line[:idx]))
			value := strings.TrimSpace(line[idx+1:])
			headers[key] = value
		}
	}

	var body *string
	if bodyStart != -1 && bodyStart < len(lines) {
		joined := strings.Join(lines[bodyStart:], "\r\n")
		if strings.TrimSpace(joined) != "" {
			body = &joined
		}
	}

	return &httpMessage{
		messageType: fl.msgType,
		firstLine:   firstLine,
		headers:     headers,
		body:        body,
		rawData:     data,
		method:      fl.method,
		path:        fl.path,
		protocol:    fl.protocol,
		statusCode:  fl.statusCode,
		statusText:  fl.statusText,
	}
}

func buildHTTPEvent(msg *httpMessage, tid uint64, original *event.Event, includeRaw bool) *event.Event {
	contentLength := int64(-1)
	if value, ok := msg.headers["content-length"]; ok {
		if parsed, err := parseInt(value); err == nil {
			contentLength = parsed
		}
	}

	isChunked := false
	if value, ok := msg.headers["transfer-encoding"]; ok {
		isChunked = strings.Contains(strings.ToLower(value), "chunked")
	}

	totalSize := len(msg.firstLine) + 4
	for k, v := range msg.headers {
		totalSize += len(k) + len(v) + 4
	}
	if msg.body != nil {
		totalSize += len(*msg.body)
	}

	payload := map[string]interface{}{
		"tid":             tid,
		"message_type":    msg.messageType,
		"first_line":      msg.firstLine,
		"method":          msg.method,
		"path":            msg.path,
		"protocol":        msg.protocol,
		"status_code":     msg.statusCode,
		"status_text":     msg.statusText,
		"headers":         msg.headers,
		"body":            msg.body,
		"total_size":      totalSize,
		"has_body":        msg.body != nil,
		"is_chunked":      isChunked,
		"content_length":  nil,
		"original_source": "ssl",
	}

	if contentLength >= 0 {
		payload["content_length"] = contentLength
	}
	if includeRaw {
		payload["raw_data"] = msg.rawData
	}

	encoded, err := json.Marshal(payload)
	if err != nil {
		return nil
	}

	return &event.Event{
		TimestampNs:     original.TimestampNs,
		TimestampUnixMs: original.TimestampUnixMs,
		Source:          "http_parser",
		PID:             original.PID,
		Comm:            original.Comm,
		Data:            encoded,
	}
}
