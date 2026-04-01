package transforms

import (
	"context"
	"encoding/json"
	"strings"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

// HTTPParser parses SSL events into HTTP request/response events.
type HTTPParser struct {
	includeRaw bool
}

func NewHTTPParser(includeRaw bool) *HTTPParser {
	return &HTTPParser{includeRaw: includeRaw}
}

func (p *HTTPParser) Name() string {
	return "http_parser"
}

func (p *HTTPParser) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
	out := make(chan *runtimeevent.Event)

	go func() {
		defer close(out)
		for {
			select {
			case <-ctx.Done():
				return
			case event, ok := <-in:
				if !ok {
					return
				}
				if event.Source != "ssl" {
					out <- event
					continue
				}

				parsed := p.parseEvent(event)
				if parsed != nil {
					out <- parsed
				} else {
					out <- event
				}
			}
		}
	}()

	return out
}

func (p *HTTPParser) parseEvent(event *runtimeevent.Event) *runtimeevent.Event {
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

func isHTTPData(data string) bool {
	hasRequest := strings.Contains(data, "HTTP/1.") &&
		(strings.Contains(data, "GET ") || strings.Contains(data, "POST ") ||
			strings.Contains(data, "PUT ") || strings.Contains(data, "DELETE ") ||
			strings.Contains(data, "HEAD ") || strings.Contains(data, "OPTIONS ") ||
			strings.Contains(data, "PATCH "))

	hasResponse := strings.HasPrefix(data, "HTTP/1.") || strings.Contains(data, "\r\nHTTP/1.")

	hasHeaders := strings.Contains(data, "Content-Type:") || strings.Contains(data, "content-type:") ||
		strings.Contains(data, "Host:") || strings.Contains(data, "host:") ||
		strings.Contains(data, "User-Agent:") || strings.Contains(data, "user-agent:")

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

func parseHTTPMessage(data string) *httpMessage {
	lines := strings.Split(data, "\r\n")
	if len(lines) == 0 {
		return nil
	}

	firstLine := lines[0]
	headers := map[string]string{}
	bodyStart := -1

	msgType := "request"
	var method, path, protocol *string
	var statusCode *uint16
	var statusText *string

	if strings.HasPrefix(firstLine, "HTTP/") {
		msgType = "response"
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 2 {
			if code, err := parseUint(parts[1]); err == nil {
				c := uint16(code)
				statusCode = &c
			}
			if len(parts) >= 3 {
				st := parts[2]
				statusText = &st
			}
			proto := parts[0]
			protocol = &proto
		}
	} else {
		parts := strings.SplitN(firstLine, " ", 3)
		if len(parts) >= 3 {
			m := parts[0]
			method = &m
			p := parts[1]
			path = &p
			proto := parts[2]
			protocol = &proto
		}
	}

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
		messageType: msgType,
		firstLine:   firstLine,
		headers:     headers,
		body:        body,
		rawData:     data,
		method:      method,
		path:        path,
		protocol:    protocol,
		statusCode:  statusCode,
		statusText:  statusText,
	}
}

func buildHTTPEvent(msg *httpMessage, tid uint64, original *runtimeevent.Event, includeRaw bool) *runtimeevent.Event {
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

	return &runtimeevent.Event{
		TimestampNs:     original.TimestampNs,
		TimestampUnixMs: original.TimestampUnixMs,
		Source:          "http_parser",
		PID:             original.PID,
		Comm:            original.Comm,
		Data:            encoded,
	}
}
