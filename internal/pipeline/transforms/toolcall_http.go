package transforms

import (
	"encoding/json"
	"fmt"
)

type httpToolCallExtractor struct{}

func (e *httpToolCallExtractor) Source() string { return "http_parser" }

func (e *httpToolCallExtractor) Extract(data json.RawMessage) []toolCallExtraction {
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}

	messageType := getStringValue(payload["message_type"], "")
	if messageType != "request" {
		return nil
	}

	host := ""
	if headers, ok := payload["headers"].(map[string]interface{}); ok {
		host = getStringValue(headers["host"], "")
	}
	method := getStringValue(payload["method"], "")
	path := getStringValue(payload["path"], "")
	if host == "" && path == "" {
		return nil
	}

	return []toolCallExtraction{{
		toolName:    "net.http",
		keyField:    host + path,
		argsSummary: fmt.Sprintf("method=%s host=%s path=%s", method, host, path),
		immediate:   false,
	}}
}
