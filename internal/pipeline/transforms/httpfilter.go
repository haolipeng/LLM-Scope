package transforms

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

var (
	globalHTTPFilterTotal    atomic.Int64
	globalHTTPFilterFiltered atomic.Int64
	globalHTTPFilterPassed   atomic.Int64
)

func PrintGlobalHTTPFilterMetrics() {
	total := globalHTTPFilterTotal.Load()
	filtered := globalHTTPFilterFiltered.Load()
	passed := globalHTTPFilterPassed.Load()
	if total > 0 {
		fmt.Printf("[HTTP Filter] Total: %d, Filtered: %d, Passed: %d\n", total, filtered, passed)
	}
}

type HTTPFilter struct {
	filters  []httpFilterExpression
	total    atomic.Int64
	filtered atomic.Int64
	passed   atomic.Int64
}

func NewHTTPFilter(patterns []string) *HTTPFilter {
	filters := make([]httpFilterExpression, 0, len(patterns))
	for _, pattern := range patterns {
		filters = append(filters, parseHTTPFilter(pattern))
	}
	return &HTTPFilter{filters: filters}
}

func (f *HTTPFilter) Name() string {
	return "http_filter"
}

func (f *HTTPFilter) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
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
				if event.Source == "http_parser" {
					f.total.Add(1)
					globalHTTPFilterTotal.Add(1)
					if f.shouldFilter(event.Data) {
						f.filtered.Add(1)
						globalHTTPFilterFiltered.Add(1)
						continue
					}
					f.passed.Add(1)
					globalHTTPFilterPassed.Add(1)
				}
				out <- event
			}
		}
	}()

	return out
}

type httpFilterExpression struct {
	expression string
	node       httpFilterNode
}

type httpFilterNode struct {
	op       string
	nodes    []httpFilterNode
	target   string
	field    string
	operator string
	value    string
}

func parseHTTPFilter(expr string) httpFilterExpression {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return httpFilterExpression{expression: expr, node: httpFilterNode{op: "empty"}}
	}
	node := parseHTTPOr(trimmed)
	return httpFilterExpression{expression: expr, node: node}
}

func parseHTTPOr(expr string) httpFilterNode {
	parts := splitAndTrim(expr, "|")
	if len(parts) > 1 {
		nodes := make([]httpFilterNode, 0, len(parts))
		for _, part := range parts {
			nodes = append(nodes, parseHTTPAnd(part))
		}
		return httpFilterNode{op: "or", nodes: nodes}
	}
	return parseHTTPAnd(expr)
}

func parseHTTPAnd(expr string) httpFilterNode {
	parts := splitAndTrim(expr, "&")
	if len(parts) > 1 {
		nodes := make([]httpFilterNode, 0, len(parts))
		for _, part := range parts {
			nodes = append(nodes, parseHTTPCondition(part))
		}
		return httpFilterNode{op: "and", nodes: nodes}
	}
	return parseHTTPCondition(expr)
}

func parseHTTPCondition(expr string) httpFilterNode {
	expr = strings.TrimSpace(expr)
	if !strings.Contains(expr, "=") {
		return httpFilterNode{
			op:       "cond",
			target:   "request",
			field:    "path",
			operator: "contains",
			value:    expr,
		}
	}

	parts := strings.SplitN(expr, "=", 2)
	if len(parts) != 2 {
		return httpFilterNode{op: "empty"}
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	if strings.Contains(key, ".") {
		keyParts := strings.SplitN(key, ".", 2)
		target := strings.TrimSpace(keyParts[0])
		field := strings.TrimSpace(keyParts[1])

		op := "exact"
		if target == "request" || target == "req" {
			switch field {
			case "path_prefix", "path_starts_with":
				op = "prefix"
			case "path_contains", "path_includes":
				op = "contains"
			case "path", "path_exact":
				op = "exact"
			}
			target = "request"
		} else if target == "response" || target == "resp" || target == "res" {
			target = "response"
		} else {
			target = "request"
		}

		return httpFilterNode{
			op:       "cond",
			target:   target,
			field:    field,
			operator: op,
			value:    value,
		}
	}

	op := "exact"
	switch key {
	case "path_prefix", "path_starts_with":
		op = "prefix"
	case "path_contains", "path_includes":
		op = "contains"
	case "path", "path_exact":
		op = "exact"
	}

	return httpFilterNode{
		op:       "cond",
		target:   "request",
		field:    key,
		operator: op,
		value:    value,
	}
}

func (f *HTTPFilter) shouldFilter(raw json.RawMessage) bool {
	if len(f.filters) == 0 {
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return false
	}

	for _, filter := range f.filters {
		if evalHTTPNode(filter.node, data) {
			return true
		}
	}
	return false
}

func evalHTTPNode(node httpFilterNode, data map[string]interface{}) bool {
	switch node.op {
	case "empty":
		return false
	case "and":
		for _, child := range node.nodes {
			if !evalHTTPNode(child, data) {
				return false
			}
		}
		return true
	case "or":
		for _, child := range node.nodes {
			if evalHTTPNode(child, data) {
				return true
			}
		}
		return false
	case "cond":
		return evalHTTPCondition(node, data)
	default:
		return false
	}
}

func evalHTTPCondition(node httpFilterNode, data map[string]interface{}) bool {
	messageType, _ := data["message_type"].(string)
	if node.target == "request" && messageType != "request" {
		return false
	}
	if node.target == "response" && messageType != "response" {
		return false
	}

	if node.target == "request" {
		return evalHTTPRequestCondition(node, data)
	}
	if node.target == "response" {
		return evalHTTPResponseCondition(node, data)
	}
	return false
}

func evalHTTPRequestCondition(node httpFilterNode, data map[string]interface{}) bool {
	switch node.field {
	case "method", "verb":
		method, _ := data["method"].(string)
		return strings.EqualFold(method, node.value)
	case "path", "path_exact":
		path, _ := data["path"].(string)
		switch node.operator {
		case "prefix":
			return strings.HasPrefix(path, node.value)
		case "contains":
			return strings.Contains(path, node.value)
		default:
			return path == node.value
		}
	case "path_prefix", "path_starts_with":
		path, _ := data["path"].(string)
		return strings.HasPrefix(path, node.value)
	case "path_contains", "path_includes":
		path, _ := data["path"].(string)
		return strings.Contains(path, node.value)
	case "host", "hostname":
		headers := mapStringMap(data["headers"])
		host := headers["host"]
		return host == node.value
	case "body", "body_contains":
		body, _ := data["body"].(string)
		return strings.Contains(body, node.value)
	default:
		path, _ := data["path"].(string)
		if idx := strings.Index(path, "?"); idx != -1 {
			query := path[idx+1:]
			return strings.Contains(query, node.field+"="+node.value)
		}
	}
	return false
}

func evalHTTPResponseCondition(node httpFilterNode, data map[string]interface{}) bool {
	switch node.field {
	case "status_code", "status", "code":
		if value, ok := toUint64(data["status_code"]); ok {
			target, err := parseUint(node.value)
			if err != nil {
				return false
			}
			return value == target
		}
		return false
	case "status_text", "status_message":
		status, _ := data["status_text"].(string)
		return strings.Contains(strings.ToLower(status), strings.ToLower(node.value))
	case "content_type", "content-type":
		headers := mapStringMap(data["headers"])
		contentType := headers["content-type"]
		return strings.Contains(contentType, node.value)
	case "server":
		headers := mapStringMap(data["headers"])
		server := headers["server"]
		return strings.Contains(server, node.value)
	case "body", "body_contains":
		body, _ := data["body"].(string)
		return strings.Contains(body, node.value)
	default:
		headers := mapStringMap(data["headers"])
		header := headers[node.field]
		return strings.Contains(header, node.value)
	}
}

func (f *HTTPFilter) ReportMetrics() {
	total := f.total.Load()
	filtered := f.filtered.Load()
	passed := f.passed.Load()
	if total > 0 {
		fmt.Printf("[HTTP Filter] Total: %d, Filtered: %d, Passed: %d\n", total, filtered, passed)
	}
}
