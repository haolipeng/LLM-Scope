package analyzer

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/haolipeng/LLM-Scope/internal/core"
)

// Global SSL filter metrics
var (
	globalSSLFilterTotal    atomic.Int64
	globalSSLFilterFiltered atomic.Int64
	globalSSLFilterPassed   atomic.Int64
)

// PrintGlobalSSLFilterMetrics prints the global SSL filter statistics.
func PrintGlobalSSLFilterMetrics() {
	total := globalSSLFilterTotal.Load()
	filtered := globalSSLFilterFiltered.Load()
	passed := globalSSLFilterPassed.Load()
	if total > 0 {
		fmt.Printf("[SSL Filter] Total: %d, Filtered: %d, Passed: %d\n", total, filtered, passed)
	}
}

type sslFilter struct {
	filters []sslFilterExpression
}

func NewSSLFilter(patterns []string) *sslFilter {
	filters := make([]sslFilterExpression, 0, len(patterns))
	for _, pattern := range patterns {
		filters = append(filters, parseSSLFilter(pattern))
	}
	return &sslFilter{filters: filters}
}

func (f *sslFilter) Name() string {
	return "ssl_filter"
}

func (f *sslFilter) Process(ctx context.Context, in <-chan *core.Event) <-chan *core.Event {
	out := make(chan *core.Event)

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
				if event.Source == "ssl" {
					globalSSLFilterTotal.Add(1)
					if f.shouldFilter(event.Data) {
						globalSSLFilterFiltered.Add(1)
						continue
					}
					globalSSLFilterPassed.Add(1)
				}
				out <- event
			}
		}
	}()

	return out
}

type sslFilterExpression struct {
	expression string
	node       sslFilterNode
}

type sslFilterNode struct {
	op       string
	left     *sslFilterNode
	right    *sslFilterNode
	field    string
	operator string
	value    string
}

func parseSSLFilter(expr string) sslFilterExpression {
	node := parseSSLExpression(strings.TrimSpace(expr))
	return sslFilterExpression{expression: expr, node: node}
}

func parseSSLExpression(expr string) sslFilterNode {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return sslFilterNode{op: "empty"}
	}

	if pos := findTopLevel(expr, '|'); pos != -1 {
		left := parseSSLExpression(expr[:pos])
		right := parseSSLExpression(expr[pos+1:])
		return sslFilterNode{op: "or", left: &left, right: &right}
	}

	if pos := findTopLevel(expr, '&'); pos != -1 {
		left := parseSSLExpression(expr[:pos])
		right := parseSSLExpression(expr[pos+1:])
		return sslFilterNode{op: "and", left: &left, right: &right}
	}

	return parseSSLCondition(expr)
}

func findTopLevel(expr string, target rune) int {
	depth := 0
	for idx, ch := range expr {
		switch ch {
		case '(':
			depth++
		case ')':
			depth--
		default:
			if ch == target && depth == 0 {
				return idx
			}
		}
	}
	return -1
}

func parseSSLCondition(expr string) sslFilterNode {
	expr = strings.TrimSpace(expr)
	if strings.HasPrefix(expr, "(") && strings.HasSuffix(expr, ")") {
		return parseSSLExpression(strings.TrimSpace(expr[1 : len(expr)-1]))
	}

	ops := []string{">=", "<=", "!=", "=", ">", "<", "~"}
	for _, op := range ops {
		if idx := strings.Index(expr, op); idx != -1 {
			field := strings.TrimSpace(expr[:idx])
			value := strings.TrimSpace(expr[idx+len(op):])
			return sslFilterNode{
				op:       "cond",
				field:    field,
				operator: mapSSLJoin(op, field),
				value:    decodeEscapes(value),
			}
		}
	}

	return sslFilterNode{op: "empty"}
}

func mapSSLJoin(op, field string) string {
	switch op {
	case "=":
		return "exact"
	case "!=":
		return "not_equal"
	case ">":
		return "gt"
	case "<":
		return "lt"
	case ">=":
		return "gte"
	case "<=":
		return "lte"
	case "~":
		return "contains"
	default:
		return "exact"
	}
}

func decodeEscapes(value string) string {
	builder := strings.Builder{}
	for i := 0; i < len(value); i++ {
		if value[i] == '\\' && i+1 < len(value) {
			i++
			switch value[i] {
			case 'r':
				builder.WriteByte('\r')
			case 'n':
				builder.WriteByte('\n')
			case 't':
				builder.WriteByte('\t')
			case '\\':
				builder.WriteByte('\\')
			case '"':
				builder.WriteByte('"')
			default:
				builder.WriteByte('\\')
				builder.WriteByte(value[i])
			}
		} else {
			builder.WriteByte(value[i])
		}
	}
	return builder.String()
}

func (f *sslFilter) shouldFilter(raw json.RawMessage) bool {
	if len(f.filters) == 0 {
		return false
	}

	var data map[string]interface{}
	if err := json.Unmarshal(raw, &data); err != nil {
		return false
	}

	for _, filter := range f.filters {
		if evalSSLNode(filter.node, data) {
			return true
		}
	}
	return false
}

func evalSSLNode(node sslFilterNode, data map[string]interface{}) bool {
	switch node.op {
	case "empty":
		return false
	case "and":
		return evalSSLNode(*node.left, data) && evalSSLNode(*node.right, data)
	case "or":
		return evalSSLNode(*node.left, data) || evalSSLNode(*node.right, data)
	case "cond":
		return evalSSLCondition(node, data)
	default:
		return false
	}
}

func evalSSLCondition(node sslFilterNode, data map[string]interface{}) bool {
	switch node.field {
	case "data.type":
		if value, ok := data["data"].(string); ok {
			return compareStrings(detectDataType(value), node.operator, node.value)
		}
		return false
	case "data":
		if value, ok := data["data"].(string); ok {
			return compareStrings(value, node.operator, node.value)
		}
		return false
	case "function", "comm":
		if value, ok := data[node.field].(string); ok {
			return compareStrings(value, node.operator, node.value)
		}
		return false
	case "is_handshake", "truncated":
		if value, ok := data[node.field].(bool); ok {
			return (value && node.value == "true") || (!value && node.value == "false")
		}
		return false
	case "len", "pid", "tid", "uid", "timestamp_ns":
		if value, ok := toUint64(data[node.field]); ok {
			return compareNumbers(value, node.operator, node.value)
		}
		return false
	case "latency_ms":
		if value, ok := toFloat64(data[node.field]); ok {
			return compareFloats(value, node.operator, node.value)
		}
		return false
	default:
		return false
	}
}

func compareStrings(actual, operator, expected string) bool {
	switch operator {
	case "exact":
		return actual == expected
	case "not_equal":
		return actual != expected
	case "contains":
		return strings.Contains(actual, expected)
	case "prefix":
		return strings.HasPrefix(actual, expected)
	case "suffix":
		return strings.HasSuffix(actual, expected)
	default:
		return false
	}
}

func compareNumbers(actual uint64, operator, expected string) bool {
	target, err := parseUint(expected)
	if err != nil {
		return false
	}
	switch operator {
	case "exact":
		return actual == target
	case "not_equal":
		return actual != target
	case "gt":
		return actual > target
	case "lt":
		return actual < target
	case "gte":
		return actual >= target
	case "lte":
		return actual <= target
	default:
		return false
	}
}

func compareFloats(actual float64, operator, expected string) bool {
	target, err := parseFloat(expected)
	if err != nil {
		return false
	}
	switch operator {
	case "exact":
		return actual == target
	case "not_equal":
		return actual != target
	case "gt":
		return actual > target
	case "lt":
		return actual < target
	case "gte":
		return actual >= target
	case "lte":
		return actual <= target
	default:
		return false
	}
}

func toUint64(value interface{}) (uint64, bool) {
	switch v := value.(type) {
	case float64:
		return uint64(v), true
	case int:
		return uint64(v), true
	case int64:
		return uint64(v), true
	case uint64:
		return v, true
	case json.Number:
		parsed, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return uint64(parsed), true
	default:
		return 0, false
	}
}

func toFloat64(value interface{}) (float64, bool) {
	switch v := value.(type) {
	case float64:
		return v, true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case json.Number:
		parsed, err := v.Float64()
		if err != nil {
			return 0, false
		}
		return parsed, true
	default:
		return 0, false
	}
}

func parseFloat(value string) (float64, error) {
	return json.Number(strings.TrimSpace(value)).Float64()
}
