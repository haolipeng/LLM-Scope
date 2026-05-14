package transforms

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"

	"github.com/haolipeng/LLM-Scope/internal/event"
)

var (
	globalSSLFilterTotal    atomic.Int64
	globalSSLFilterFiltered atomic.Int64
	globalSSLFilterPassed   atomic.Int64
)

func PrintGlobalSSLFilterMetrics() {
	total := globalSSLFilterTotal.Load()
	filtered := globalSSLFilterFiltered.Load()
	passed := globalSSLFilterPassed.Load()
	if total > 0 {
		fmt.Printf("[SSL Filter] Total: %d, Filtered: %d, Passed: %d\n", total, filtered, passed)
	}
}

type SSLFilter struct {
	filters  []sslFilterExpression
	total    atomic.Int64
	filtered atomic.Int64
	passed   atomic.Int64
	inner    *mapAnalyzer
}

func NewSSLFilter(patterns []string) *SSLFilter {
	filters := make([]sslFilterExpression, 0, len(patterns))
	for _, pattern := range patterns {
		filters = append(filters, parseSSLFilter(pattern))
	}
	f := &SSLFilter{filters: filters}
	f.inner = NewMapAnalyzer("ssl_filter", f.processEvent)
	return f
}

func (f *SSLFilter) Name() string {
	return "ssl_filter"
}

func (f *SSLFilter) Process(ctx context.Context, in <-chan *event.Event) <-chan *event.Event {
	return f.inner.Process(ctx, in)
}

func (f *SSLFilter) processEvent(ev *event.Event) []*event.Event {
	if ev.Source == "ssl" {
		f.total.Add(1)
		globalSSLFilterTotal.Add(1)
		if f.shouldFilter(ev.Data) {
			f.filtered.Add(1)
			globalSSLFilterFiltered.Add(1)
			return nil
		}
		f.passed.Add(1)
		globalSSLFilterPassed.Add(1)
	}
	return []*event.Event{ev}
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
				operator: mapSSLJoin(op),
				value:    decodeEscapes(value),
			}
		}
	}

	return sslFilterNode{op: "empty"}
}

func mapSSLJoin(op string) string {
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

func (f *SSLFilter) shouldFilter(raw json.RawMessage) bool {
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

type sslFieldEvaluator func(data map[string]interface{}, node sslFilterNode) bool

func evalSSLStringField(field string) sslFieldEvaluator {
	return func(data map[string]interface{}, node sslFilterNode) bool {
		if value, ok := data[field].(string); ok {
			return compareStrings(value, node.operator, node.value)
		}
		return false
	}
}

func evalSSLBoolField(field string) sslFieldEvaluator {
	return func(data map[string]interface{}, node sslFilterNode) bool {
		if value, ok := data[field].(bool); ok {
			return (value && node.value == "true") || (!value && node.value == "false")
		}
		return false
	}
}

func evalSSLUint64Field(field string) sslFieldEvaluator {
	return func(data map[string]interface{}, node sslFilterNode) bool {
		if value, ok := toUint64(data[field]); ok {
			return compareNumbers(value, node.operator, node.value)
		}
		return false
	}
}

func evalSSLFloat64Field(field string) sslFieldEvaluator {
	return func(data map[string]interface{}, node sslFilterNode) bool {
		if value, ok := toFloat64(data[field]); ok {
			return compareFloats(value, node.operator, node.value)
		}
		return false
	}
}

var sslFieldEvaluators = map[string]sslFieldEvaluator{
	"data.type": func(data map[string]interface{}, node sslFilterNode) bool {
		if value, ok := data["data"].(string); ok {
			return compareStrings(detectDataType(value), node.operator, node.value)
		}
		return false
	},
	"data":         evalSSLStringField("data"),
	"function":     evalSSLStringField("function"),
	"comm":         evalSSLStringField("comm"),
	"is_handshake": evalSSLBoolField("is_handshake"),
	"truncated":    evalSSLBoolField("truncated"),
	"len":          evalSSLUint64Field("len"),
	"pid":          evalSSLUint64Field("pid"),
	"tid":          evalSSLUint64Field("tid"),
	"uid":          evalSSLUint64Field("uid"),
	"timestamp_ns": evalSSLUint64Field("timestamp_ns"),
	"latency_ms":   evalSSLFloat64Field("latency_ms"),
}

func evalSSLCondition(node sslFilterNode, data map[string]interface{}) bool {
	if fn, ok := sslFieldEvaluators[node.field]; ok {
		return fn(data, node)
	}
	return false
}

func (f *SSLFilter) ReportMetrics() {
	total := f.total.Load()
	filtered := f.filtered.Load()
	passed := f.passed.Load()
	if total > 0 {
		fmt.Printf("[SSL Filter] Total: %d, Filtered: %d, Passed: %d\n", total, filtered, passed)
	}
}
