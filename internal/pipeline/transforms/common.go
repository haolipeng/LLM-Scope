package transforms

import (
	"encoding/hex"
	"encoding/json"
	"strings"
)

func detectDataType(data string) string {
	for _, r := range data {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return "binary"
		}
	}
	return "text"
}

func dataToString(data string) string {
	if detectDataType(data) == "text" {
		return data
	}
	return "HEX:" + hex.EncodeToString([]byte(data))
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

func parseFloat(value string) (float64, error) {
	return json.Number(strings.TrimSpace(value)).Float64()
}

func parseUint(value string) (uint64, error) {
	parsed, err := json.Number(strings.TrimSpace(value)).Int64()
	if err != nil {
		return 0, err
	}
	return uint64(parsed), nil
}

func parseInt(value string) (int64, error) {
	return json.Number(strings.TrimSpace(value)).Int64()
}

func splitAndTrim(value, sep string) []string {
	parts := strings.Split(value, sep)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

func mapStringMap(value interface{}) map[string]string {
	out := map[string]string{}
	raw, ok := value.(map[string]interface{})
	if !ok {
		return out
	}
	for k, v := range raw {
		if s, ok := v.(string); ok {
			out[strings.ToLower(k)] = s
		}
	}
	return out
}
