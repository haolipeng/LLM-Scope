package transforms

import (
	"encoding/hex"
	"encoding/json"
	"strings"
)

func DetectDataType(data string) string {
	for _, r := range data {
		if r < 0x20 && r != '\n' && r != '\r' && r != '\t' {
			return "binary"
		}
	}
	return "text"
}

func DataToString(data string) string {
	if DetectDataType(data) == "text" {
		return data
	}
	return "HEX:" + hex.EncodeToString([]byte(data))
}

func ToUint64(value interface{}) (uint64, bool) {
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

func ToFloat64(value interface{}) (float64, bool) {
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

func CompareStrings(actual, operator, expected string) bool {
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

func CompareNumbers(actual uint64, operator, expected string) bool {
	target, err := ParseUint(expected)
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

func CompareFloats(actual float64, operator, expected string) bool {
	target, err := ParseFloat(expected)
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

func ParseFloat(value string) (float64, error) {
	return json.Number(strings.TrimSpace(value)).Float64()
}

func ParseUint(value string) (uint64, error) {
	parsed, err := json.Number(strings.TrimSpace(value)).Int64()
	if err != nil {
		return 0, err
	}
	return uint64(parsed), nil
}

func ParseInt(value string) (int64, error) {
	return json.Number(strings.TrimSpace(value)).Int64()
}

func SplitAndTrim(value, sep string) []string {
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

func MapStringMap(value interface{}) map[string]string {
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
