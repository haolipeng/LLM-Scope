package transforms

import (
	"encoding/json"
	"fmt"
	"strings"
)

type toolCallExtraction struct {
	toolName    string
	keyField    string
	argsSummary string
	bytes       int64
	immediate   bool
}

type toolCallExtractor interface {
	Source() string
	Extract(data json.RawMessage) []toolCallExtraction
}

type processToolCallExtractor struct{}

func (e *processToolCallExtractor) Source() string { return "process" }

func (e *processToolCallExtractor) Extract(data json.RawMessage) []toolCallExtraction {
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return nil
	}
	eventType, _ := payload["event"].(string)

	switch eventType {
	case "EXEC":
		return e.extractExec(payload)
	case "FILE_OPEN":
		return e.extractFileOpen(payload)
	default:
		return nil
	}
}

func (e *processToolCallExtractor) extractExec(payload map[string]interface{}) []toolCallExtraction {
	filename := getStringValue(payload["filename"], "")
	fullCommand := getStringValue(payload["full_command"], "")
	if filename == "" {
		return nil
	}
	argsSummary := fullCommand
	if argsSummary == "" {
		argsSummary = filename
	}
	return []toolCallExtraction{{
		toolName:    "proc.exec",
		keyField:    filename,
		argsSummary: argsSummary,
		immediate:   true,
	}}
}

func isNoiseFilePath(filepath string) bool {
	if strings.HasPrefix(filepath, "/proc/") {
		return true
	}
	if strings.HasPrefix(filepath, "/sys/") || strings.HasPrefix(filepath, "/dev/") {
		return true
	}
	if strings.HasPrefix(filepath, "/usr/lib/") ||
		strings.HasPrefix(filepath, "/lib/") ||
		strings.HasPrefix(filepath, "/usr/share/") {
		return true
	}
	if strings.HasPrefix(filepath, "/etc/") {
		return filepath == "/etc/ld.so.cache" || strings.HasPrefix(filepath, "/etc/ld.so")
	}
	if strings.HasSuffix(filepath, ".so") || strings.Contains(filepath, ".so.") {
		return true
	}
	if strings.Contains(filepath, ".cursor-server/") {
		return true
	}
	if strings.Contains(filepath, "/node_modules/") {
		return true
	}
	if strings.HasPrefix(filepath, ".git/objects/") || strings.Contains(filepath, "/.git/objects/") {
		return true
	}
	if strings.HasSuffix(filepath, ".lock") || strings.HasSuffix(filepath, ".pid") {
		return true
	}
	return false
}

func (e *processToolCallExtractor) extractFileOpen(payload map[string]interface{}) []toolCallExtraction {
	flagsValue, _ := toUint64(payload["flags"])
	filepath := getStringValue(payload["filepath"], "")
	if filepath == "" {
		return nil
	}

	toolName := classifyFileTool(flagsValue)
	if toolName == "" {
		return nil
	}

	if isNoiseFilePath(filepath) {
		return nil
	}

	return []toolCallExtraction{{
		toolName:    toolName,
		keyField:    filepath,
		argsSummary: fmt.Sprintf("path=%s flags=%d", filepath, flagsValue),
		immediate:   false,
	}}
}
