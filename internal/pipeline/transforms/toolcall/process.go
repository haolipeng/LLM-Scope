package toolcall

import (
	"encoding/json"
	"fmt"
	"strings"

	transforms "github.com/haolipeng/LLM-Scope/internal/pipeline/transforms"
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

// Noise file path rules — declarative tables for easy extension.
var (
	noisePrefixes = []string{
		"/proc/", "/sys/", "/dev/",
		"/usr/lib/", "/lib/", "/usr/share/",
	}
	noiseSuffixes = []string{".so", ".lock", ".pid"}
	noiseContains = []string{".so.", ".cursor-server/", "/node_modules/", "/.git/objects/"}
)

func isNoiseFilePath(path string) bool {
	for _, p := range noisePrefixes {
		if strings.HasPrefix(path, p) {
			return true
		}
	}
	if strings.HasPrefix(path, "/etc/") {
		return path == "/etc/ld.so.cache" || strings.HasPrefix(path, "/etc/ld.so")
	}
	for _, s := range noiseSuffixes {
		if strings.HasSuffix(path, s) {
			return true
		}
	}
	for _, c := range noiseContains {
		if strings.Contains(path, c) {
			return true
		}
	}
	if strings.HasPrefix(path, ".git/objects/") {
		return true
	}
	return false
}

func (e *processToolCallExtractor) extractFileOpen(payload map[string]interface{}) []toolCallExtraction {
	flagsValue, _ := transforms.ToUint64(payload["flags"])
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
