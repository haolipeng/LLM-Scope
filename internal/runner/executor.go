package runner

import (
	"bufio"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"unicode/utf8"
)

// BinaryExecutor runs an eBPF user-space binary and streams JSON lines.
type BinaryExecutor struct {
	binaryPath string
	args       []string
	cmd        *exec.Cmd
	runnerName string
}

func NewBinaryExecutor(binaryPath string, args []string) *BinaryExecutor {
	return &BinaryExecutor{
		binaryPath: binaryPath,
		args:       args,
	}
}

// WithRunnerName sets a log prefix for this executor.
func (e *BinaryExecutor) WithRunnerName(name string) *BinaryExecutor {
	e.runnerName = name
	return e
}

func (e *BinaryExecutor) logPrefix() string {
	if e.runnerName != "" {
		return fmt.Sprintf("[%s] ", e.runnerName)
	}
	return ""
}

func (e *BinaryExecutor) Run(ctx context.Context) (<-chan json.RawMessage, error) {
	e.cmd = exec.CommandContext(ctx, e.binaryPath, e.args...)
	stdout, err := e.cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}

	stderr, err := e.cmd.StderrPipe()
	if err != nil {
		return nil, err
	}

	if err := e.cmd.Start(); err != nil {
		return nil, err
	}

	// stderr log capture goroutine
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			line := scanner.Text()
			upper := strings.ToUpper(line)
			switch {
			case strings.Contains(upper, "ERROR"):
				log.Printf("%sstderr ERROR: %s", e.logPrefix(), line)
			case strings.Contains(upper, "WARN"):
				log.Printf("%sstderr WARN: %s", e.logPrefix(), line)
			default:
				log.Printf("%sstderr INFO: %s", e.logPrefix(), line)
			}
		}
	}()

	out := make(chan json.RawMessage, 100)
	go func() {
		defer close(out)

		lineNum := 0
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

		for scanner.Scan() {
			lineNum++
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			data := make([]byte, len(line))
			copy(data, line)

			// Validate JSON; if invalid, attempt UTF-8 recovery
			if !json.Valid(data) {
				recovered := tryRecoverUTF8JSON(data)
				if recovered != nil {
					data = recovered
				} else {
					// Debug: show line number and HEX preview
					preview := data
					if len(preview) > 64 {
						preview = preview[:64]
					}
					log.Printf("%sline %d: non-JSON data, HEX: %s",
						e.logPrefix(), lineNum, hex.EncodeToString(preview))
					continue
				}
			}

			select {
			case out <- json.RawMessage(data):
			case <-ctx.Done():
				return
			}
		}
	}()

	return out, nil
}

// tryRecoverUTF8JSON attempts to find a valid UTF-8 prefix that is also valid JSON.
func tryRecoverUTF8JSON(data []byte) []byte {
	// Find the longest valid UTF-8 prefix
	valid := data
	for len(valid) > 0 && !utf8.Valid(valid) {
		valid = valid[:len(valid)-1]
	}
	if len(valid) == 0 {
		return nil
	}

	// Try to parse the valid UTF-8 prefix as JSON
	if json.Valid(valid) {
		result := make([]byte, len(valid))
		copy(result, valid)
		return result
	}

	return nil
}

func (e *BinaryExecutor) Stop() error {
	if e.cmd != nil && e.cmd.Process != nil {
		return e.cmd.Process.Kill()
	}
	return nil
}
