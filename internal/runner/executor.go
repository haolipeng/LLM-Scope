package runner

import (
    "bufio"
    "context"
    "encoding/json"
    "os/exec"
)

// BinaryExecutor runs an eBPF user-space binary and streams JSON lines.
type BinaryExecutor struct {
    binaryPath string
    args       []string
    cmd        *exec.Cmd
}

func NewBinaryExecutor(binaryPath string, args []string) *BinaryExecutor {
    return &BinaryExecutor{
        binaryPath: binaryPath,
        args:       args,
    }
}

func (e *BinaryExecutor) Run(ctx context.Context) (<-chan json.RawMessage, error) {
    e.cmd = exec.CommandContext(ctx, e.binaryPath, e.args...)
    stdout, err := e.cmd.StdoutPipe()
    if err != nil {
        return nil, err
    }

    if err := e.cmd.Start(); err != nil {
        return nil, err
    }

    out := make(chan json.RawMessage, 100)
    go func() {
        defer close(out)

        scanner := bufio.NewScanner(stdout)
        scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

        for scanner.Scan() {
            line := scanner.Bytes()
            if len(line) == 0 {
                continue
            }

            data := make([]byte, len(line))
            copy(data, line)

            select {
            case out <- json.RawMessage(data):
            case <-ctx.Done():
                return
            }
        }
    }()

    return out, nil
}

func (e *BinaryExecutor) Stop() error {
    if e.cmd != nil && e.cmd.Process != nil {
        return e.cmd.Process.Kill()
    }
    return nil
}
