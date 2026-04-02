# Development Guide

**English** | [中文](development.zh-CN.md)

## Frontend Development Mode

The Go binary embeds frontend assets at compile time via `//go:embed all:out` in `frontend/embed.go`. By default, every frontend change requires rebuilding the Go binary (`make build-frontend && make build-go`).

To speed up frontend development, set the `AGENTSIGHT_FRONTEND_DIR` environment variable so the server loads frontend assets directly from disk instead of the embedded `embed.FS`:

### Setup

```sh
# 1. Build frontend
make build-frontend

# 2. Start with environment variable
AGENTSIGHT_FRONTEND_DIR=./frontend/out sudo -E ./agentsight record -c claude --binary-path <path>
```

After each frontend change:

```sh
make build-frontend
# Restart agentsight — no need to recompile Go
```

For live development with hot reload:

```sh
# Terminal 1: Start the backend (API server)
sudo ./agentsight record -c python --server-port 7395

# Terminal 2: Start Next.js dev server
make frontend-dev
# Dev server runs on http://localhost:3000, proxies API to :7395
```

### How It Works

- On startup, the server checks the `AGENTSIGHT_FRONTEND_DIR` environment variable.
- **Set** — Reads files directly from the specified directory. The directory must contain `index.html`.
- **Not set** — Uses embedded assets from `embed.FS` (compiled into the binary).

### Notes

- Use `sudo -E` to preserve environment variables under sudo.
- Both relative paths (e.g., `./frontend/out`) and absolute paths are supported.
- Do not set this variable in production; the embedded assets will be used normally.

## Project Directory Structure

```
agentsight_go/
├── cmd/agentsight/           # CLI entry point (Cobra commands)
│   ├── main.go               # Root command, global flags, config init
│   ├── record.go             # record subcommand (optimized defaults)
│   ├── trace.go              # trace subcommand (flexible combined monitoring)
│   ├── ssl.go                # ssl subcommand (standalone SSL monitoring)
│   ├── process.go            # process subcommand (standalone process monitoring)
│   ├── system.go             # system subcommand (CPU/memory monitoring)
│   └── stdio.go              # stdio subcommand (stdin/stdout/stderr capture)
│
├── internal/
│   ├── bpf/                  # bpf2go generated Go bindings
│   │   ├── sslsniff/         # SSL sniffing eBPF bindings
│   │   │   ├── gen.go        # //go:generate directive for bpf2go
│   │   │   ├── loader.go     # eBPF program loader
│   │   │   └── *_bpfel.go    # Generated: Go types + embedded .o
│   │   ├── process/          # Process tracing eBPF bindings
│   │   └── stdiocap/         # Stdio capture eBPF bindings
│   │
│   ├── runtime/
│   │   ├── event/            # Unified Event struct definition
│   │   │   └── event.go      # Event type, timestamp helpers
│   │   ├── bpf/              # eBPF program loading wrappers
│   │   │   ├── sslsniff/     # SSL eBPF loader
│   │   │   ├── process/      # Process eBPF loader
│   │   │   └── stdiocap/     # Stdio eBPF loader
│   │   └── collectors/       # Runner implementations (event sources)
│   │       ├── base/         # Shared base collector logic
│   │       ├── ssl/          # SSL collector (Runner)
│   │       ├── process/      # Process collector (Runner)
│   │       ├── system/       # System resource collector (Runner, reads /proc)
│   │       └── stdio/        # Stdio collector (Runner)
│   │
│   ├── pipeline/
│   │   ├── types/            # Core interfaces: Runner, Analyzer, Sink, MetricsReporter
│   │   │   └── types.go
│   │   ├── core/             # Analyzer chain builder (Chain function)
│   │   │   └── chain.go
│   │   ├── transforms/       # Analyzer implementations
│   │   │   ├── sslfilter.go          # SSL event filter
│   │   │   ├── ssemerger.go          # SSE chunk merger
│   │   │   ├── httpparser.go         # HTTP request/response parser
│   │   │   ├── httpfilter.go         # HTTP event filter
│   │   │   ├── authremover.go        # Sensitive header removal
│   │   │   ├── toolcall.go           # Tool call aggregator
│   │   │   ├── toolcall_http.go      # HTTP-based tool call detection
│   │   │   ├── toolcall_process.go   # Process-based tool call detection
│   │   │   └── sse_parse.go          # SSE parsing utilities
│   │   └── stream/           # Multi-source stream utilities
│   │       ├── combined.go   # CombinedRunner (merges multiple Runners)
│   │       └── merge.go      # MergeStreams (merges multiple channels)
│   │
│   ├── interfaces/
│   │   ├── http/             # Gin web server, SSE endpoint, event hub
│   │   │   ├── server.go     # Router setup, static file serving
│   │   │   ├── event_hub.go  # Event storage and SSE broadcasting
│   │   │   └── assets.go     # Frontend asset resolution (embed.FS or disk)
│   │   └── sink/             # Output sinks
│   │       ├── filelogger.go # File logger with rotation
│   │       └── output.go     # Console output
│   │
│   └── command/              # Shared command execution helper
│       └── execute.go        # Execute() helper for single-runner commands
│
├── bpf/                      # C eBPF source files
│   ├── sslsniff.bpf.c       # SSL/TLS interception (uprobe)
│   ├── sslsniff.h            # SSL data structures
│   ├── process.bpf.c        # Process lifecycle tracing (tracepoint)
│   ├── process.h             # Process data structures
│   ├── stdiocap.bpf.c       # Stdio capture (tracepoint)
│   └── stdiocap.h            # Stdio data structures
│
├── frontend/                 # Next.js/React/TypeScript frontend
│   ├── embed.go              # //go:embed all:out (embeds static assets)
│   ├── src/                  # React source code
│   ├── out/                  # Build output (static export)
│   ├── package.json          # npm dependencies
│   └── next.config.js        # Next.js configuration
│
├── vmlinux/                  # Architecture-specific vmlinux.h headers
│   └── x86/
│
├── Makefile                  # Build system
├── go.mod / go.sum           # Go module definition
└── CLAUDE.md                 # Claude Code development guidance
```

## Key Go Interfaces

All core interfaces are defined in `internal/pipeline/types/types.go`:

```go
// Runner produces events from a data source (eBPF, /proc, etc.)
type Runner interface {
    ID() string
    Name() string
    Run(ctx context.Context) (<-chan *runtimeevent.Event, error)
    Stop() error
}

// Analyzer transforms an input event stream into an output event stream
type Analyzer interface {
    Name() string
    Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event
}

// Sink consumes events for side effects (logging, export) without producing output
type Sink interface {
    Name() string
    Consume(ctx context.Context, in <-chan *runtimeevent.Event)
}

// MetricsReporter is an optional interface for analyzers that report metrics
type MetricsReporter interface {
    ReportMetrics()
}
```

## Adding a New Analyzer

1. Create a new file in `internal/pipeline/transforms/`, e.g., `myanalyzer.go`
2. Implement the `Analyzer` interface:

```go
package transforms

import (
    "context"
    runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

type MyAnalyzer struct {
    // configuration fields
}

func NewMyAnalyzer() *MyAnalyzer {
    return &MyAnalyzer{}
}

func (a *MyAnalyzer) Name() string {
    return "my-analyzer"
}

func (a *MyAnalyzer) Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event {
    out := make(chan *runtimeevent.Event, 64)
    go func() {
        defer close(out)
        for {
            select {
            case <-ctx.Done():
                return
            case evt, ok := <-in:
                if !ok {
                    return
                }
                // Transform or filter evt here
                out <- evt
            }
        }
    }()
    return out
}
```

3. Optionally implement `MetricsReporter` for metrics reporting on SIGINT
4. Add the analyzer to the pipeline in the relevant command file (e.g., `cmd/agentsight/trace.go`):

```go
analyzers = append(analyzers, pipelinetransforms.NewMyAnalyzer())
```

## Adding a New Collector (Runner)

1. Create a new package under `internal/runtime/collectors/`, e.g., `internal/runtime/collectors/myrunner/`
2. Implement the `Runner` interface:

```go
package myrunner

import (
    "context"
    runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

type Config struct {
    // configuration fields
}

type Runner struct {
    config Config
    cancel context.CancelFunc
}

func New(cfg Config) *Runner {
    return &Runner{config: cfg}
}

func (r *Runner) ID() string   { return "my-runner" }
func (r *Runner) Name() string { return "My Runner" }

func (r *Runner) Run(ctx context.Context) (<-chan *runtimeevent.Event, error) {
    ctx, r.cancel = context.WithCancel(ctx)
    out := make(chan *runtimeevent.Event, 256)

    go func() {
        defer close(out)
        // Read events from data source and send to out channel
        // For eBPF: load program, attach probes, read ring buffer
        // For /proc: poll periodically
    }()

    return out, nil
}

func (r *Runner) Stop() error {
    if r.cancel != nil {
        r.cancel()
    }
    return nil
}
```

3. Register the runner in the appropriate command file under `cmd/agentsight/`
4. For eBPF-based runners, use the eBPF loader from `internal/runtime/bpf/`

## Adding a New eBPF Program (bpf2go Flow)

1. **Write the C eBPF program**: Create `bpf/myprogram.bpf.c` and `bpf/myprogram.h`
   - Use CO-RE (Compile Once, Run Everywhere) pattern
   - Include architecture-specific `vmlinux.h` from `vmlinux/`
   - Communicate with userspace via ring buffers (not JSON stdout)

2. **Create the Go binding package**: Create `internal/bpf/myprogram/gen.go`:

```go
package myprogram

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target amd64 -type my_event_t myprogram ../../../bpf/myprogram.bpf.c -- -I../../../vmlinux/x86
```

3. **Generate Go bindings**: Run `make build-bpf` or `go generate ./internal/bpf/myprogram/...`
   - This generates `myprogram_x86_bpfel.go` with Go types and embedded compiled BPF object

4. **Create a loader**: Add `internal/bpf/myprogram/loader.go` to load and configure the eBPF program

5. **Create a collector**: Add `internal/runtime/collectors/myrunner/` implementing the `Runner` interface, using the loader to read events from ring buffers

6. **Register the CLI command**: Add a new command file in `cmd/agentsight/` or integrate into existing `trace` command

## Build System

| Makefile Target | Description |
|----------------|-------------|
| `make build-all` | Full build: BPF generation + frontend + Go binary |
| `make build-bpf` | Generate BPF Go bindings via `go generate ./internal/bpf/...` |
| `make build-frontend` | Build Next.js frontend as static export to `frontend/out/` |
| `make build-go` | Compile Go binary (uses existing BPF bindings) |
| `make frontend-dev` | Start Next.js development server with hot reload |
| `make deps` | Install all dependencies (Go modules, bpf2go, npm packages) |
| `make test` | Run Go tests (`go test -v ./...`) |
| `make clean` | Remove build artifacts |

## Testing

```sh
# Run all Go tests
make test

# Run tests for a specific package
go test -v ./internal/pipeline/transforms/...

# Run a specific test
go test -v -run TestMyFunction ./internal/pipeline/transforms/
```

## Debugging

### eBPF Program Issues

- Ensure you have root privileges or `CAP_BPF` + `CAP_SYS_ADMIN`
- Verify kernel version: `uname -r` (4.1+ required, 5.0+ recommended)
- Check eBPF verifier output for program loading errors
- Use `bpftool prog list` to see loaded eBPF programs

### Frontend Issues

- Check `AGENTSIGHT_FRONTEND_DIR` is set correctly for development
- Verify `frontend/out/` contains `index.html` after building
- Check browser console for JavaScript errors
- API endpoint: `/api/analytics/timeline` (query from DuckDB)

### Pipeline Debugging

- Use the `--quiet=false` flag to see events on console
- Check log file output with `--log-file`
- Analyzers implementing `MetricsReporter` print statistics on SIGINT (Ctrl+C)
