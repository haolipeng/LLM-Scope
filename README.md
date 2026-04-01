# LLM-Scope: Zero-Instrumentation LLM Agent Observability with eBPF

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://go.dev/)

**English** | [中文](README.zh-CN.md)

LLM-Scope is an observability tool designed specifically for monitoring LLM agent behavior through SSL/TLS traffic interception and process monitoring. Unlike traditional application-level instrumentation, LLM-Scope observes at the system boundary using eBPF technology, providing comprehensive insights into AI agent interactions with minimal performance overhead.

**Zero Instrumentation Required** - No code changes, no new dependencies, no SDKs. Works with any AI framework or application out of the box.

## Quick Start

```bash
# Clone and build from source
git clone https://github.com/haolipeng/LLM-Scope.git --recursive
cd LLM-Scope
make deps
make build-all

# Record Claude Code activity (Bun-based, requires --binary-path for statically-linked BoringSSL)
sudo ./agentsight record -c claude --binary-path ~/.local/share/claude/versions/$(claude --version | head -1)

# For Python AI tools (e.g. aider, open-interpreter)
sudo ./agentsight record -c "python"

# For Node.js apps with NVM (statically-linked OpenSSL)
sudo ./agentsight record -c node --binary-path ~/.nvm/versions/node/v20.0.0/bin/node
```

Visit [http://127.0.0.1:7395](http://127.0.0.1:7395) to view the recorded data.

## Why LLM-Scope?

### Traditional Observability vs. System-Level Monitoring

| **Challenge** | **Application-Level Tools** | **LLM-Scope Solution** |
|---------------|----------------------------|------------------------|
| **Framework Adoption** | New SDK/proxy for each framework | Drop-in daemon, no code changes |
| **Closed-Source Tools** | Limited visibility into operations | Complete visibility into prompts & behaviors |
| **Dynamic Agent Behavior** | Logs can be silenced or manipulated | Kernel-level hooks for reliable monitoring |
| **Encrypted Traffic** | Only sees wrapper outputs | Captures real unencrypted requests/responses |
| **System Interactions** | Misses subprocess executions | Tracks all process behaviors & file operations |
| **Multi-Agent Systems** | Isolated per-process tracing | Global correlation and analysis |

LLM-Scope captures critical interactions that application-level tools miss:

- Subprocess executions that bypass instrumentation
- Raw encrypted payloads before agent processing
- File operations and system resource access
- Cross-agent communications and coordination

## Architecture

```ascii
┌─────────────────────────────────────────────────┐
│              AI Agent Runtime                    │
│   ┌─────────────────────────────────────────┐   │
│   │    Application-Level Observability       │   │
│   │  (LangSmith, Helicone, Langfuse, etc.)   │   │
│   │         Can be bypassed                  │   │
│   └─────────────────────────────────────────┘   │
│                     ↕ (Can be bypassed)          │
├─────────────────────────────────────────────────┤ ← System Boundary
│  LLM-Scope eBPF Monitoring (Kernel-level)       │
│  ┌───────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ SSL/TLS   │ │ Process  │ │ Stdio/System │   │
│  │ Traffic   │ │ Events   │ │ Monitoring   │   │
│  └───────────┘ └──────────┘ └──────────────┘   │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│         Go Streaming Analysis Framework         │
│  ┌─────────────┐  ┌──────────────┐  ┌────────┐  │
│  │  Collectors  │  │  Analyzers   │  │ Sinks  │  │
│  │  (Runners)   │  │ (Transforms) │  │        │  │
│  └─────────────┘  └──────────────┘  └────────┘  │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│           Frontend Visualization                │
│   Timeline · Process Tree · Logs · Metrics      │
└─────────────────────────────────────────────────┘
```

### Core Components

1. **eBPF Data Collection** (Kernel Space)
   - **SSL Monitor**: Intercepts SSL/TLS read/write operations via uprobe hooks
   - **Process Monitor**: Tracks process lifecycle and file operations via tracepoints
   - **Stdio Monitor**: Captures stdin/stdout/stderr of target processes
   - **System Monitor**: Collects CPU and memory usage from /proc
   - **<3% Performance Overhead**: Operates below application layer with minimal impact

2. **Go Streaming Framework** (User Space)
   - **Collectors (Runners)**: Load eBPF programs and read events from ring buffers (SSL, Process, System, Stdio)
   - **Analyzers**: Pluggable processors for SSE merging, HTTP parsing, filtering, auth header removal, tool call aggregation
   - **Sinks**: Output destinations — file logger, console output, SSE event hub
   - **Pipeline**: Channel-based event streaming with analyzer chains

3. **Frontend Visualization** (React/TypeScript)
   - Interactive timeline, process tree, and log views
   - Real-time metrics visualization (CPU, memory)
   - i18n support for Chinese/English language switching
   - See "Web Interface" section for details

### Data Flow Pipeline

```
eBPF Programs → Ring Buffer → Collectors → Analyzer Chain → Sinks/Frontend
```

## Usage

### Prerequisites

- **Linux kernel**: 4.1+ with eBPF support (5.0+ recommended)
- **Root privileges**: Required for eBPF program loading
- **Go**: 1.22+
- **Node.js**: 18+ (for frontend development)
- **Build tools**: clang, llvm, libelf-dev

### Installation

```bash
# Clone repository with submodules
git clone https://github.com/haolipeng/LLM-Scope.git --recursive
cd LLM-Scope

# Install dependencies (Go modules, bpf2go tool, frontend npm packages)
make deps

# Build all components (BPF code generation + frontend + Go binary)
make build-all

# Or build individually:
# make build-bpf        # Generate BPF Go bindings via bpf2go
# make build-frontend   # Build Next.js frontend as static export
# make build-go         # Compile Go binary only
```

After a successful build, the binary is located at `./agentsight`.

### Usage Examples

#### Monitoring Claude Code

Claude Code is a Bun-based application with BoringSSL statically linked and
symbols stripped. LLM-Scope auto-detects BoringSSL functions via byte-pattern
matching when `--binary-path` is provided:

```bash
# Find the Claude binary version
CLAUDE_BIN=~/.local/share/claude/versions/$(claude --version | head -1)

# Record all Claude activity with web UI
sudo ./agentsight record -c claude --binary-path "$CLAUDE_BIN"
# Open http://127.0.0.1:7395 to view timeline

# Advanced: full trace with custom filters
sudo ./agentsight trace --ssl true --process true --comm claude \
  --binary-path "$CLAUDE_BIN" --server true --server-port 8080
```

This captures:
- **Conversation API**: `POST /v1/messages` requests with full prompt/response SSE streaming
- **Telemetry**: heartbeat, event logging, Datadog logs
- **Process activity**: file operations, subprocess executions

> **Note**: All SSL traffic in Claude flows through an internal "HTTP Client"
> thread, not the main "claude" thread. When `--binary-path` is specified,
> the `--comm` filter is automatically skipped for SSL monitoring (but still
> applied for process monitoring) to ensure traffic is captured correctly.

#### Monitoring Python AI Tools

```bash
# Monitor aider, open-interpreter, or any Python-based AI tool
sudo ./agentsight record -c "python"

# Custom port and log file
sudo ./agentsight record -c "python" --server-port 8080 --log-file /tmp/agent.log
```

#### Monitoring Node.js AI Tools (Gemini CLI, etc.)

For Node.js applications installed via NVM that statically link OpenSSL, use
`--binary-path` to point to the actual Node.js binary:

```bash
# Monitor Gemini CLI or other Node.js AI tools
sudo ./agentsight record -c node --binary-path ~/.nvm/versions/node/v20.0.0/bin/node

# Or with system Node.js (uses dynamic libssl, no --binary-path needed)
sudo ./agentsight record -c node
```

#### Advanced Monitoring

```bash
# Combined SSL and process monitoring with web interface
sudo ./agentsight trace --ssl true --process true --server true

# Enable system resource monitoring
sudo ./agentsight trace --ssl true --process true --system true --comm python

# Capture stdio of a specific process
sudo ./agentsight trace --stdio true --pid 12345 --ssl false --process false
```

### CLI Subcommands

| Command | Description | Key Flags |
|---------|-------------|-----------|
| `record` | Out-of-the-box agent recording with optimized defaults | `--comm` (required), `--binary-path`, `--log-file`, `--server-port` |
| `trace` | Flexible combined monitoring with independent toggles | `--ssl`, `--process`, `--system`, `--stdio`, `--comm`, `--pid`, `--binary-path` |
| `ssl` | Standalone SSL/TLS traffic monitoring | `--http-parser`, `--sse-merge`, `--ssl-filter`, `--http-filter`, `--binary-path` |
| `process` | Standalone process lifecycle monitoring | `--comm`, `--pid`, `--duration`, `--mode` |
| `system` | System resource monitoring (CPU/memory) | `--interval`, `--pid`, `--comm`, `--cpu-threshold`, `--memory-threshold` |
| `stdio` | Standard I/O capture | `--pid` (required), `--comm`, `--all-fds`, `--max-bytes` |

### Web Interface

All monitoring commands with `--server` flag (or `record` which enables it by default) provide web visualization at:
- **Timeline View**: http://127.0.0.1:7395/timeline
- **Process Tree**: http://127.0.0.1:7395/tree
- **Raw Logs**: http://127.0.0.1:7395/logs
- **Metrics**: http://127.0.0.1:7395/metrics

## FAQ

### General

**Q: How does LLM-Scope differ from traditional APM tools?**
A: LLM-Scope operates at the kernel level using eBPF, providing system-level monitoring that is independent of application code. Traditional APM requires instrumentation that can be modified or disabled.

**Q: What's the performance impact?**
A: Less than 3% CPU overhead due to optimized eBPF kernel-space data collection.

**Q: Can agents detect they're being monitored?**
A: Detection is extremely difficult since monitoring occurs at the kernel level without code modification.

### Technical

**Q: Which Linux distributions are supported?**
A: Any distribution with kernel 4.1+ (5.0+ recommended). Tested on Ubuntu 20.04+, CentOS 8+, RHEL 8+.

**Q: Can I monitor multiple agents simultaneously?**
A: Yes, use combined monitoring modes for concurrent multi-agent observation with correlation.

**Q: Why doesn't LLM-Scope capture traffic from Claude Code or NVM Node.js?**
A: These applications statically link their SSL library (BoringSSL for Claude/Bun, OpenSSL for NVM Node.js) instead of using system `libssl.so`. Use `--binary-path` to point to the actual binary so LLM-Scope can auto-detect SSL functions via byte-pattern matching.

**Q: Why does `--comm claude` not capture SSL traffic?**
A: Claude Code's SSL traffic runs on an internal "HTTP Client" thread, not the main "claude" thread. The `--comm` filter in sslsniff matches thread name (from `bpf_get_current_comm()`), not process name. When using `--binary-path`, the collector automatically skips the `--comm` filter for SSL monitoring.

### Troubleshooting

**Q: "Permission denied" errors**
A: Ensure you're running with `sudo` or have `CAP_BPF` and `CAP_SYS_ADMIN` capabilities.

**Q: "Failed to load eBPF program" errors**
A: Verify kernel version meets requirements (see Prerequisites). Update vmlinux.h for your architecture if needed.

## Contributing

We welcome contributions! After cloning and building (see Installation above), you can:

```bash
# Run tests
make test

# Frontend development server with hot reload
make frontend-dev
```

### Key Resources

- [CLAUDE.md](CLAUDE.md) - Project guidelines and architecture
- [docs/usage.md](docs/usage.md) - Detailed usage guide
- [docs/development.md](docs/development.md) - Development guide

## License

MIT License - see [LICENSE](LICENSE) for details.

---

**The Future of AI Observability**: As AI agents become more autonomous and capable of self-modification, traditional observability approaches become insufficient. LLM-Scope provides independent, system-level monitoring for safe AI deployment at scale.
