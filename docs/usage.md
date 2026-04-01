# Usage Guide

**English** | [中文](usage.zh-CN.md)

## Building from Source

### 1. Clone the repository and initialize submodules

```sh
git clone https://github.com/haolipeng/LLM-Scope.git --recursive
cd LLM-Scope
```

If you have already cloned the repository but the submodule directories are empty, run:

```sh
git submodule update --init --recursive
```

### 2. Install dependencies

```sh
make deps
```

This installs:
- Go module dependencies (`go mod download`)
- bpf2go code generation tool (`github.com/cilium/ebpf/cmd/bpf2go@v0.17.3`)
- Frontend npm packages (`cd frontend && npm install`)

System-level build dependencies (Ubuntu/Debian):

```sh
sudo apt-get install -y clang llvm libelf-dev zlib1g-dev
```

### 3. Build

```sh
make build-all
```

After a successful build, the `agentsight` binary is located in the project root directory (`./agentsight`).

You can also build individual components:

```sh
make build-bpf        # Generate BPF Go bindings via bpf2go (requires clang)
make build-frontend   # Build Next.js frontend as static export (frontend/out/)
make build-go         # Compile Go binary only (uses existing BPF bindings)
```

## CLI Commands

### record - Out-of-the-box Agent Recording

The `record` command provides optimized defaults for monitoring AI agents. It automatically enables SSL monitoring, process monitoring, system resource monitoring, and the web server.

```sh
# Basic usage (--comm is required)
sudo ./agentsight record -c claude --binary-path ~/.local/share/claude/versions/<version>

# Monitor Python AI tools
sudo ./agentsight record -c python

# Custom log file and port
sudo ./agentsight record -c python --log-file /tmp/agent.log --server-port 8080
```

**Preset behavior:**
- SSL monitoring: enabled with optimized filters
- Process monitoring: enabled
- System monitoring: enabled (10s interval)
- Web server: enabled on port 7395
- Console output: quiet (logs to file only)
- Log rotation: enabled (10MB max)

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--comm` | `-c` | (required) | Process name to monitor |
| `--binary-path` | | | Path to binary with statically-linked SSL |
| `--log-file` | `-o` | `record.log` | Log file path |
| `--server-port` | | `7395` | Web server port |
| `--rotate-logs` | | `true` | Enable log rotation |
| `--max-log-size` | | `10` | Maximum log size in MB |

### trace - Flexible Combined Monitoring

The `trace` command provides maximum flexibility, allowing you to toggle each monitoring source independently.

```sh
# SSL + process monitoring with web UI
sudo ./agentsight trace --ssl true --process true --server true --comm claude

# Full monitoring stack
sudo ./agentsight trace --ssl true --process true --system true --comm python \
  --binary-path /usr/bin/python3

# Stdio capture for a specific process
sudo ./agentsight trace --stdio true --pid 12345 --ssl false --process false

# Custom SSL filters
sudo ./agentsight trace --ssl true --process false \
  --ssl-filter "data=0\r\n\r\n" \
  --http-filter "request.path_prefix=/v1/messages"
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--ssl` | | `true` | Enable SSL monitoring |
| `--process` | | `true` | Enable process monitoring |
| `--system` | | `false` | Enable system resource monitoring |
| `--stdio` | | `false` | Enable stdio monitoring (requires `--pid`) |
| `--comm` | `-c` | | Process name filter (comma-separated) |
| `--pid` | `-p` | `0` | PID filter |
| `--binary-path` | | | Path to binary with statically-linked SSL |
| `--ssl-uid` | | `0` | SSL UID filter |
| `--ssl-filter` | | | SSL filter expressions |
| `--ssl-handshake` | | `false` | Show SSL handshake events |
| `--ssl-http` | | `true` | Enable HTTP parsing |
| `--ssl-raw-data` | | `false` | Include raw data in output |
| `--http-filter` | | | HTTP filter expressions |
| `--disable-auth-removal` | | `false` | Disable sensitive header removal |
| `--duration` | | `0` | Minimum process duration (ms) |
| `--mode` | | `0` | Process filter mode (0=all, 1=proc, 2=filter) |
| `--system-interval` | | `10` | System monitoring interval (seconds) |
| `--stdio-uid` | | `0` | Stdio UID filter |
| `--stdio-comm` | | | Stdio process name filter |
| `--stdio-all-fds` | | `false` | Capture all file descriptors |
| `--stdio-max-bytes` | | `8192` | Max bytes per stdio event |

### ssl - Standalone SSL Monitoring

Monitor SSL/TLS traffic independently with fine-grained control.

```sh
# Basic SSL monitoring
sudo ./agentsight ssl

# With HTTP parsing
sudo ./agentsight ssl --http-parser

# With SSE merge and HTTP parsing
sudo ./agentsight ssl --sse-merge --http-parser

# With filters
sudo ./agentsight ssl --http-parser \
  --ssl-filter "data=0\r\n\r\n|data.type=binary" \
  --http-filter "request.path_prefix=/v1/rgstr | response.status_code=202"

# With binary path for statically-linked SSL
sudo ./agentsight ssl --http-parser --binary-path ~/.nvm/versions/node/v20.0.0/bin/node
```

| Flag | Default | Description |
|------|---------|-------------|
| `--sse-merge` | `false` | Enable SSE event merging |
| `--http-parser` | `false` | Enable HTTP parsing |
| `--http-raw-data` | `false` | Include raw data in parsed output |
| `--http-filter` | | HTTP filter expressions |
| `--ssl-filter` | | SSL filter expressions |
| `--disable-auth-removal` | `false` | Disable sensitive header removal |
| `--binary-path` | | Path to binary with statically-linked SSL |

### process - Standalone Process Monitoring

Track process execution and lifecycle events.

```sh
# Monitor all processes
sudo ./agentsight process

# Filter by process name
sudo ./agentsight process -c python

# Filter by PID with minimum duration
sudo ./agentsight process -p 12345 -d 100
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--comm` | `-c` | | Process name filter (comma-separated) |
| `--pid` | `-p` | `0` | PID filter |
| `--duration` | `-d` | `0` | Minimum process duration (ms) |
| `--mode` | `-m` | `0` | Filter mode: 0=all, 1=proc, 2=filter |

### system - System Resource Monitoring

Monitor CPU and memory usage for target processes.

```sh
# Monitor by process name
sudo ./agentsight system -c python

# Monitor by PID with alerts
sudo ./agentsight system -p 12345 --cpu-threshold 80 --memory-threshold 1024

# Custom interval, exclude child processes
sudo ./agentsight system -c node -i 5 --no-children
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--interval` | `-i` | `10` | Monitoring interval (seconds) |
| `--pid` | `-p` | `0` | Monitor specific PID |
| `--comm` | `-c` | | Filter by process name |
| `--no-children` | | `false` | Exclude child processes |
| `--cpu-threshold` | | `0` | CPU alert threshold (%) |
| `--memory-threshold` | | `0` | Memory alert threshold (MB) |

### stdio - Standard I/O Capture

Capture stdin/stdout/stderr of a target process. Useful for monitoring local MCP servers communicating over stdio.

```sh
# Capture stdio for a specific PID (required)
sudo ./agentsight stdio -p 12345

# Capture all file descriptors
sudo ./agentsight stdio -p 12345 --all-fds

# Filter by process name with custom max bytes
sudo ./agentsight stdio -p 12345 -c mcp-server --max-bytes 16384
```

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--pid` | `-p` | (required) | Target process PID |
| `--uid` | `-u` | `0` | UID filter |
| `--comm` | `-c` | | Process name filter |
| `--all-fds` | | `false` | Capture all file descriptors |
| `--max-bytes` | | `8192` | Max bytes per event |

## Global Flags

These flags are available for all subcommands:

| Flag | Short | Default | Description |
|------|-------|---------|-------------|
| `--server` | | `false` | Start web server (auto-enabled for `record`) |
| `--server-port` | | `7395` | Web server port |
| `--log-file` | `-o` | | Log file path |
| `--quiet` | `-q` | `false` | Disable console output |
| `--rotate-logs` | | `false` | Enable log rotation |
| `--max-log-size` | | `10` | Maximum log size in MB |

## Advanced Usage

### Filter Expressions

#### SSL Filters (`--ssl-filter`)

SSL filters operate on raw SSL event data. Multiple conditions are separated by `|` (OR logic). Use `--ssl-filter` to exclude unwanted SSL events.

```sh
# Filter out empty chunk transfer endings and binary data
--ssl-filter "data=0\r\n\r\n|data.type=binary"
```

#### HTTP Filters (`--http-filter`)

HTTP filters operate on parsed HTTP request/response pairs. Multiple conditions are separated by `|` (OR logic). Use `--http-filter` to exclude unwanted HTTP events.

```sh
# Filter out registration endpoints, 202 responses, HEAD requests, and empty response bodies
--http-filter "request.path_prefix=/v1/rgstr | response.status_code=202 | request.method=HEAD | response.body="
```

Supported filter fields:
- `request.path_prefix` — Match request path prefix
- `request.method` — Match HTTP method (GET, POST, HEAD, etc.)
- `response.status_code` — Match response status code
- `response.body` — Match response body content (empty value matches empty bodies)

### `--binary-path` Explained

By default, LLM-Scope hooks the system's shared `libssl.so` to intercept SSL traffic. However, some applications bundle their own SSL library statically:

- **Claude Code (Bun)**: Statically links BoringSSL with symbols stripped
- **NVM Node.js**: Statically links OpenSSL

For these applications, use `--binary-path` to point directly to the application binary:

```sh
# Claude Code
sudo ./agentsight record -c claude --binary-path ~/.local/share/claude/versions/$(claude --version | head -1)

# NVM Node.js
sudo ./agentsight record -c node --binary-path ~/.nvm/versions/node/v20.0.0/bin/node
```

When `--binary-path` is specified:
1. LLM-Scope attempts symbol lookup first
2. Falls back to BoringSSL byte-pattern detection for stripped binaries
3. The `--comm` filter is **NOT** applied to SSL monitoring (only to process monitoring), because `bpf_get_current_comm()` returns the thread name rather than the process name

### Web Interface

When the web server is enabled (`--server` flag or `record` command), visit:

- **http://127.0.0.1:7395** — Main dashboard
- **http://127.0.0.1:7395/timeline** — Timeline view
- **http://127.0.0.1:7395/tree** — Process tree view
- **http://127.0.0.1:7395/logs** — Raw log view
- **http://127.0.0.1:7395/metrics** — Metrics view

The frontend supports i18n with Chinese/English language switching.
