# 使用指南

[English](usage.md) | **中文**

## 从源码构建

### 1. 克隆仓库并初始化子模块

```sh
git clone https://github.com/haolipeng/LLM-Scope.git --recursive
cd LLM-Scope
```

如果已经克隆了仓库但子模块目录为空，请运行：

```sh
git submodule update --init --recursive
```

### 2. 安装依赖

```sh
make deps
```

此命令安装：
- Go 模块依赖（`go mod download`）
- bpf2go 代码生成工具（`github.com/cilium/ebpf/cmd/bpf2go@v0.17.3`）
- 前端 npm 包（`cd frontend && npm install`）

系统级构建依赖（Ubuntu/Debian）：

```sh
sudo apt-get install -y clang llvm libelf-dev zlib1g-dev
```

### 3. 构建

```sh
make build-all
```

构建成功后，`agentsight` 二进制文件位于项目根目录（`./agentsight`）。

也可以单独构建各组件：

```sh
make build-bpf        # 通过 bpf2go 生成 BPF Go 绑定（需要 clang）
make build-frontend   # 构建 Next.js 前端静态导出（frontend/out/）
make build-go         # 仅编译 Go 二进制（使用已有的 BPF 绑定）
```

## CLI 命令

### record - 开箱即用的智能体录制

`record` 命令为监控 AI 智能体提供了优化的默认配置。它自���启用 SSL 监控、进程监控、系统资源监控和 Web 服务器。

```sh
# 基本用法（--comm 是必需的）
sudo ./agentsight record -c claude --binary-path ~/.local/share/claude/versions/<version>

# 监控 Python AI 工具
sudo ./agentsight record -c python

# 自定义日志文件和端口
sudo ./agentsight record -c python --log-file /tmp/agent.log --server-port 8080
```

**预设行为：**
- SSL 监控：启用，带优化过滤器
- 进程监控：启用
- 系统监控：启用（10 秒���隔）
- Web 服务器：启用，端口 7395
- 控制台输出：静默（仅写入日志文件）
- 日志轮转：启用（最大 10MB）

| 参数 | 短格式 | 默认值 | 说明 |
|------|--------|--------|------|
| `--comm` | `-c` | （必需） | 要监控的进程名 |
| `--binary-path` | | | 静态链接 SSL 的二进制路径 |
| `--log-file` | `-o` | `record.log` | 日志文件路径 |
| `--server-port` | | `7395` | Web 服务器端口 |
| `--rotate-logs` | | `true` | 启用日志轮转 |
| `--max-log-size` | | `10` | 最大日志大小（MB） |

### trace - 灵活的综合监控

`trace` 命令提供最大灵活性，允许独立开关每种监控源。

```sh
# SSL + 进程监控，启用 Web UI
sudo ./agentsight trace --ssl true --process true --server true --comm claude

# 全栈监控
sudo ./agentsight trace --ssl true --process true --system true --comm python \
  --binary-path /usr/bin/python3

# 特定进程的 Stdio 捕获
sudo ./agentsight trace --stdio true --pid 12345 --ssl false --process false

# 自定义 SSL 过滤器
sudo ./agentsight trace --ssl true --process false \
  --ssl-filter "data=0\r\n\r\n" \
  --http-filter "request.path_prefix=/v1/messages"
```

| 参数 | 短格式 | 默认值 | 说明 |
|------|--------|--------|------|
| `--ssl` | | `true` | 启用 SSL 监控 |
| `--process` | | `true` | 启用进程监控 |
| `--system` | | `false` | 启用系统资源监控 |
| `--stdio` | | `false` | 启用 stdio 监控（需要 `--pid`） |
| `--comm` | `-c` | | 进程名过滤（逗号分隔） |
| `--pid` | `-p` | `0` | PID 过滤 |
| `--binary-path` | | | 静态链接 SSL 的二进制路径 |
| `--ssl-uid` | | `0` | SSL UID 过滤 |
| `--ssl-filter` | | | SSL 过滤表达式 |
| `--ssl-handshake` | | `false` | 显示 SSL 握手事件 |
| `--ssl-http` | | `true` | 启用 HTTP 解析 |
| `--ssl-raw-data` | | `false` | 输出中包含原始数据 |
| `--http-filter` | | | HTTP 过滤表达式 |
| `--disable-auth-removal` | | `false` | 禁用敏感头移除 |
| `--duration` | | `0` | 最小进程持续时间（毫秒） |
| `--mode` | | `0` | 进程过滤模式（0=全部, 1=进程, 2=过滤） |
| `--system-interval` | | `10` | 系统监控间隔（秒） |
| `--stdio-uid` | | `0` | Stdio UID 过滤 |
| `--stdio-comm` | | | Stdio 进程名过滤 |
| `--stdio-all-fds` | | `false` | 捕获所有文件描述符 |
| `--stdio-max-bytes` | | `8192` | 每个 stdio 事件最大字节数 |

### ssl - 独立 SSL 监控

独立监控 SSL/TLS 流量，支持精细控制。

```sh
# 基本 SSL 监控
sudo ./agentsight ssl

# 启用 HTTP 解析
sudo ./agentsight ssl --http-parser

# 启用 SSE 合并和 HTTP 解析
sudo ./agentsight ssl --sse-merge --http-parser

# 使用过滤器
sudo ./agentsight ssl --http-parser \
  --ssl-filter "data=0\r\n\r\n|data.type=binary" \
  --http-filter "request.path_prefix=/v1/rgstr | response.status_code=202"

# 指定静态链接 SSL 的二进制路径
sudo ./agentsight ssl --http-parser --binary-path ~/.nvm/versions/node/v20.0.0/bin/node
```

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `--sse-merge` | `false` | 启用 SSE 事件合并 |
| `--http-parser` | `false` | 启用 HTTP 解析 |
| `--http-raw-data` | `false` | 解析输出中包含原始数据 |
| `--http-filter` | | HTTP 过滤表达式 |
| `--ssl-filter` | | SSL 过滤表达式 |
| `--disable-auth-removal` | `false` | 禁用敏感头移除 |
| `--binary-path` | | 静态链接 SSL 的二进制路径 |

### process - 独立进程监控

追踪进程执行和生命周期事件。

```sh
# 监控所有进程
sudo ./agentsight process

# 按进程名过滤
sudo ./agentsight process -c python

# 按 PID 过滤，设置最小持续时间
sudo ./agentsight process -p 12345 -d 100
```

| 参数 | 短格式 | 默认值 | 说明 |
|------|--------|--------|------|
| `--comm` | `-c` | | 进程名过滤（逗号分隔） |
| `--pid` | `-p` | `0` | PID 过滤 |
| `--duration` | `-d` | `0` | 最小进程持续时间（毫秒） |
| `--mode` | `-m` | `0` | 过滤模式：0=全部, 1=进程, 2=过滤 |

### system - 系统资源监控

监控目标进程的 CPU 和内存使用情况。

```sh
# 按进程名监控
sudo ./agentsight system -c python

# 按 PID 监控，设置告警阈值
sudo ./agentsight system -p 12345 --cpu-threshold 80 --memory-threshold 1024

# 自定义间隔，排除子进程
sudo ./agentsight system -c node -i 5 --no-children
```

| 参数 | 短格式 | 默认值 | 说明 |
|------|--------|--------|------|
| `--interval` | `-i` | `10` | 监控间隔（秒） |
| `--pid` | `-p` | `0` | 监控特定 PID |
| `--comm` | `-c` | | 按进程名过滤 |
| `--no-children` | | `false` | 排除子进程 |
| `--cpu-threshold` | | `0` | CPU 告警阈值（%） |
| `--memory-threshold` | | `0` | 内存告警阈值（MB） |

### stdio - 标准 I/O 捕获

捕获目标进程的 stdin/stdout/stderr。适用于监控通过 stdio 通信的本地 MCP 服务器。

```sh
# 捕获特定 PID 的 stdio（必需）
sudo ./agentsight stdio -p 12345

# 捕获所有文件描述符
sudo ./agentsight stdio -p 12345 --all-fds

# 按进程名过滤，自定义最大字节数
sudo ./agentsight stdio -p 12345 -c mcp-server --max-bytes 16384
```

| 参数 | 短格式 | 默认值 | 说明 |
|------|--------|--------|------|
| `--pid` | `-p` | （必需） | 目标进程 PID |
| `--uid` | `-u` | `0` | UID 过滤 |
| `--comm` | `-c` | | 进程名过滤 |
| `--all-fds` | | `false` | 捕获所有文件描述符 |
| `--max-bytes` | | `8192` | 每事件最大字节数 |

## 全局参数

以下参数适用于所有子命令：

| 参数 | 短格式 | 默认值 | 说明 |
|------|--------|--------|------|
| `--server` | | `false` | 启动 Web 服务器（`record` 自动启用） |
| `--server-port` | | `7395` | Web 服务器端口 |
| `--log-file` | `-o` | | 日志文件路径 |
| `--quiet` | `-q` | `false` | 禁用控制台输出 |
| `--rotate-logs` | | `false` | 启用日志轮转 |
| `--max-log-size` | | `10` | 最大日志大小（MB） |

## 高级用法

### 过滤表达式

#### SSL 过滤器 (`--ssl-filter`)

SSL 过滤器作用于原始 SSL 事件数据。多个条件用 `|`（或逻辑）分隔。使用 `--ssl-filter` 排除不需要的 SSL 事件。

```sh
# 过滤掉空的分块传输结尾和二进制数据
--ssl-filter "data=0\r\n\r\n|data.type=binary"
```

#### HTTP 过滤器 (`--http-filter`)

HTTP 过滤器作用于解析后的 HTTP 请求/响应对。多个条件用 `|`（或逻辑）分隔。使用 `--http-filter` 排除不需要的 HTTP 事件。

```sh
# 过滤掉注册端点、202 响应、HEAD 请求和空响应体
--http-filter "request.path_prefix=/v1/rgstr | response.status_code=202 | request.method=HEAD | response.body="
```

支持的过滤字段：
- `request.path_prefix` — 匹配请求路径前缀
- `request.method` — 匹配 HTTP 方法（GET、POST、HEAD 等）
- `response.status_code` — 匹配响应状态码
- `response.body` — 匹配响应体内容（空值匹配空响应体）

### `--binary-path` 详解

默认情况下，LLM-Scope 钩住系统共享的 `libssl.so` 来拦截 SSL 流量。但有些应用静态打包了自己的 SSL 库：

- **Claude Code (Bun)**：静态链接 BoringSSL，且符号被剥离
- **NVM Node.js**：静态链接 OpenSSL

对于这些应用，使用 `--binary-path` 直接指向应用二进制文件：

```sh
# Claude Code
sudo ./agentsight record -c claude --binary-path ~/.local/share/claude/versions/$(claude --version | head -1)

# NVM Node.js
sudo ./agentsight record -c node --binary-path ~/.nvm/versions/node/v20.0.0/bin/node
```

当指定 `--binary-path` 时：
1. LLM-Scope 首先尝试符号查找
2. 对于剥离符号的二进制文件，回退到 BoringSSL 字节模式检测
3. `--comm` 过滤器**不会**应用于 SSL 监控（仅应用于进程监控），因为 `bpf_get_current_comm()` 返回的是线程名而非进程名

### Web 界面

当 Web 服务器启用时（`--server` 参数或 `record` 命令），访问：

- **http://127.0.0.1:7395** — 主仪表板
- **http://127.0.0.1:7395/timeline** — 时间线视图
- **http://127.0.0.1:7395/tree** — 进程树视图
- **http://127.0.0.1:7395/logs** — 原始日志视图
- **http://127.0.0.1:7395/metrics** — 指标视图

前端支持 i18n 中英文切换。
