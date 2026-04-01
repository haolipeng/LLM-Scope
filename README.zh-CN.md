# LLM-Scope：基于 eBPF 的零侵入 LLM 智能体可观测性工具

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Go Version](https://img.shields.io/badge/Go-1.22+-00ADD8.svg)](https://go.dev/)

[English](README.md) | **中文**

LLM-Scope 是一款专为监控 LLM 智能体行为而设计的可观测性工具，通过 SSL/TLS 流量拦截和进程监控来实现。与传统的应用级插桩不同，LLM-Scope 使用 eBPF 技术在系统边界进行观测，以极低的性能开销提供对 AI 智能体交互的全面洞察。

**零侵入** - 无需修改代码，无需引入新依赖，无需集成 SDK。开箱即用，兼容任何 AI 框架或应用。

## 快速开始

```bash
# 克隆并从源码构建
git clone https://github.com/haolipeng/LLM-Scope.git --recursive
cd LLM-Scope
make deps
make build-all

# 记录 Claude Code 活动（基于 Bun，静态链接 BoringSSL，需要 --binary-path）
sudo ./agentsight record -c claude --binary-path ~/.local/share/claude/versions/$(claude --version | head -1)

# 监控 Python AI 工具（如 aider、open-interpreter）
sudo ./agentsight record -c "python"

# 监控使用 NVM 的 Node.js 应用（静态链接 OpenSSL）
sudo ./agentsight record -c node --binary-path ~/.nvm/versions/node/v20.0.0/bin/node
```

访问 [http://127.0.0.1:7395](http://127.0.0.1:7395) 查看记录的数据。

## 为什么选择 LLM-Scope？

### 传统可观测性 vs. 系统级监控

| **挑战** | **应用级工具** | **LLM-Scope 方案** |
|----------|--------------|---------------------|
| **框架适配** | 每个框架都需要新的 SDK/代理 | 即插即用的守护进程，无需修改代码 |
| **闭源工具** | 对内部运作的可见性有限 | 完整可见提示词和行为 |
| **动态智能体行为** | 日志可能被静默或篡改 | 内核级钩子确保可靠监控 |
| **加密流量** | 只能看到封装后的输出 | 捕获真实的未加密请求/响应 |
| **系统交互** | 遗漏子进程执行 | 追踪所有进程行为和文件操作 |
| **多智能体系统** | 隔离的单进程追踪 | 全局关联和分析 |

LLM-Scope 能捕获应用级工具遗漏的关键交互：

- 绕过插桩的子进程执行
- 智能体处理前的原始加密载荷
- 文件操作和系统资源访问
- 跨智能体通信与协调

## 架构

```ascii
┌─────────────────────────────────────────────────┐
│              AI 智能体运行时                      │
│   ┌─────────────────────────────────────────┐   │
│   │       应用级可观测性                      │   │
│   │  (LangSmith, Helicone, Langfuse 等)      │   │
│   │         可被绕过                          │   │
│   └─────────────────────────────────────────┘   │
│                     ↕ (可被绕过)                  │
├─────────────────────────────────────────────────┤ ← 系统边界
│  LLM-Scope eBPF 监控（内核级）                    │
│  ┌───────────┐ ┌──────────┐ ┌──────────────┐   │
│  │ SSL/TLS   │ │ 进程事件  │ │ Stdio/系统   │   │
│  │ 流量      │ │          │ │ 监控         │   │
│  └───────────┘ └──────────┘ └──────────────┘   │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│         Go 流式分析框架                           │
│  ┌─────────────┐  ┌──────────────┐  ┌────────┐  │
│  │  Collector  │  │  Analyzer    │  │  Sink  │  │
│  │ （收集器）   │  │ （处理器）    │  │ (输出)  │  │
│  └─────────────┘  └──────────────┘  └────────┘  │
└─────────────────────────────────────────────────┘
                      ↓
┌─────────────────────────────────────────────────┐
│             前端可视化                            │
│   时间线 · 进程树 · 日志 · 指标                    │
└─────────────────────────────────────────────────┘
```

### 核心组件

1. **eBPF 数据采集**（内核空间）
   - **SSL 监控器**：通过 uprobe 钩子拦截 SSL/TLS 读写操作
   - **进程监控器**：通过 tracepoint 追踪进程生命周期和文件操作
   - **Stdio 监控器**：捕获目标进程的 stdin/stdout/stderr
   - **系统监控器**：从 /proc 采集 CPU 和内存使用情况
   - **性能开销 <3%**：在应用层之下运行，影响极小

2. **Go 流式框架**（用户空间）
   - **Collector（Runner）**：加载 eBPF 程序并从 Ring Buffer 读取事件（SSL、进程、系统、Stdio）
   - **Analyzer**：可插拔的处理器，用于 SSE 合并、HTTP 解析、过滤、认证头移除、工具调用聚合
   - **Sink**：输出目的地 — 文件日志、控制台输出、SSE 事件推送
   - **Pipeline**：基于 channel 的事件流，支持 Analyzer 链式处理

3. **前端可视化**（React/TypeScript）
   - 交互式时间线、进程树和日志视图
   - 实时指标可视化（CPU、内存）
   - i18n 中英文切换支持
   - 详见"Web 界面"章节

### 数据流管道

```
eBPF 程序 → Ring Buffer → Collector → Analyzer 链 → Sink/前端
```

## 使用方法

### 前置要求

- **Linux 内核**：4.1+ 且支持 eBPF（推荐 5.0+）
- **Root 权限**：加载 eBPF 程序所需
- **Go**：1.22+
- **Node.js**：18+（用于前端开发）
- **构建工具**：clang、llvm、libelf-dev

### 安装

```bash
# 克隆仓库（含子模块）
git clone https://github.com/haolipeng/LLM-Scope.git --recursive
cd LLM-Scope

# 安装依赖（Go 模块、bpf2go 工具、前端 npm 包）
make deps

# 构建所有组件（BPF 代码生成 + 前端 + Go 二进制）
make build-all

# 或单独构建：
# make build-bpf        # 通过 bpf2go 生成 BPF Go 绑定
# make build-frontend   # 构建 Next.js 前端静态导出
# make build-go         # 仅编译 Go 二进制
```

构建成功后，二进制文件位于 `./agentsight`。

### 使用示例

#### 监控 Claude Code

Claude Code 是基于 Bun 的应用，静态链接了 BoringSSL 且符号被剥离。提供 `--binary-path` 时，LLM-Scope 通过字节模式匹配自动检测 BoringSSL 函数：

```bash
# 找到 Claude 二进制版本
CLAUDE_BIN=~/.local/share/claude/versions/$(claude --version | head -1)

# 记录所有 Claude 活动并启用 Web UI
sudo ./agentsight record -c claude --binary-path "$CLAUDE_BIN"
# 打开 http://127.0.0.1:7395 查看时间线

# 高级用法：使用自定义过滤器的完整追踪
sudo ./agentsight trace --ssl true --process true --comm claude \
  --binary-path "$CLAUDE_BIN" --server true --server-port 8080
```

这将捕获：
- **对话 API**：`POST /v1/messages` 请求，包含完整的提示词/响应 SSE 流
- **遥测数据**：心跳、事件日志、Datadog 日志
- **进程活动**：文件操作、子进程执行

> **注意**：Claude 中所有 SSL 流量都通过内部 "HTTP Client" 线程传输，而非主 "claude" 线程。当指定 `--binary-path` 时，`--comm` 过滤器会自动跳过 SSL 监控（但仍应用于进程监控），以确保流量被正确捕获。

#### 监控 Python AI 工具

```bash
# 监控 aider、open-interpreter 或任何基于 Python 的 AI 工具
sudo ./agentsight record -c "python"

# 自定义端口和日志文件
sudo ./agentsight record -c "python" --server-port 8080 --log-file /tmp/agent.log
```

#### 监控 Node.js AI 工具（Gemini CLI 等）

对于通过 NVM 安装的静态链接 OpenSSL 的 Node.js 应用，使用 `--binary-path` 指向实际的 Node.js 二进制文件：

```bash
# 监控 Gemini CLI 或其他 Node.js AI 工具
sudo ./agentsight record -c node --binary-path ~/.nvm/versions/node/v20.0.0/bin/node

# 或使用系统 Node.js（使用动态 libssl，无需 --binary-path）
sudo ./agentsight record -c node
```

#### 高级监控

```bash
# SSL 和进程组合监控，启用 Web 界面
sudo ./agentsight trace --ssl true --process true --server true

# 启用系统资源监控
sudo ./agentsight trace --ssl true --process true --system true --comm python

# 捕获特定进程的 stdio
sudo ./agentsight trace --stdio true --pid 12345 --ssl false --process false
```

### CLI 子命令

| 命令 | 说明 | 关键参数 |
|------|------|----------|
| `record` | 开箱即用的智能体录制，预设优化参数 | `--comm`（必需）、`--binary-path`、`--log-file`、`--server-port` |
| `trace` | 灵活的综合监控，可独立开关各监控源 | `--ssl`、`--process`、`--system`、`--stdio`、`--comm`、`--pid`、`--binary-path` |
| `ssl` | 独立 SSL/TLS 流量监控 | `--http-parser`、`--sse-merge`、`--ssl-filter`、`--http-filter`、`--binary-path` |
| `process` | 独立进程生命周期监控 | `--comm`、`--pid`、`--duration`、`--mode` |
| `system` | 系统资源监控（CPU/内存） | `--interval`、`--pid`、`--comm`、`--cpu-threshold`、`--memory-threshold` |
| `stdio` | 标准 I/O 捕获 | `--pid`（必需）、`--comm`、`--all-fds`、`--max-bytes` |

### Web 界面

所有带 `--server` 参数的监控命令（`record` 默认启用）都在以下地址提供 Web 可视化：
- **时间线视图**：http://127.0.0.1:7395/timeline
- **进程树**：http://127.0.0.1:7395/tree
- **原始日志**：http://127.0.0.1:7395/logs
- **指标**：http://127.0.0.1:7395/metrics

## 常见问题

### 通用问题

**问：LLM-Scope 与传统 APM 工具有什么区别？**
答：LLM-Scope 使用 eBPF 在内核级运行，提供独立于应用代码的系统级监控。传统 APM 需要插桩，而插桩可能被修改或禁用。

**问：性能影响如何？**
答：由于采用优化的 eBPF 内核空间数据采集，CPU 开销不到 3%。

**问：智能体能否检测到自己正在被监控？**
答：检测极其困难，因为监控在内核级进行，无需修改代码。

### 技术问题

**问：支持哪些 Linux 发行版？**
答：任何内核 4.1+（推荐 5.0+）的发行版。已在 Ubuntu 20.04+、CentOS 8+、RHEL 8+ 上测试通过。

**问：能否同时监控多个智能体？**
答：可以，使用组合监控模式可以对多个智能体进行并发观测和关联分析。

**问：为什么 LLM-Scope 无法捕获 Claude Code 或 NVM Node.js 的流量？**
答：这些应用静态链接了 SSL 库（Claude/Bun 使用 BoringSSL，NVM Node.js 使用 OpenSSL），而非使用系统 `libssl.so`。请使用 `--binary-path` 指向实际的二进制文件，LLM-Scope 将通过字节模式匹配自动检测 SSL 函数。

**问：为什么 `--comm claude` 无法捕获 SSL 流量？**
答：Claude Code 的 SSL 流量运行在内部 "HTTP Client" 线程上，而非主 "claude" 线程。sslsniff 中的 `--comm` 过滤器匹配的是线程名（来自 `bpf_get_current_comm()`），而非进程名。使用 `--binary-path` 时，collector 会自动跳过 SSL 监控的 `--comm` 过滤。

### 故障排除

**问："Permission denied" 错误**
答：确保使用 `sudo` 运行或拥有 `CAP_BPF` 和 `CAP_SYS_ADMIN` 能力。

**问："Failed to load eBPF program" 错误**
答：验证内核版本是否满足要求（见前置要求）。如需要，请为你的架构更新 vmlinux.h。

## 参与贡献

欢迎贡献！克隆并构建后（见上方安装章节），你可以：

```bash
# 运行测试
make test

# 前端开发服务器（热重载）
make frontend-dev
```

### 关键资源

- [CLAUDE.md](CLAUDE.md) - 项目指南和架构
- [docs/usage.zh-CN.md](docs/usage.zh-CN.md) - 详细使用指南
- [docs/development.zh-CN.md](docs/development.zh-CN.md) - 开发指南

## 许可证

MIT 许可证 - 详见 [LICENSE](LICENSE)。

---

**AI 可观测性的未来**：随着 AI 智能体变得更加自主且具备自我修改能力，传统的可观测性方法变得力不从心。LLM-Scope 为大规模安全部署 AI 提供了独立的系统级监控。
