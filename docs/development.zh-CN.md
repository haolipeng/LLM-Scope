# 开发指南

[English](development.md) | **中文**

## 前端开发模式

Go 二进制在编译时通过 `//go:embed all:out`（位于 `frontend/embed.go`）将前端资源内嵌。默认情况下，每次前端改动都需要重新编译 Go 二进制（`make build-frontend && make build-go`）才能生效。

为加速前端开发，可设置 `AGENTSIGHT_FRONTEND_DIR` 环境变量，让服务器直接从磁盘目录读取前端资源，而非使用内嵌的 `embed.FS`：

### 使用方法

```sh
# 1. 构建前端
make build-frontend

# 2. 设置环境变量启动
AGENTSIGHT_FRONTEND_DIR=./frontend/out sudo -E ./agentsight record -c claude --binary-path <path>
```

之后每次修改前端：

```sh
make build-frontend
# 重启 agentsight 即可生效，无需重新编译 Go
```

使用热重载进行开发：

```sh
# 终端 1：启动后端（API 服务器）
sudo ./agentsight record -c python --server-port 7395

# 终端 2：启动 Next.js 开发服务器
make frontend-dev
# 开发服务器运行在 http://localhost:3000，API 代理到 :7395
```

### 工作原理

- 服务器启动时检查 `AGENTSIGHT_FRONTEND_DIR` 环境变量。
- **已设置** — 直接从指定目录读取文件。目录中必须包含 `index.html`。
- **未设置** — 使用内嵌资源（编译进二进制的 `embed.FS`）。

### 注意事项

- 使用 `sudo -E` 以在 sudo 下保留环境变量。
- 路径支持相对路径（如 `./frontend/out`）和绝对路径。
- 生产环境中不要设置此变量，将正常使用内嵌资源。

## 项目目录结构

```
agentsight_go/
├── cmd/agentsight/           # CLI 入口（Cobra 命令）
│   ├── main.go               # 根命令、全局参数、配置初始化
│   ├── record.go             # record 子命令（优化的默认配置）
│   ├── trace.go              # trace 子命令（灵活的综合监控）
│   ├── ssl.go                # ssl 子命令（独立 SSL 监控）
│   ├── process.go            # process 子命令（独立进程监控）
│   ├── system.go             # system 子命令（CPU/内存监控）
│   └── stdio.go              # stdio 子命令（标准 I/O 捕获）
│
├── internal/
│   ├── bpf/                  # bpf2go 生成的 Go 绑定
│   │   ├── sslsniff/         # SSL 嗅探 eBPF 绑定
│   │   │   ├── gen.go        # //go:generate 指令
│   │   │   ├── loader.go     # eBPF 程序加载器
│   │   │   └── *_bpfel.go    # 生成文件：Go 类型 + 内嵌 .o
│   │   ├── process/          # 进程追踪 eBPF 绑定
│   │   └── stdiocap/         # Stdio 捕获 eBPF 绑定
│   │
│   ├── runtime/
│   │   ├── event/            # 统一的 Event 结构定义
│   │   │   └── event.go      # Event 类型、时间戳工具
│   │   ├── bpf/              # eBPF 程序加载封装
│   │   │   ├── sslsniff/     # SSL eBPF 加载器
│   │   │   ├── process/      # 进程 eBPF 加载器
│   │   │   └── stdiocap/     # Stdio eBPF 加载器
│   │   └── collectors/       # Runner 实现（事件源）
│   │       ├── base/         # 共享的基础 collector 逻辑
│   │       ├── ssl/          # SSL 收集器（Runner）
│   │       ├── process/      # 进程收集器（Runner）
│   │       ├── system/       # 系统资源收集器（Runner，读取 /proc）
│   │       └── stdio/        # Stdio 收集器（Runner）
│   │
│   ├── pipeline/
│   │   ├── types/            # 核心接口：Runner、Analyzer、Sink、MetricsReporter
│   │   │   └── types.go
│   │   ├── core/             # Analyzer 链构建器（Chain 函数）
│   │   │   └── chain.go
│   │   ├── transforms/       # Analyzer 实现
│   │   │   ├── sslfilter.go          # SSL 事件过滤器
│   │   │   ├── ssemerger.go          # SSE 分块合并器
│   │   │   ├── httpparser.go         # HTTP 请求/响应解析器
│   │   │   ├── httpfilter.go         # HTTP 事件过滤器
│   │   │   ├── authremover.go        # 敏感头移除器
│   │   │   ├── toolcall.go           # 工具调用聚合器
│   │   │   ├── toolcall_http.go      # 基于 HTTP 的工具调用检测
│   │   │   ├── toolcall_process.go   # 基于进程的工具调用检测
│   │   │   └── sse_parse.go          # SSE 解析工具
│   │   └── stream/           # 多源流工具
│   │       ├── combined.go   # CombinedRunner（合并多个 Runner）
│   │       └── merge.go      # MergeStreams（合并多个 channel）
│   │
│   ├── interfaces/
│   │   ├── http/             # Gin Web 服务器、SSE 端点、事件中心
│   │   │   ├── server.go     # 路由设置、静态文件服务
│   │   │   ├── event_hub.go  # 事件存储和 SSE 广播
│   │   │   └── assets.go     # 前端资源解析（embed.FS 或磁盘）
│   │   └── sink/             # 输出 Sink
│   │       ├── filelogger.go # 文件日志（支持轮转）
│   │       └── output.go     # 控制台输出
│   │
│   └── command/              # 共享的命令执行助手
│       └── execute.go        # Execute() 单 Runner 命令助手
│
├── bpf/                      # C eBPF 源文件
│   ├── sslsniff.bpf.c       # SSL/TLS 拦截（uprobe）
│   ├── sslsniff.h            # SSL 数据结构
│   ├── process.bpf.c        # 进程生命周期追踪（tracepoint）
│   ├── process.h             # 进程数据结构
│   ├── stdiocap.bpf.c       # Stdio 捕获（tracepoint）
│   └── stdiocap.h            # Stdio 数据结构
│
├── frontend/                 # Next.js/React/TypeScript 前端
│   ├── embed.go              # //go:embed all:out（内嵌静态资源）
│   ├── src/                  # React 源代码
│   ├── out/                  # 构建输出（静态导出）
│   ├── package.json          # npm 依赖
│   └── next.config.js        # Next.js 配置
│
├── vmlinux/                  # 架构相关的 vmlinux.h 头文件
│   └── x86/
│
├── Makefile                  # 构建系统
├── go.mod / go.sum           # Go 模块定义
└── CLAUDE.md                 # Claude Code 开发指南
```

## 核心 Go 接口

所有核心接口定义在 `internal/pipeline/types/types.go`：

```go
// Runner 从数据源（如 eBPF、/proc）中产生事件流。
type Runner interface {
    ID() string
    Name() string
    Run(ctx context.Context) (<-chan *runtimeevent.Event, error)
    Stop() error
}

// Analyzer 处理输入事件流，并输出变换后的事件流。
type Analyzer interface {
    Name() string
    Process(ctx context.Context, in <-chan *runtimeevent.Event) <-chan *runtimeevent.Event
}

// Sink 只消费事件用于副作用处理（如日志、导出），不会继续输出事件。
type Sink interface {
    Name() string
    Consume(ctx context.Context, in <-chan *runtimeevent.Event)
}

// MetricsReporter 可选接口，支持过滤指标上报的 Analyzer 实现此接口。
type MetricsReporter interface {
    ReportMetrics()
}
```

## 新增 Analyzer

1. 在 `internal/pipeline/transforms/` 下创建新文件，例如 `myanalyzer.go`
2. 实现 `Analyzer` 接口：

```go
package transforms

import (
    "context"
    runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

type MyAnalyzer struct {
    // 配置字段
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
                // 在此处变换或过滤 evt
                out <- evt
            }
        }
    }()
    return out
}
```

3. 可选实现 `MetricsReporter` 接口，用于 SIGINT 时上报指标
4. 在相应的命令文件（例如 `cmd/agentsight/trace.go`）中将 analyzer 添加到管道中：

```go
analyzers = append(analyzers, pipelinetransforms.NewMyAnalyzer())
```

## 新增 Collector（Runner）

1. 在 `internal/runtime/collectors/` 下创建新包，例如 `internal/runtime/collectors/myrunner/`
2. 实现 `Runner` 接口：

```go
package myrunner

import (
    "context"
    runtimeevent "github.com/haolipeng/LLM-Scope/internal/runtime/event"
)

type Config struct {
    // 配置字段
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
        // 从数据源读取事件并发送到 out channel
        // 对于 eBPF：加载程序、附加探针、读取 Ring Buffer
        // 对于 /proc：定期轮询
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

3. 在 `cmd/agentsight/` 下的相应命令文件中注册 runner
4. 对于基于 eBPF 的 runner，使用 `internal/runtime/bpf/` 中的 eBPF 加载器

## 新增 eBPF 程序（bpf2go 流程）

1. **编写 C eBPF 程序**：在 `bpf/` 下创建 `myprogram.bpf.c` 和 `myprogram.h`
   - 使用 CO-RE（Compile Once, Run Everywhere）模式
   - 包含 `vmlinux/` 中的架构相关 `vmlinux.h`
   - 通过 Ring Buffer 与用户空间通信（不使用 JSON stdout）

2. **创建 Go 绑定包**：创建 `internal/bpf/myprogram/gen.go`：

```go
package myprogram

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target amd64 -type my_event_t myprogram ../../../bpf/myprogram.bpf.c -- -I../../../vmlinux/x86
```

3. **生成 Go 绑定**：运行 `make build-bpf` 或 `go generate ./internal/bpf/myprogram/...`
   - 这会生成 `myprogram_x86_bpfel.go`，包含 Go 类型和内嵌的编译后 BPF 对象

4. **创建加载器**：在 `internal/bpf/myprogram/loader.go` 中添加 eBPF 程序的加载和配置逻辑

5. **创建收集器**：在 `internal/runtime/collectors/myrunner/` 下实现 `Runner` 接口，使用加载器从 Ring Buffer 读取事件

6. **注册 CLI 命令**：在 `cmd/agentsight/` 下添加新的命令文件，或集成到现有的 `trace` 命令中

## 构建系统

| Makefile 目标 | 说明 |
|--------------|------|
| `make build-all` | 完整构建：BPF 生成 + 前端 + Go 二进制 |
| `make build-bpf` | 通过 `go generate ./internal/bpf/...` 生成 BPF Go 绑定 |
| `make build-frontend` | 构建 Next.js 前端静态导出到 `frontend/out/` |
| `make build-go` | 编译 Go 二进制（使用已有的 BPF 绑定） |
| `make frontend-dev` | 启动 Next.js 开发服务器（热重载） |
| `make deps` | 安装所有依赖（Go 模块、bpf2go、npm 包） |
| `make test` | 运行 Go 测试（`go test -v ./...`） |
| `make clean` | 删除构建产物 |

## 测试

```sh
# 运行所有 Go 测试
make test

# 运行特定包的测试
go test -v ./internal/pipeline/transforms/...

# 运行单个测试
go test -v -run TestMyFunction ./internal/pipeline/transforms/
```

## 调试

### eBPF 程序问题

- 确保拥有 root 权限或 `CAP_BPF` + `CAP_SYS_ADMIN`
- 验证内核版本：`uname -r`（要求 4.1+，推荐 5.0+）
- 检查 eBPF 验证器输出以获取程序加载错误信息
- 使用 `bpftool prog list` 查看已加载的 eBPF 程序

### 前端问题

- 检查 `AGENTSIGHT_FRONTEND_DIR` 开发时是否设置正确
- 确认 `frontend/out/` 在构建后包含 `index.html`
- 检查浏览器控制台是否有 JavaScript 错误
- API 端点：`/api/analytics/timeline`（从 DuckDB 查询）

### 管道调试

- 使用 `--quiet=false` 参数在控制台查看事件
- 通过 `--log-file` 检查日志文件输出
- 实现了 `MetricsReporter` 的 Analyzer 会在 SIGINT（Ctrl+C）时打印统计信息
