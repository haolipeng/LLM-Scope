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
# 无需重启 agentsight、无需重新编译 Go：静态文件由 os.DirFS 按请求读磁盘
# 浏览器若仍显示旧页面，请强制刷新（Ctrl+Shift+R）或禁用缓存后再试
```

使用热重载进行开发：

```sh
# 终端 1：启动后端（API 服务器）
sudo ./agentsight record -c python --server-port 7395

# 终端 2：启动 Next.js 开发服务器
make frontend-dev
# 开发服务器监听 0.0.0.0:3000（本机可用 http://localhost:3000，局域网可用 http://<机器IP>:3000）
# 浏览器请打开 :3000，而不是 :7395（见下方「热重载与 7395 的区别」）
```

### 热重载与 `:7395` 的区别（常见误区）

| 访问地址 | 页面来源 | 修改 `src/` 后如何生效 |
|---------|----------|------------------------|
| **`http://…:3000`**（`make frontend-dev`） | Next.js 开发服务器，**支持热重载** | 保存文件后自动刷新，一般无需额外命令 |
| **`http://…:7395`** | Go 内嵌的 `frontend/out`，或 `AGENTSIGHT_FRONTEND_DIR` 指向的静态目录 | **没有** Next 热重载。已设置 **`AGENTSIGHT_FRONTEND_DIR`** 时：每次改前端执行 `make build-frontend` 即可，**一般不必重启** agentsight（磁盘目录按请求读取）；若浏览器仍旧，请**硬刷新**或清缓存。**未设置**该变量时：需 `make build-frontend && make build-go` 并**替换/重启**二进制（资源编译进程序内） |

因此：按上文「终端 1 + 终端 2」做前端开发时，请在浏览器打开 **`:3000`** 验证界面改动；若一直打开 `:7395`，看到的仍是旧静态包，与是否在终端跑了 `frontend-dev` 无关。

### 工作原理

- 服务器启动时检查 `AGENTSIGHT_FRONTEND_DIR` 环境变量。
- **已设置** — 直接从指定目录读取文件。目录中必须包含 `index.html`。
- **未设置** — 使用内嵌资源（编译进二进制的 `embed.FS`）。

### 注意事项

- 使用 `sudo -E` 以在 sudo 下保留环境变量。
- 路径支持相对路径（如 `./frontend/out`）和绝对路径。
- 生产环境中不要设置此变量，将正常使用内嵌资源。

## 前端静态导出如何更快

- **增量**：`make build-frontend` 依赖 `frontend/src/` 等源文件的修改时间；**未改前端时** Make 会跳过导出，几乎不耗时。
- **Turbopack**：`make build-frontend` 默认使用 `next build --turbopack`（Next 15.3+），一般比 webpack 更快。若需与旧版行为一致或排查兼容问题，使用：  
  `FRONTEND_WEBPACK=1 make build-frontend`
- **日常改 UI**：优先 `make frontend-dev` 用 `:3000` 热重载，少跑完整静态导出。

## 构建系统

| Makefile 目标 | 说明 |
|--------------|------|
| `make build-all` | 完整构建：BPF 生成 + 前端 + Go 二进制 |
| `make build-bpf` | 通过 `go generate ./internal/bpf/...` 生成 BPF Go 绑定 |
| `make build-frontend` | 构建 Next.js 前端静态导出到 `frontend/out/`（默认 Turbopack；`FRONTEND_WEBPACK=1` 使用 webpack） |
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
