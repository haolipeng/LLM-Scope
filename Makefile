# AgentSight Makefile

BINARY := agentsight
BUILD_DIR := build
FRONTEND_DIR := frontend

GO := go
NPM := npm

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: all build-all build-bpf build-frontend build-go frontend-dev clean help test deps

all: build-all

# Full build: generate BPF Go bindings + compile Go
build-all: build-bpf build-frontend build-go
	@echo "构建完成: ./$(BINARY)"

# Generate BPF Go bindings via bpf2go (requires clang)
build-bpf:
	@echo ">>> 生成 BPF Go 绑定..."
	$(GO) generate ./internal/bpf/...
	@echo "✓ BPF 绑定生成完成"

# Build Next.js frontend as static export (for Go server embedding)
build-frontend:
	@echo ">>> 静态导出 Next.js 前端..."
	cd $(FRONTEND_DIR) && $(NPM) install && NEXT_EXPORT=1 $(NPM) run build
	@echo "✓ 前端静态导出完成: $(FRONTEND_DIR)/out/"

# Start frontend dev server
frontend-dev:
	@echo ">>> 启动前端开发服务器..."
	cd $(FRONTEND_DIR) && $(NPM) run dev

# Build Go binary (skip BPF generation, uses existing .o files)
build-go:
	@echo ">>> 编译 Go 程序..."
	$(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/agentsight
	@echo "✓ Go 编译完成: ./$(BINARY)"

# Run tests
test:
	@echo ">>> 运行 Go 测试..."
	$(GO) test -v ./...
	@echo "✓ 测试完成"

# Clean build artifacts
clean:
	@echo ">>> 清理构建产物..."
	rm -f $(BINARY)
	rm -rf $(BUILD_DIR)
	@echo "✓ 清理完成"

# Install dependencies
deps:
	@echo ">>> 安装 Go 依赖..."
	$(GO) mod download
	@echo ">>> 安装 bpf2go 工具..."
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@v0.17.3
	@echo ">>> 安装前端依赖..."
	cd $(FRONTEND_DIR) && $(NPM) install
	@echo "✓ 依赖安装完成"

# Help
help:
	@echo "AgentSight 构建系统"
	@echo ""
	@echo "用法: make [目标]"
	@echo ""
	@echo "目标:"
	@echo "  build-all      - 完整构建 (BPF 绑定 + Go)"
	@echo "  build-bpf      - 生成 BPF Go 绑定 (需要 clang)"
	@echo "  build-frontend - 编译并静态导出前端 (用于 Go 内嵌)"
	@echo "  build-go       - 编译 Go 程序 (跳过 BPF 生成)"
	@echo "  frontend-dev   - 启动前端开发服务器"
	@echo "  test           - 运行测试"
	@echo "  deps           - 安装依赖"
	@echo "  clean          - 清理构建产物"
	@echo "  help           - 显示此帮助信息"
