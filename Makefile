# AgentSight Makefile

BINARY := agentsight
BUILD_DIR := build
BPF_DIR := bpf
FRONTEND_DIR := frontend

GO := go
NPM := npm

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

.PHONY: all build bpf web web-dev go clean help install dev test deps

all: build

# Full build (frontend runs independently, not embedded)
build: bpf go
	@echo "构建完成: ./$(BINARY)"

# Build BPF programs
bpf:
	@echo ">>> 编译 BPF 程序..."
	$(MAKE) -C $(BPF_DIR)
	@echo "✓ BPF 编译完成"

# Build Next.js frontend
web:
	@echo ">>> 编译 Next.js 前端..."
	cd $(FRONTEND_DIR) && $(NPM) install && $(NPM) run build
	@echo "✓ 前端编译完成"

# Start frontend dev server
web-dev:
	@echo ">>> 启动前端开发服务器..."
	cd $(FRONTEND_DIR) && $(NPM) run dev

# Build Go binary
go:
	@echo ">>> 编译 Go 程序..."
	$(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/agentsight
	@echo "✓ Go 编译完成"

# Quick Go build (skip BPF)
go-only:
	@echo ">>> 编译 Go 程序..."
	$(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/agentsight
	@echo "✓ Go 编译完成: ./$(BINARY)"

# Dev mode: quick Go rebuild
dev: go-only

# Run tests
test:
	@echo ">>> 运行 BPF 测试..."
	$(MAKE) -C $(BPF_DIR) test
	@echo ">>> 运行 Go 测试..."
	$(GO) test -v ./...
	@echo "✓ 测试完成"

# Clean build artifacts
clean:
	@echo ">>> 清理构建产物..."
	rm -f $(BINARY)
	rm -rf $(BUILD_DIR)
	$(MAKE) -C $(BPF_DIR) clean
	@echo "✓ 清理完成"

# Install dependencies
deps:
	@echo ">>> 安装 Go 依赖..."
	$(GO) mod download
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
	@echo "  all, build  - 完整构建 (BPF + Go)"
	@echo "  bpf         - 仅编译 BPF 程序"
	@echo "  web         - 编译 Next.js 前端"
	@echo "  web-dev     - 启动前端开发服务器"
	@echo "  go          - 仅编译 Go 程序"
	@echo "  go-only     - 快速编译 Go（不检查依赖）"
	@echo "  dev         - 开发模式快速编译"
	@echo "  test        - 运行测试"
	@echo "  deps        - 安装依赖"
	@echo "  clean       - 清理构建产物"
	@echo "  help        - 显示此帮助信息"
	@echo ""
	@echo "示例:"
	@echo "  make              # 完整构建 (BPF + Go)"
	@echo "  make dev          # 快速重编译 Go"
	@echo "  make web-dev      # 启动前端开发服务器 (端口 3000)"
	@echo "  make bpf web go   # 编译所有组件"
