# AgentSight Makefile

BINARY := agentsight
BUILD_DIR := build
FRONTEND_DIR := frontend
STAMP_DIR := .build-stamps

GO := go
NPM := npm

# Version info
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME := $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Source file groups for dependency tracking
BPF_SOURCES := $(shell find bpf/ -name '*.c' -o -name '*.h' 2>/dev/null)
GO_SOURCES  := $(shell find . -name '*.go' -not -path './frontend/*' -not -path './.build-stamps/*' 2>/dev/null)
FE_SOURCES  := $(shell find $(FRONTEND_DIR)/src/ -name '*.ts' -o -name '*.tsx' -o -name '*.css' -o -name '*.json' 2>/dev/null) \
               $(FRONTEND_DIR)/next.config.js $(FRONTEND_DIR)/tailwind.config.ts $(FRONTEND_DIR)/package.json

.PHONY: all build quick force-all build-bpf build-frontend build-go \
        frontend-dev clean help test deps lint-frontend

# ─── Default: smart incremental build ────────────────────────────────
# Only rebuilds stages whose source files changed.
all: $(STAMP_DIR)/bpf $(STAMP_DIR)/frontend $(BINARY)
	@echo "✓ 构建完成: ./$(BINARY)"

# Alias
build: all

# ─── Quick: skip BPF and frontend, only rebuild Go ───────────────────
# Use when you only changed Go code (most common case). ~8s
quick: $(BINARY)
	@echo "✓ Go 快速构建完成: ./$(BINARY)"

# ─── Force full rebuild ──────────────────────────────────────────────
force-all:
	@rm -rf $(STAMP_DIR)
	@$(MAKE) all

# ─── BPF generation (only when .bpf.c / .h change) ──────────────────
$(STAMP_DIR)/bpf: $(BPF_SOURCES)
	@mkdir -p $(STAMP_DIR)
	@echo ">>> 生成 BPF Go 绑定..."
	$(GO) generate ./internal/bpf/...
	@echo "✓ BPF 绑定生成完成"
	@touch $@

build-bpf: $(STAMP_DIR)/bpf

# ─── Frontend (only when src/ files change) ──────────────────────────
$(STAMP_DIR)/npm: $(FRONTEND_DIR)/package.json $(FRONTEND_DIR)/package-lock.json
	@mkdir -p $(STAMP_DIR)
	@echo ">>> 安装前端依赖..."
	cd $(FRONTEND_DIR) && $(NPM) install --prefer-offline
	@touch $@

$(STAMP_DIR)/frontend: $(STAMP_DIR)/npm $(FE_SOURCES)
	@mkdir -p $(STAMP_DIR)
	@echo ">>> 静态导出 Next.js 前端..."
	cd $(FRONTEND_DIR) && NEXT_EXPORT=1 $(NPM) run build
	@echo "✓ 前端静态导出完成: $(FRONTEND_DIR)/out/"
	@touch $@

build-frontend: $(STAMP_DIR)/frontend

# ─── Go binary (rebuilds when Go or frontend output changes) ─────────
$(BINARY): $(GO_SOURCES) $(STAMP_DIR)/frontend
	@echo ">>> 编译 Go 程序..."
	$(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/agentsight
	@echo "✓ Go 编译完成: ./$(BINARY)"

build-go:
	@echo ">>> 编译 Go 程序..."
	$(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/agentsight
	@echo "✓ Go 编译完成: ./$(BINARY)"

# ─── Frontend dev server ─────────────────────────────────────────────
frontend-dev:
	@echo ">>> 启动前端开发服务器..."
	cd $(FRONTEND_DIR) && $(NPM) run dev

# ─── Lint frontend (separate from build) ─────────────────────────────
lint-frontend:
	@echo ">>> 前端代码检查..."
	cd $(FRONTEND_DIR) && $(NPM) run lint
	@echo "✓ 前端检查完成"

# ─── Tests ────────────────────────────────────────────────────────────
test:
	@echo ">>> 运行 Go 测试..."
	$(GO) test -v ./...
	@echo "✓ 测试完成"

# ─── Clean ────────────────────────────────────────────────────────────
clean:
	@echo ">>> 清理构建产物..."
	rm -f $(BINARY)
	rm -rf $(BUILD_DIR) $(STAMP_DIR)
	@echo "✓ 清理完成"

# ─── Install dependencies ────────────────────────────────────────────
deps:
	@echo ">>> 安装 Go 依赖..."
	$(GO) mod download
	@echo ">>> 安装 bpf2go 工具..."
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@v0.17.3
	@echo ">>> 安装前端依赖..."
	cd $(FRONTEND_DIR) && $(NPM) install
	@echo "✓ 依赖安装完成"

# ─── Help ─────────────────────────────────────────────────────────────
help:
	@echo "AgentSight 构建系统"
	@echo ""
	@echo "用法: make [目标]"
	@echo ""
	@echo "常用目标:"
	@echo "  make           - 智能增量构建（只重建有改动的部分）"
	@echo "  make quick     - 仅编译 Go（跳过 BPF 和前端，最快 ~8s）"
	@echo "  make force-all - 强制全量重建"
	@echo ""
	@echo "单独构建:"
	@echo "  build-bpf      - 生成 BPF Go 绑定（需要 clang）"
	@echo "  build-frontend - 编译并静态导出前端"
	@echo "  build-go       - 编译 Go 程序"
	@echo ""
	@echo "开发:"
	@echo "  frontend-dev   - 启动前端开发服务器（热重载）"
	@echo "  lint-frontend  - 前端代码检查"
	@echo "  test           - 运行 Go 测试"
	@echo "  deps           - 安装所有依赖"
	@echo "  clean          - 清理构建产物和缓存戳记"
