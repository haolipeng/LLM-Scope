# 会话 ID 与会话关联机制设计

## 背景

LLM-Scope 监控 Claude Code 会话时，会采集多种数据源的事件：SSL/TLS 网络流量、进程生命周期、文件操作、网络连接、系统资源等。需要一套完整的机制来解决：

1. 如何唯一标识一次监控会话
2. 如何将不同来源的事件正确关联到同一个会话
3. 如何在会话内部建立事件之间的因果关系

## 现有问题

| 问题 | 描述 |
|------|------|
| Session ID 碰撞 | 当前使用 `time.Now().Format("20060102-150405")`，精度到秒，同一秒启动两个实例会冲突 |
| 会话元数据未填充 | `sessions` 表的 `comm_filter`、`binary_path` 字段存在但未写入 |
| SSL 事件无进程过滤 | 指定 `--binary-path` 时 sslsniff 不使用 `--comm` 过滤，可能混入无关进程的流量 |
| OS 事件无法关联到工具调用 | FILE_OPEN、NET_CONNECT 等事件无法精确归属到具体的 tool_call |
| 跨批次引用断裂 | `streamToID` 映射仅在单次 flush 批次内有效，跨批次的安全告警无法找到源事件 |
| 进程树未持久化 | PIDTracker 的进程树仅在内存中维护，会话结束后丢失 |

## 设计方案

### 整体架构

```
Session (会话)
  │  唯一标识：时间戳 + 额外因子
  │  元数据：hostname, comm_filter, binary_path
  │  持久化：sessions 表
  │
  ├─ Process Tree (进程树) ← 核心纽带
  │    持久化：process_tree 表
  │    关联方式：PID/PPID 父子关系
  │
  ├─ SSL/HTTP 事件关联
  │    方式：用户态 PID 过滤（Analyzer 层匹配进程树）
  │
  ├─ 工具调用 → OS 事件关联
  │    方式：tool_use/tool_result 时间窗口 + PID 子树
  │    持久化：event_links 表
  │
  └─ 安全告警 → 源事件关联
       方式：streamToID 映射提升到 session 级别
       持久化：events_security.source_event_id
```

### 1. Session ID 唯一性

**问题**：当前 Session ID 使用 `time.Now().Format("20060102-150405")`，同一秒内启动两个实例会产生相同的 ID。

**分析**：

- 被监控者（Claude Code）的 PID 不可用于 Session ID：生成 Session ID 时 agentsight 尚未启动 Runner 扫描进程，且 `--comm` 可能匹配到多个进程。
- agentsight 自身的 PID 在生成时刻是确定可用的，且同一台机器上不可能存在两个相同 PID 的 agentsight 进程。

**方案**：在时间戳基础上增加额外因子确保唯一性。具体方案待定（候选：agentsight 自身 PID、随机后缀、hostname hash 等）。

**代码位置**：`internal/pipeline/sink/duckdb.go` `DuckDBConfig.defaults()` 方法。

### 2. Sessions 表元数据完善

**问题**：`sessions` 表已有 `comm_filter` 和 `binary_path` 字段但从未填充。

**方案**：在 `NewDuckDBSink` 创建会话记录时，将 `TraceConfig` 中的配置信息写入，使每个会话自描述。建议扩展字段：

```sql
CREATE TABLE IF NOT EXISTS sessions (
    session_id    VARCHAR PRIMARY KEY,
    start_time    TIMESTAMP,
    end_time      TIMESTAMP,
    comm_filter   VARCHAR,       -- 已有，需填充
    binary_path   VARCHAR,       -- 已有，需填充
    hostname      VARCHAR,       -- 新增：主机名
    root_pid      UINTEGER,      -- 新增：监控根进程 PID（运行时发现后回填）
    kernel_version VARCHAR,      -- 新增：内核版本
    labels        JSON           -- 新增：用户自定义标签
);
```

**代码位置**：`internal/pipeline/sink/duckdb_schema.go`、`internal/pipeline/sink/duckdb.go` 第 96-99 行。

### 3. SSL 事件的进程树过滤

**问题**：指定 `--binary-path` 时，sslsniff 不使用 `--comm` 过滤（因为 `bpf_get_current_comm()` 返回线程名而非进程名）。这导致所有使用该二进制的进程的 SSL 流量都被捕获，可能混入无关进程的数据。

**典型场景**：同一台机器上运行两个 Claude Code 实例，都使用同一个 node 二进制。

**方案选择**：

| 方案 | 描述 | 优点 | 缺点 |
|------|------|------|------|
| **用户态过滤（选定）** | 在 Analyzer 链中增加过滤步骤，将 SSL 事件的 PID 与 PIDTracker 的进程树匹配，丢弃不属于当前追踪树的事件 | 实现简单，不需要改 eBPF 代码 | 不匹配的事件仍经过 ring buffer 传到用户态后才被丢弃 |
| 内核态过滤 | 在 eBPF 层维护 BPF Hash Map 存储被追踪的 PID 集合，sslsniff 在 uprobe 触发时查 map | 内核层过滤，性能更好 | 需要改 eBPF 代码，进程 Runner 和 sslsniff 需共享 BPF map |

**实现要点**：PIDTracker 需要将已追踪的 PID 集合暴露给 SSL 过滤 Analyzer，且需要处理动态变化（子进程的创建和退出）。

### 4. 工具调用与 OS 事件的因果关联

**问题**：Claude Code 执行工具调用（如 Bash、Write）时会产生 OS 级事件（进程创建、文件操作等），但当前无法将 OS 事件精确归属到具体的工具调用。

**方案：时间窗口 + PID 子树**

Claude Code 与 API 的交互遵循固定节奏：

```
API 响应 tool_use(tool_id="abc", name="Bash", args="git status")
         ↓
   Claude Code 执行工具 → fork 子进程(PID=3001) → 子进程产生 OS 事件
         ↓
API 请求 tool_result(tool_id="abc", content="...")
```

具体步骤：

1. `ClaudeToolCallAnalyzer` 从 SSE 响应中解析到 `tool_use` 块时，记录 `(tool_id, tool_name, start_time)`
2. 在下一个 HTTP 请求中检测到对应的 `tool_result` 时，记录 `end_time`，得到时间窗口 `[start_time, end_time]`
3. 在这个窗口内，PPID 为 Claude Code（或其后代）的 EXEC 事件标记为该 tool_call 的根进程
4. 该根进程及其所有子孙进程产生的 OS 事件全部归属该 tool_call

关联关系写入 `event_links` 表：

```sql
CREATE TABLE IF NOT EXISTS event_links (
    session_id      VARCHAR NOT NULL,
    source_table    VARCHAR NOT NULL,   -- 源事件表名
    source_id       UBIGINT NOT NULL,   -- 源事件 ID
    target_table    VARCHAR NOT NULL,   -- 目标事件表名
    target_id       UBIGINT NOT NULL,   -- 目标事件 ID
    link_type       VARCHAR NOT NULL    -- 关联类型：caused, parsed_from, triggered 等
);
```

**TODO**：并行执行多个工具调用时时间窗口重叠的处理。

### 5. 跨批次事件引用修复

**问题**：`streamToID` 映射（StreamSeq → 数据库 ID）仅在单次 `flush()` 调用的局部变量中维护。如果源事件和安全告警分属不同的 flush 批次，告警的 `source_event_id` 将无法填充。

**方案**：将 `streamToID` 从 `flush()` 方法的局部变量提升为 `DuckDBSink` 结构体的字段，在整个会话生命周期内持续维护映射关系。

**代码位置**：`internal/pipeline/sink/duckdb.go` `flush()` 方法。

### 6. 进程树持久化

**问题**：PIDTracker 的进程树仅在内存中维护，会话结束后丢失。事后查询"某个会话的完整进程树"需要从 `events_process` 表通过复杂 JOIN 还原。

**方案**：新增 `process_tree` 表，直接表达进程父子关系和层级深度：

```sql
CREATE TABLE IF NOT EXISTS process_tree (
    session_id  VARCHAR NOT NULL,
    pid         UINTEGER NOT NULL,
    ppid        UINTEGER,
    comm        VARCHAR,
    filename    VARCHAR,
    start_time  TIMESTAMP,
    end_time    TIMESTAMP,
    depth       UINTEGER,           -- 在追踪树中的深度（root=0）
    PRIMARY KEY (session_id, pid)
);
```

**写入时机**：PIDTracker 在 `ShouldTrackProcess` 返回 true 时，或由 DuckDB sink 从 EXEC/EXIT 事件中维护。

**优点**：

- 查询完整进程树变成一次 `SELECT ... WHERE session_id = ? ORDER BY depth`
- 对 depth 过滤可快速定位直接子进程 vs 孙进程
- 前端画进程树图时不需要复杂 JOIN

## 实施优先级

| 优先级 | 改动项 | 改动范围 | 依赖 |
|--------|--------|---------|------|
| P0 | Session ID 唯一性 | `duckdb.go` 一个函数 | 无 |
| P0 | 填充 sessions 元数据 | `duckdb.go` + `duckdb_schema.go` | 无 |
| P1 | streamToID 提升到 session 级 | `duckdb.go` flush 方法 | 无 |
| P1 | SSL 事件用户态 PID 过滤 | 新增 Analyzer | PIDTracker 暴露 PID 集合 |
| P2 | process_tree 表持久化 | 新增表 + sink 写入逻辑 | 无 |
| P2 | 工具调用 → OS 事件关联 | ClaudeToolCallAnalyzer + event_links 表 | process_tree |
