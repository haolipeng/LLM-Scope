# SSEMerger 合并逻辑详解

## 概述

`SSEMerger` 是 SSL 流量分析管道中的关键分析器，负责将 eBPF 捕获的多个碎片化 SSL 读写事件合并为完整的 SSE（Server-Sent Events）消息流。

由于 eBPF 在内核层拦截 `SSL_read`/`SSL_write` 调用，一次完整的 HTTP SSE 响应会被拆分为大量细粒度的事件片段。SSEMerger 在下游 HTTPParser 之前运行，将这些碎片重组为完���的逻辑消息，供后续 HTTP 解析器正确处理。

## 在管道中的位置

```
SSL Runner → SSLFilter(可选) → SSEMerger → HTTPParser → HTTPFilter(可选) → AuthRemover(可选)
```

源码位置：
- `internal/pipeline/transforms/ssemerger.go` — 主控逻辑
- `internal/pipeline/transforms/sse_parse.go` — SSE 解析与累积器

## 核心数据结构

### SSEMerger

```go
type SSEMerger struct {
    timeout time.Duration           // 超时刷新时间，默认 30s
    mu      sync.Mutex              // 保护 buffers 的并发访问
    buffers map[string]*sseAccumulator // key → 累积器，按连接维度聚合
}
```

### sseAccumulator（累积器）

每个活跃的 SSE 连接对应一个累积器实例：

```go
type sseAccumulator struct {
    connectionID    string      // 连接标识（pid:tid:timeWindow）
    messageID       string      // 从 message_start 事件提取的消息 ID
    events          []sseEvent  // 收集到的所有 SSE 事件
    accumulatedText string      // 累积的文本内容（text_delta + thinking_delta）
    accumulatedJSON string      // 累积的 JSON 片段（partial_json）
    hasMessageStart bool        // 是否收到过 message_start 事件
    startTime       int64       // 首个事件时间戳(ns)
    endTime         int64       // 最新事件时间戳(ns)
    lastUpdate      time.Time   // 最后更新的挂钟时间（用于超时判断）
    function        string      // SSL 函数名（SSL_read/SSL_write）
    tid             uint64      // 线程 ID
}
```

### sseEvent（单个 SSE 事件）

```go
type sseEvent struct {
    Event      string                 // 事件类型：message_start, content_block_delta, message_stop 等
    Data       string                 // 原始 data 字段内容
    ID         string                 // SSE id 字段
    ParsedData map[string]interface{} // Data 成功解析为 JSON 后的结果
    RawData    string                 // Data 无法解析为 JSON 时保留的原始文本
}
```

## 处理流程

### 1. 事件分发（Process 方法）

SSEMerger 以 goroutine 方式运行，通过 `select` 同时监听三个来源：

```
┌────────────────────────────────────────────────┐
│                  select loop                    │
│                                                │
│  ┌─ ctx.Done()    → flushAll() 并退出           │
│  ├─ ticker.C      → flushExpired() 清理超时      │
│  └─ in channel    → 事件处理                     │
│       ├─ 非 SSL 事件 → 直接透传                   │
│       └─ SSL 事件   → handleEvent()             │
└────────────────────────────────────────────────┘
```

- **非 SSL 事件**（如 process、system）：直接透传到输出 channel，不做任何处理
- **SSL 事件**：进入 `handleEvent` 合并流程

### 2. 事件处理（handleEvent）

```
输入 SSL 事件
    │
    ▼
解析 JSON payload 获取 data 字段
    │
    ▼
isSSEData() 检测是否为 SSE 格式？───否──→ 直接透传
    │是
    ▼
parseSSEEvents() 解析出 SSE 事件列表
    │
    ▼
全部是元数据事件（ping/heartbeat/空）？───是──→ 丢弃（静默过滤）
    │否
    ▼
connectionID() 生成聚合 key
    │
    ▼
查找或创建 accumulator
    │
    ▼
accumulator.update() 追加事件 + 累积内容
    │
    ▼
isComplete() 检查是否完整？───否──→ 继续等待后续碎片
    │是
    ▼
hasMeaningfulContent()？───否──→ 丢弃
    │是
    ▼
toEvent() 生成合并后的事件 → 输出
```

### 3. SSE 数据识别（isSSEData）

通过特征匹配判断原始 SSL 数据是否为 SSE 格式，满足任一条件即认定为 SSE：

| 条件 | 说明 |
|------|------|
| `event:` + `data:` | 标准 SSE 字段同时存在 |
| `text/event-stream` | Content-Type 表明 SSE 流 |
| `Transfer-Encoding: chunked` + (`event:` 或 `data:`) | 分块传输中的 SSE |
| `data:` + 双空行（`\r\n\r\n` 或 `\n\n`） | data 字段 + SSE 块分隔符 |

### 4. SSE 文本解析（parseSSEEvents）

分两步完成：

**第一步：清理 HTTP chunked 编码**（`cleanChunkedContent`）

HTTP chunked 传输编码的格式为 `<十六进制长度>\r\n<数据>\r\n`。清理器会：
- 识别十六进制长度行并跳过
- 提取实际数据行
- 遇到 `0`（终止块）停止

**第二步：解析 SSE 块**（`parseSSEEventsFromChunk`）

按 `\n\n` 分割为独立的 SSE 块，逐行解析 `event:`、`data:`、`id:` 字段。`data:` 字段如果能解析为 JSON，存入 `ParsedData`；否则保留为 `RawData`。

### 5. 连接标识生成（connectionID）

聚合 key 格式为 `pid:tid:timeWindow`：

```go
window := event.TimestampNs / 600_000_000_000  // 10 分钟窗口
key = fmt.Sprintf("%d:%d:%d", pid, tid, window)
```

- **pid** — 进程 ID
- **tid** — 线程 ID（区分同一进程的不同 SSL 连接）
- **timeWindow** — 将时间戳按 600 秒（10 分钟）取整，避免长时间运行的连接堆积过多数据

同一进程、同一线程、同一 10 分钟窗口内的 SSE 碎片被归为同一个消息流。

### 6. 内容累积（accumulator.update）

收到新的 SSE 事件后，累积器执行：

1. 更新时间戳范围（`startTime`, `endTime`）
2. 记录挂钟时间（`lastUpdate`，用于超时判断）
3. 遍历所有 SSE 事件：
   - 发现 `message_start` → 标记 `hasMessageStart = true`
   - 发现 `content_block_delta` → 调用 `accumulateContentDelta` 提取文本

**`accumulateContentDelta` 的累积规则**（针对 Claude API 的 SSE 响应格式）：

| delta.type | 提取字段 | 累积到 |
|------------|---------|--------|
| `text_delta` | `delta.text` | `accumulatedText` |
| `thinking_delta` | `delta.thinking` | `accumulatedText` |
| _(任意)_ | `delta.partial_json` | `accumulatedJSON` |

### 7. 完成判定（isComplete）

满足以下任一条件即认为消息流完整：

- 收到 `message_stop` 事件（正常结束）
- 收到 `error` 事件（异常结束）
- `accumulatedText` 长度超过 50,000 字符（防止内存膨胀）
- `accumulatedJSON` 长度超过 50,000 字符（防止内存膨胀）

### 8. 有效内容判定（hasMeaningfulContent）

决定合并结果是否值得输出。满足任一条件即为有效：

- 收到过 `message_start` 事件
- `accumulatedJSON` 非空
- `accumulatedText` 非空

### 9. 超时与刷新机制

| 触发条件 | 方法 | 行为 |
|---------|------|------|
| 上下文取消（ctx.Done） | `flushAll` | 刷新所有累积器中有意义的内容并输出 |
| 输入 channel 关闭 | `flushAll` | 同上 |
| 定时器触发（每 30s） | `flushExpired` | 检查所有累积器，刷新超过 30s 未更新的 |

超时刷新确保以下场景不会造成数据丢失：
- SSE 连接异常断开，未收到 `message_stop`
- 网络延迟导致碎片间隔过长

### 10. 输出事件格式（toEvent）

合并完成后，生成一个新的 `Event`，`Source` 标记为 `sse_processor`，payload 结构如下：

```json
{
  "connection_id":     "12345:67890:42",
  "message_id":        "msg_01ABC...",
  "start_time":        1234567890000000000,
  "end_time":          1234567891000000000,
  "duration_ns":       1000000000,
  "original_source":   "ssl",
  "function":          "SSL_read",
  "tid":               67890,
  "json_content":      "{ ... }",
  "text_content":      "合并后的完整文本",
  "total_size":        1234,
  "event_count":       42,
  "has_message_start": true,
  "sse_events":        [ ... ]
}
```

其中 `json_content` 会尝试格式化为缩进的 JSON 以提升可读性。

## 元数据过滤

以下 SSE 事件被视为元数据，如果一个 SSL 事件中**只包含**这类事件，则整个事件被静默丢弃：

- `event` 类型为 `ping` 或 `heartbeat`
- `event` 和 `data` 均为空
- `data` 仅包含空白、`:` 或 `: `

这避免了心跳/保活包干扰合并逻辑和输出。

## 设计考量

1. **为什么在 HTTP 解析之前做 SSE 合并？** — eBPF 捕获的是原始 `SSL_read` 调用的碎片，每个碎片可能只是一条 SSE 消息的一部分。HTTP 解析器需要完整的请��/响应体才能正确工作，因此必须先合并。

2. **为什么用 pid+tid+timeWindow 作为聚合 key？** — pid 区分进程，tid 区分同进程内的不同 SSL 连接（如 Claude 使用独立的 "HTTP Client" 线程），timeWindow 防止单个长连接无限累积。

3. **为什么有 50,000 字符的硬上限？** — 防止异常情况下（如始终未收到 `message_stop`）内存无限增长。达到上限后强制完成，产生截断但安全的输出。

4. **为什么同时累积 text 和 JSON？** — Claude API 的 SSE 响应中，`text_delta`/`thinking_delta` 传递模型生成的文本内容，`partial_json` 传递工具调用的 JSON 参数。两者可能在同一消息流中交替出现。
