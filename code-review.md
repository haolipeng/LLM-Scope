# AgentSight Go 代码审核报告

> 审核时间：2026-03-27
> 审核范围：全部 Go 后端代码（约 33 个源文件）
> 代码来源：Codex 生成

---

## 第一轮：架构和设计层面的问题

### 问题 1：`record.go` 通过直接修改全局变量来复用 `runTrace`

**文件位置**：`cmd/agentsight/record.go:35-61`

`runRecord` 直接修改了 `trace.go` 中定义的全局变量（`traceSSL`、`traceProcess`、`traceComm` 等），然后调用 `runTrace`。这意味着 `record` 命令和 `trace` 命令通过**全局可变状态**强耦合。

**问题**：这种设计是有意为之的快速复用方案，还是后续会重构成配置结构体的传递方式？如果两个命令将来同时演化（比如 record 需要独有参数），这种全局变量共享会不会成为维护负担？

---

### 问题 2：`trace.go` 中 SSL 分析链的顺序 — SSEMerger 放在 HTTPParser 前面

**文件位置**：`cmd/agentsight/trace.go:108-109`

```go
sslAnalyzers = append(sslAnalyzers, analyzer.NewSSEMerger())
sslAnalyzers = append(sslAnalyzers, analyzer.NewHTTPParser(traceSSLRaw))
```

SSEMerger 排在 HTTPParser **前面**。SSEMerger 处理完后把 source 改成了 `"sse_processor"`，而 HTTPParser 只处理 `source == "ssl"` 的事件。这意味着**被 SSEMerger 合并的 SSE 数据不会再经过 HTTP 解析**。

**问题**：这个顺序是刻意设计的吗？SSE 流数据不需要 HTTP 解析？还是说 SSE 合并后的数据格式已经不再是 HTTP 报文了，所以不需要经过 HTTPParser？

---

### 问题 3：`ssl.go` (子命令) 中 SSEMerger 放在 AuthRemover 后面

**文件位置**：`cmd/agentsight/ssl.go:61-83` vs `cmd/agentsight/trace.go:103-116`

对比 `trace.go` 和 `cmd/agentsight/ssl.go`，两者的 analyzer 链顺序不一致：

- **trace.go**: SSLFilter → SSEMerger → HTTPParser → HTTPFilter → AuthRemover
- **ssl.go**: SSLFilter → HTTPParser → HTTPFilter → AuthRemover → SSEMerger

**问题**：两条路径处理同类数据，但 analyzer 顺序不同，这是有意为之还是疏忽？不同顺序会导致行为差异。

---

## 第二轮：潜在的 Bug

### 问题 4：`SSEMerger.accumulatedJSON` 拼接产生的不是合法 JSON

**文件位置**：`internal/analyzer/ssemerger.go:185-188`

```go
if jsonBytes, err := json.Marshal(event.ParsedData); err == nil {
    a.accumulatedJSON += string(jsonBytes)
}
```

多个 SSE 事件拼接后会变成 `{"a":1}{"b":2}`，这不是合法的 JSON。但在 `toEvent()` 第 246 行尝试做 `json.Unmarshal([]byte(jsonContent), &parsed)`，**对于多个事件拼接的情况一定会解析失败**，导致 pretty-print 不生效。

**问题**：这里 `accumulatedJSON` 的设计意图是什么？它应该是一个 JSON 数组，还是说只期望它在只有一个 ParsedData 的情况下生效？

---

### 问题 5：`cleanChunkedContent` 对非 chunked 数据会丢弃所有内容

**文件位置**：`internal/analyzer/ssemerger.go:355-372`

函数的逻辑是——遍历 `\r\n` 分割的行：如果是空行则跳过；如果是十六进制数则取下一行；**否则什么都不做，直接跳过该行**。

这意味着对于**不是 chunked transfer encoding 格式**的数据，所有有效内容行都会被丢弃，返回空字符串。

**问题**：这个函数是否默认所有 SSE 数据都来自 chunked transfer encoding？如果遇到非 chunked 的 SSE 数据（比如 HTTP/2 或直接的 SSE 流），是否会导致数据丢失？

---

### 问题 6：`FakeRunner` 使用 `time.Now().UnixNano()` 作为时间戳

**文件位置**：`internal/runner/fake.go:84` 和 `fake.go:133`

```go
timestamp := time.Now().UnixNano()
```

但系统其他部分（SSL/Process/Stdio Runner）使用的是 **nanoseconds since boot**，而 `core.BootNsToUnixMs()` 会在此基础上加上 boot time 偏移。如果 FakeRunner 传入的已经是 Unix 纳秒时间戳，`BootNsToUnixMs` 就会算出一个错误的时间。

**问题**：FakeRunner 是纯测试用途，不会在生产中使用对吗？如果会用于演示或集成测试，这个时间戳不一致会不会导致前端时间线显示错误？

---

## 第三轮：性能问题

### 问题 7：`FileLogger.writeEvent` 每个事件都打开/关闭文件

**文件位置**：`internal/analyzer/filelogger.go:83-88`

```go
file, err := os.OpenFile(f.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
// ...
defer file.Close()
```

每个事件都执行一次 `open` → `write` → `close` 系统调用。在高吞吐场景下（SSL 抓包可以产生大量事件），这会成为 I/O 性能瓶颈。

**问题**：是否考虑过保持文件句柄常驻，仅在日志轮转时关闭/重新打开？或者使用 `bufio.Writer` 做缓冲写入？

---

### 问题 8：`SSEMerger.isComplete()` 每次都遍历全部已累积事件

**文件位置**：`internal/analyzer/ssemerger.go:197-209`

每次调用 `isComplete()` 都遍历 `a.events` 查找 `message_stop` 或 `error`。随着 SSE 流的增长，这变成了 O(n) * n = O(n²) 的时间复杂度。

**问题**：是否可以在 `update()` 中用一个布尔标记记录是否已经遇到了完成信号，避免重复遍历？

---

### 问题 9：`getAllChildren` 递归遍历 /proc

**文件位置**：`internal/runner/system.go:160-190`

对每一级子进程，都要遍历 `/proc` 下的所有条目。如果进程树很深，最坏情况是 O(n * depth)，可能接近 O(n²)。

**问题**：这个函数在每个采样周期（默认 10 秒）都会调用。在进程数多的系统上是否会有明显延迟？是否考虑过一次性读取所有 `/proc/*/stat`，在内存中构建父子关系？

---

### 问题 10：`processMemory` 硬编码 pageSize = 4

**文件位置**：`internal/runner/system.go:332`

```go
pageSize := uint64(4) // KB
```

这假设页面大小是 4KB。在某些 ARM64 系统上页面大小可能是 16KB 或 64KB。

**问题**：是否考虑过使用 `os.Getpagesize()` 来获取实际页面大小？当前目标是只运行在 x86 Linux 上吗？

---

## 第四轮：并发和资源管理

### 问题 11：`channelRunner.Run` 创建了不必要的中间 goroutine

**文件位置**：`internal/runner/channel.go:27-45`

`channelRunner` 已经持有一个 event channel，但 `Run()` 方法又创建了一个新 channel 和一个代理 goroutine。在 `trace.go` 中，SSL 事件经过 analyzer chain 后用 `FromChannel` 包装，然后 `CombinedRunner` 又调用 `Run()` 再创建一层代理。

**问题**：这个额外的中间层是为了统一接口，还是有其他考虑（比如确保 context 取消时的正确关闭语义）？

---

### 问题 12：`EventHub.Publish` 静默丢弃事件

**文件位置**：`internal/server/hub.go:30-34`

```go
select {
case ch <- event:
default:  // 静默丢弃
}
```

当订阅者的 channel 满了，事件被直接丢弃，没有任何日志或指标。

**问题**：这是预期的背压策略吗？前端 SSE 客户端如果处理慢了，是否会丢失关键事件？是否需要至少记录一个丢弃计数器？

---

### 问题 13：Web 服务器没有优雅关闭机制

**文件位置**：`cmd/agentsight/trace.go:202-204`

```go
go func() {
    _ = router.Run(addr)
}()
```

`router.Run` 的错误被忽略，且没有 graceful shutdown 逻辑。如果端口被占用，启动会静默失败；程序退出时也不会等待正在处理的 HTTP 请求完成。

**问题**：这里是否应该使用 `http.Server` 配合 `Shutdown(ctx)` 来实现优雅关闭？端口冲突时是否应该报错给用户？

---

## 第五轮：代码质量

### 问题 14：`getEvents` API 将整个日志文件读入内存

**文件位置**：`internal/server/api.go:22`

```go
data, err := os.ReadFile(logPath)
```

从项目目录看，`record.log` 已经有 8.3MB。在长时间运行后可能会更大。整个文件一次性读入内存返回给客户端。

**问题**：是否考虑过分页、流式返回，或者最多返回最近 N 条事件？

---

### 问题 15：`toolcall.go` 缩进格式不一致

**文件位置**：`internal/analyzer/toolcall.go:66-86`

`select/case` 块混合使用了空格和 tab，缩进层级不一致（对比第 68 行和第 71 行的缩进深度）。

**问题**：这是 Codex 生成时的格式��题吗？是否运行过 `gofmt`？

---

### 问题 16：`BinaryExecutor.Stop()` 使用 SIGKILL

**文件位置**：`internal/runner/executor.go:145`

```go
return e.cmd.Process.Kill()
```

`Kill()` 发送 SIGKILL，不给 eBPF 程序清理的机会。

**问题**：eBPF 用户态程序（sslsniff, process 等）是否有需要在退出时执行的清理逻辑（比如 detach BPF 程序、释放 map）？是否应该先发 SIGTERM，等待超时后再 SIGKILL？

---

### 问题 17：`viper.BindPFlag` 返回值被忽略

**文件位置**：`cmd/agentsight/main.go:37-38`

```go
viper.BindPFlag("server", rootCmd.PersistentFlags().Lookup("server"))
viper.BindPFlag("server-port", rootCmd.PersistentFlags().Lookup("server-port"))
```

**问题**：这里忽略错误是有意的吗？在实际项目中 `BindPFlag` 失败的可能性很低，但 Go 的 best practice 通常建议至少做 `_ =` 标注或在 init 阶段做 `must` 检查。

---

## 问题严重程度总结

| 严重程度 | 问题编号 | 说明 |
|---------|---------|------|
| **高（Bug）** | #4, #5 | SSE JSON 拼接非法、chunked 清理会丢数据 |
| **高（设计）** | #2, #3 | analyzer 链顺序不一致，可能导致不同入口行为不同 |
| **中（性能）** | #7, #8, #9 | 文件每次开关、O(n²) 遍历、递归 /proc 扫描 |
| **中（可靠性）** | #12, #13 | 事件静默丢弃、服务器无优雅关闭 |
| **低（代码质量）** | #1, #6, #10, #11, #14, #15, #16, #17 | 全局变量耦合、FakeRunner 时间戳、硬编码页面大小等 |
