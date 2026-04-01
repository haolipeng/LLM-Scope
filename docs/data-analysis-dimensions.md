# AgentSight 采集数据分类与分析维度

> 基于 record.log 数据（共 85,987 条记录）和源代码的深入分析

---

## 一、数据分为三大类

### 1. 工具调用事件 (`source: "tool_call"`) — 55,070 条 (64%)

由 ToolCallAggregator 从底层 process 事件聚合生成，代表 AI Agent 的"动作"。

| 工具名 | 数量 | 含义 |
|--------|------|------|
| `fs.read` | 53,059 | 文件读取（含库加载） |
| `proc.exec` | 1,830 | 进程执行 |
| `fs.write` | 181 | 文件写入 |

每个工具调用有 `tool_call_start` 和 `tool_call_end` 配对，包含 `duration_ms`、`bytes`、`status`、`reason` 等。

### 2. 进程事件 (`source: "process"`) — 28,920 条 (33.6%)

eBPF 内核级采集的原始系统调用事件：

| 事件类型 | 数量 | 含义 |
|---------|------|------|
| `FILE_OPEN` | 26,832 | 文件打开操作 |
| `EXEC` | 915 | 进程创建/执行 |
| `EXIT` | 865 | 进程退出 |
| `DIR_CREATE` | 128 | 目录创建 |
| `NET_CONNECT` | 87 | 网络连接 |
| `FILE_DELETE` | 76 | 文件删除 |
| `FILE_RENAME` | 17 | 文件重命名 |

### 3. 系统指标 (`source: "system"`) — 1,997 条 (2.3%)

周期性采样的资源使用数据，包含 CPU、内存、线程数等。

> 注：代码中还支持 `ssl`（SSL/TLS 流量）、`stdio`（标准 I/O）、`http_parser`（HTTP 解析）事件源，当前采集数据中未出现，但架构已支持。

---

## 二、可观测性分析维度

### 1. Agent 行为画像

- **工具调用频次与模式**：Agent 调了哪些工具、频率如何、调用链是什么样的
- **工具调用耗时分布**：`duration_ms` 的 P50/P95/P99，识别慢调用
- **工具调用成功率**：`status` 字段（success/timeout），失败原因 `reason` 分析
- **进程派生树**：通过 `EXEC` 的 `pid/ppid` 重建完整的进程树，观察 Agent 的命令执行链路
- **进��生命周期**：`EXEC → EXIT` 配对，分析 `duration_ms` 和 `exit_code`

### 2. 资源消耗分析

- **CPU 使用趋势**：按进程、按时间窗口的 CPU 使用率变化
- **内存增长曲线**：RSS/VSZ 的时序变化，检测内存泄漏
- **线程数监控**：进程线程数变化趋势
- **资源告警**：`alert` 字段标识是否超过阈值

### 3. 文件 I/O 分析

- **热点文件**：被频繁访问的文件路径 Top-N（`key_field` / `filepath`）
- **读写比例**：`fs.read` vs `fs.write` 的比例
- **文件操作模式**：从 `flags` 可区分只读(524288=O_RDONLY|O_CLOEXEC)、创建写入(525377)等
- **目录操作**：`DIR_CREATE` 追踪工作目录的创建模式
- **文件变更**：`FILE_DELETE` + `FILE_RENAME` 追踪文件生命周期

### 4. 网络行为分析

- **网络连接目标**：`NET_CONNECT` 的 `ip:port` 分布
- **连接频率**：同一目标的连接次数和时间模式
- **协议族分析**：`family=2`(IPv4) vs `family=10`(IPv6)

### 5. 时序与关联分析

- **事件时间线**：纳秒级时间戳支持精确的事件排序和因果推断
- **工具调用间隔**：相邻工具调用的时间间距，识别思考/等待时间
- **并发度**：同一时间窗口内的并行活动数

---

## 三、安全分析维度

### 1. 命令执行审计

- **命令注入检测**：审计 `EXEC` 的 `full_command`，检测是否有危险命令（`rm -rf`、`chmod 777`、`curl | bash` 等）
- **异常进程链**：识别非预期的进程派生关系（如 Agent 启动了反弹 shell）
- **异常退出码**：`exit_code != 0` 的命令分析

### 2. 文件系统安全

- **敏感文件访问**：监控对 `/etc/passwd`、`/etc/shadow`、`.env`、credentials 文件的读取
- **敏感文件修改**：对系统配置文件、SSH 密钥等的写入操作
- **临时文件安全**：分析 `/tmp` 目录的文件创建模式，检测恶意临时文件
- **异常路径访问**：如访问 `/proc/self/maps`、其他进程的 `/proc/[pid]/cmdline` 等

### 3. 网络安全

- **异常外连**：连接到非预期的 IP 地址或端口
- **高频连接**：短时间大量网络连接可能是扫描行为
- **数据外泄风险**：结合文件读取 + 网络连接，检测 "先读敏感文件后外连" 的模式

### 4. 权限与权限提升

- **CRED_CHANGE 事件**：代码支持但当前数据未出现，用于检测 UID/GID 变更
- **特权操作检测**：以 root 身份执行的危险命令
- **目录权限**：`DIR_CREATE` 的 `mode` 字段（如 `mode=511` 即 `0777`）

### 5. Agent 行为基线与异常检测

- **行为基线建模**：基于历史数据建立 Agent 的正常行为模式（调用频率、访问文件范围、网络目标等）
- **偏离检测**：当实际行为偏离基线时告警
- **Token/成本异常**：结合 SSL 拦截的 API 请求/响应，分析 token 消耗异常

---

## 四、当前数据中值得关注的具体发现

从现有数据看（以 `claude` 进程为例）：

- 频繁连接 `10.107.12.70:7897`（代理/API 网关）
- 访问了 `/proc/[pid]/cmdline`（遍历系统进程信息）
- 操作了 `/root/.claude.json`（配置文件的原子写入模式：tmp → rename）
- 在 `/tmp/claude-0/` 下创建和删除临时工作文件

这些行为模式本身是 AI Agent 的正常运行特征，但建立了很好的分析基线。

---

## 五、数据样本参考

### 工具调用事件样本

```json
{
  "timestamp_ns": 11735029025808,
  "timestamp_unix_ms": 1775045169029,
  "source": "tool_call",
  "pid": 8483,
  "comm": "node",
  "data": {
    "args_hash": "18768827c5b0b891",
    "bytes": 0,
    "duration_ms": 0,
    "event_type": "tool_call_end",
    "key_field": "/proc/451/cmdline",
    "reason": "idle_gap",
    "status": "timeout",
    "tid": 0,
    "tool_name": "fs.read"
  }
}
```

### 进程 EXEC 事件样本

```json
{
  "timestamp_ns": 11741396182718,
  "timestamp_unix_ms": 1775045175396,
  "source": "process",
  "pid": 30696,
  "comm": "echo",
  "data": {
    "comm": "echo",
    "event": "EXEC",
    "filename": "/usr/bin/echo",
    "full_command": "echo",
    "pid": 30696,
    "ppid": 7817,
    "timestamp": 11741396182718
  }
}
```

### 进程 EXIT 事件样本

```json
{
  "timestamp_ns": 11745949164291,
  "timestamp_unix_ms": 1775045179949,
  "source": "process",
  "pid": 30699,
  "comm": "git",
  "data": {
    "comm": "git",
    "duration_ms": 4,
    "event": "EXIT",
    "exit_code": 0,
    "pid": 30699,
    "ppid": 8483,
    "rate_limit_warning": "Process had 30+ file ops per second",
    "timestamp": 11745949164291
  }
}
```

### 网络连接事件样本

```json
{
  "timestamp_ns": 11746998384275,
  "timestamp_unix_ms": 1775045180998,
  "source": "process",
  "pid": 29986,
  "comm": "claude",
  "data": {
    "comm": "claude",
    "event": "NET_CONNECT",
    "family": 2,
    "ip": "10.107.12.70",
    "pid": 29986,
    "port": 7897,
    "timestamp": 11746998384275
  }
}
```

### 系统指标事件样本

```json
{
  "timestamp_ns": 11745050000000,
  "timestamp_unix_ms": 1775045179050,
  "source": "system",
  "pid": 10263,
  "comm": "node",
  "data": {
    "alert": false,
    "comm": "node",
    "cpu": { "cores": 4, "percent": "0.10" },
    "memory": { "rss_kb": 25552, "rss_mb": 24, "vsz_kb": 11518240, "vsz_mb": 11248 },
    "pid": 10263,
    "process": { "children": 0, "threads": 11 },
    "timestamp": 11745050000000,
    "type": "system_metrics"
  }
}
```

### 文件删除事件样本

```json
{
  "timestamp_ns": 11753088410265,
  "timestamp_unix_ms": 1775045187088,
  "source": "process",
  "pid": 29986,
  "comm": "libuv-worker",
  "data": {
    "comm": "libuv-worker",
    "event": "FILE_DELETE",
    "filepath": "/tmp/claude-0/-home-work-agentsight-go/tasks/b219312.output",
    "flags": 0,
    "pid": 29986,
    "timestamp": 11753088410265
  }
}
```

### 目录创建事件样本

```json
{
  "timestamp_ns": 11746973492051,
  "timestamp_unix_ms": 1775045180973,
  "source": "process",
  "pid": 29986,
  "comm": "libuv-worker",
  "data": {
    "comm": "libuv-worker",
    "event": "DIR_CREATE",
    "mode": 511,
    "path": "/tmp/claude-0/-home-work-agentsight-go/tasks",
    "pid": 29986,
    "timestamp": 11746973492051
  }
}
```

### 文件重命名事件样本

```json
{
  "timestamp_ns": 11747024982870,
  "timestamp_unix_ms": 1775045181024,
  "source": "process",
  "pid": 29986,
  "comm": "claude",
  "data": {
    "comm": "claude",
    "event": "FILE_RENAME",
    "newpath": "/root/.claude.json",
    "oldpath": "/root/.claude.json.tmp.29986.1775045181801",
    "pid": 29986,
    "timestamp": 11747024982870
  }
}
```
