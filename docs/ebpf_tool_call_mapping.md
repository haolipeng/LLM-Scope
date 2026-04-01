# eBPF 事件到 `tool_call_*` 的自动映射规则（MVP）

本文给出将 eBPF 采集到的系统调用事件自动归并为一次 `tool_call_start` / `tool_call_end` 的最小可用规则，目标是将低层行为提升为“工具调用”视角，支撑卡住/循环/结果不对的诊断。

## 1. 前提与输入

- eBPF 可采集：`execve/execveat`、`open/openat`、`read/write`、`close`、`rename`、`unlink`、`connect`、`accept`、`send/recv`、`exit`。
- 基本上下文：`pid/tid/ppid`、`argv`、`cwd`、`sockaddr`、`errno/return`、`timestamp`。
- 可选增强：读取少量用户态缓冲区用于识别 HTTP 方法或 TLS SNI。

## 2. 事件模型

### 2.1 `tool_call_start`

- `tool_name`: 见规则表
- `args_summary`: 低成本摘要（path/addr/argv/bytes）
- `args_hash`: 对摘要关键字段 hash
- `run_id`、`step_id`：由上层相关性策略补齐

### 2.2 `tool_call_end`

- `status`: `success` / `timeout` / `error`
- `error_code`: errno 或超时原因
- `response_summary`: 读取/写入字节数或返回摘要

## 3. 归并逻辑（span 规则）

使用“聚合键 + 时间窗口”的方式将多次 syscall 归并为一次工具调用。

**聚合键**

```
key = run_id + pid + tid + tool_name + key_field
```

- `key_field` 由不同工具类型决定（文件路径 / 目标地址 / 命令名）。

**start 触发**

- 首次出现对应 syscall（如 `openat` / `connect` / `execve`）。

**end 触发**

- `close` / `exit` / 明确错误返回。
- 超过 `idle_gap`（默认 500ms～2s）无新 syscall 则切分为一次调用。

**合并窗口**

- 同一聚合键在 `idle_gap` 内连续事件合并为同一次调用。
- 超过 `max_duration`（如 60s）强制切分并标记超时。

## 4. 工具类型映射规则（核心表）

| tool_name   | 触发 syscall（start）                         | key_field          | args_summary 示例                 |
|------------|----------------------------------------------|--------------------|----------------------------------|
| fs.read    | `openat(O_RDONLY)` 或 `read`                  | resolved_path      | `path=... bytes=...`             |
| fs.write   | `openat(O_WRONLY/O_RDWR)` 或 `write/rename`   | resolved_path      | `path=... bytes=...`             |
| fs.list    | `openat` 打开目录 + `getdents64`             | dir_path           | `dir=...`                        |
| proc.exec  | `execve/execveat`                             | argv[0]            | `argv="git status"`            |
| net.connect| `connect` + `send/recv`                       | dst_ip:dst_port    | `dst=1.2.3.4:443`                |
| net.http   | `connect` 且首包含 HTTP 方法或可解析 TLS SNI  | dst_ip:dst_port    | `method=GET host=...`            |
| net.dns    | `sendto` 目标端口 53（UDP/TCP）               | dst_ip:53          | `dst=8.8.8.8:53`                 |

说明：
- `net.http` 优先级高于 `net.connect`。若无法识别 HTTP/TLS SNI，回退为 `net.connect` 或 `net.tcp`。
- `fs.write` 可包含 `rename/unlink` 等与写入直接相关的 syscall 作为补充。

## 5. 字段填充规则

**tool_call_start**

- `tool_name`: 由上表判定。
- `args_summary`: 路径、地址、命令等最小摘要。
- `args_hash`: 对关键字段 hash（`path|addr|argv`）。

**tool_call_end**

- `status`:
  - `success`：返回码为 0 或符合预期
  - `error`：errno 非 0
  - `timeout`：超过 `max_duration` 或长时间无进展
- `error_code`: errno 或 `ETIMEDOUT`
- `response_summary`: 字节数/摘要字符串

## 6. 边界情况处理

- **长连接**：`connect` 后无 `close`，使用 `idle_gap` 切分为多段。
- **重复读写**：同一路径短时间多次 `read/write` 合并为一次调用。
- **目录遍历**：`openat` 目录 + `getdents64` 视作 `fs.list`。
- **进程分裂**：`fork` 后子进程继承 `run_id`，按 `pid/tid` 区分。

## 7. 示例（eBPF → tool_call）

- `openat(O_WRONLY) + write* + close` → `tool_call_start(fs.write)` / `tool_call_end(fs.write)`
- `execve("git", "status")` → `tool_call_start(proc.exec)` / `tool_call_end(proc.exec)`
- `connect(1.2.3.4:443) + send("GET /")` → `tool_call_start(net.http)` / `tool_call_end(net.http)`

## 8. 推荐配置参数（初始值）

- `idle_gap`: 1000ms
- `max_duration`: 60s（可对 `net.connect` 放宽）
- `loop_merge_window`: 2s（用于聚合同一路径/地址）

## 9. 可落地实现建议

- 建立一个内存中的 `active_calls` 哈希表（key = `run_id+pid+tid+tool+key_field`）。
- 每个 syscall 更新该 entry 的 `last_event_time`，并累积 `bytes_in/out`。
- 定时扫描过期条目，生成 `tool_call_end(status=timeout)`。

