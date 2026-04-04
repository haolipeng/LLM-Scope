# Claude Code 场景下如何「真实」触发三类安全告警

进程采集使用 **`/proc/<pid>/comm`**（最多约 15 字符）与 **父进程链**：只有 **comm 命中 `--comm` 列表** 的进程，以及 **其子进程树** 里产生的事件会进入流水线并可能被安全规则命中。

因此：

- 要让告警**对 Claude Code 监控有效**，需要让 **FILE_OPEN / EXEC / NET_CONNECT** 发生在 **Claude Code 所启动或派生的进程**里（例如 Claude 内置终端、由 agent 调起的命令）。

---

## 推荐流程（先清空，再采集，再触发）

1. **清空历史告警**（`--duckdb-path` 与下面 `record` 使用**完全相同的绝对或相对路径**）  
   - 若采集**已在运行**：请先 **Ctrl+C 结束** `./agentsight record`，再清空；否则 DuckDB 可能被占用导致清空失败。  
   - 若你用 **`sudo ./agentsight record`** 创建库文件，库通常属 **root**，清空也需 **`sudo`**，否则会权限不足：  
     `sudo ./agentsight clear-security-alerts --duckdb-path ./agentsight.duckdb`  
   - 未写 `--duckdb-path` 时，默认在当前**工作目录**下的 `agentsight.duckdb`；`sudo` 时 cwd 可能是 `/root`，与你在项目目录里看到的文件不是同一个——**建议始终显式写 `--duckdb-path` 的绝对路径**（例如 `$PWD/agentsight.duckdb`）。

2. **启动采集**（见下节）。

3. **在 Claude Code 内**按文末表格依次执行命令，产生新告警。  
   - 本步骤**必须在 Claude Code 内**由你或 Agent 发起（外部工具无法代替你在 IDE 里执行终端命令）。

---

## 启动采集

示例（按本机 Node 安装路径调整 `--binary-path`，用于 SSL 探针挂到静态链接 OpenSSL 的运行时）：

```bash
sudo ./agentsight record -c claude --binary-path /opt/node-v22.20.0/bin/node \
  --duckdb-path ./agentsight.duckdb --server
```

（亦可用官方文档中的 `~/.local/share/claude/versions/<version>` 等路径；`trace` 等见 `CLAUDE.md`。）

---

## 在 Claude Code 内触发（示例思路）

以下需通过 **Claude Code 能执行终端命令** 的方式发起（具体以你使用的「Run command」/终端能力为准），使进程落在已跟踪树下。

| 告警类型 | 规则要点 | 示例（让 Claude 执行） |
|----------|----------|------------------------|
| **sensitive_file_access** | `FILE_OPEN` 等 + 路径含敏感子串（如 `/etc/passwd`、`.env`） | 只读：`head -n 1 /etc/passwd` 或 `wc -c ~/.env`（若存在） |
| **dangerous_command** | `EXEC` + `full_command` 命中危险正则 | 在**临时目录**上：`d=$(mktemp -d); /bin/chmod 777 "$d"; rmdir "$d"`（建议写 **`/bin/chmod`**，确保走真实可执行文件，便于 eBPF 上报 `sched_process_exec` 与完整命令行） |
| **suspicious_network** | `NET_CONNECT` + **公网 IP** + **非白名单端口** | `curl -sS --connect-timeout 4 --max-time 8 http://1.1.1.1:4444/ || true`（不要用 `bash` 的 `/dev/tcp/...`，会命中另一类「危险命令」规则） |

**注意**：读敏感路径、改权限、外连均可能影响环境或策略，仅在**测试环境**使用，并自行评估风险。

---

## 文档勘误与易错点（对照 `internal/pipeline/transforms/security.go`）

| 问题 | 说明 |
|------|------|
| **DuckDB 路径与 sudo** | `record` 用 `sudo` 且未固定 `--duckdb-path` 时，库可能落在 **root 的当前目录**；清空、查库须用**同一路径**，且清空时往往需 **`sudo`**。 |
| **先停再清** | 采集进程占用 DuckDB 时无法可靠清空；文档原顺序是「先清空再 record」；若你已先启动 record，须**先停再清**再重启，或接受不清空直接叠加新告警。 |
| **`dangerous_command` 风险等级** | 代码中为 **`critical`**，不是「中」；Web 上展示以库中为准。 |
| **`suspicious_network` 无告警** | 需进程事件 **`NET_CONNECT`** + **公网 IP** + **端口不在白名单**。`curl` 若未真正发起连接（网络策略、解析失败、无 `curl`），可能无此类告警；`1.1.1.1:4444` 常被对端拒绝，一般仍会有连接尝试，**视 eBPF 是否上报为准**。 |
| **`--comm` 与 node** | 子进程 comm 可能是 `node` 等；若发现进程事件缺失，可尝试 `record -c claude,node`（逗号分隔），见 `CLAUDE.md`。 |
| **表格中的 `chmod`/`curl`** | 必须由 **Claude Code 所拉起终端里的 shell** 执行，使子进程落在已跟踪进程树下；在**本机另一个 SSH/终端**里执行通常**不会**记入 `-c claude` 会话。 |
| **`chmod 777` 仍无 dangerous_command** | 见下节「排查」 |

### `chmod 777` 仍无 dangerous_command 告警？

规则要求 **`event=EXEC`** 且 **`full_command` 含 `chmod 777`**（`security.go` 中正则 `\bchmod\s+777\b`）。常见原因：

1. **命令不在被跟踪进程树下**  
   采集器只把 **comm 命中 `--comm`** 的进程，以及其 **直接子进程**（父 PID 在跟踪列表里）纳入事件。若你在 **系统自带 SSH、本机另一个终端** 里跑命令，**父进程不是** Claude Code 拉起的 `node`/`bash` 链，则 **`chmod` 的 EXEC 不会进入流水线**，自然无告警。  

2. **中间进程 comm 不是 `claude`**  
   终端里常是 `node` → `bash` → `chmod`。若只写 `-c claude`，通常 **claude 与 node 都会在启动时进跟踪**；若仍缺事件，可显式：`-c claude,node`（逗号分隔）。

3. **`trace` 开了进程最短存活时间**  
   若使用 `trace --duration <非0>`（进程最小持续时间 ms）且 **min_duration_ns > 0**，eBPF 在 **`sched_process_exec` 上直接不发射 EXEC 样本**（见 `bpf/process.bpf.c` 中 `min_duration_ns` 分支），**`dangerous_command` 无法命中**。`record` 默认进程 `Duration` 为 0，一般无此问题。

4. **确认链路上真有 EXEC**  
   在 `events_process` 里查是否有 `event_type` 含 EXEC、且 `full_command` 含 `chmod` 的行；若表为空，问题在采集/过滤，不在安全规则。

5. **建议命令**  
   使用 **`/bin/chmod 777 "$d"`**（或 `command -v chmod` 的绝对路径），避免个别环境下对 `chmod` 解析异常；仍须满足 (1)(2)。
