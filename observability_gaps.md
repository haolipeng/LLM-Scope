# AgentSight 可观测性完善项（对标主流 AI Agent 产品）

基于当前能力（eBPF + SSL/进程/系统事件 + HTTP/SSE 解析 + JSONL/SSE 输出），以下是对标 Claude Code、Gemini、Codex、Cursor 等 LLM 产品所需的主要补强方向。

## 语义与链路
- 事件模型偏底层，缺少 agent 语义字段（agent_id/session_id/conversation_id/trace_id/span_id/tool_id、模型/版本、prompt/response/token 统计、成本等）。
- 缺少跨步骤链路建模（plan → tool call → result → LLM response）与因果关系，无法构建完整执行图。
- 缺少失败/重试/降级/缓存命中等行为状态事件，难以做 SLO 与根因分析。

## 采集与协议覆盖
- HTTP 解析较粗，SSE 合并依赖简单规则；缺 HTTP/2、WebSocket、gRPC streaming 等主流流式协议支持。
- 仅从 SSL/进程层采集，无法捕获应用内部“工具调用”“文件变更”“命令执行”等关键 agent 行为。
- 需要针对主流供应商（OpenAI/Anthropic/Google/自建）做请求/响应 schema 识别与统一规范化。

## 存储、查询、指标
- 目前以文件 JSONL 与 SSE 实时流为主，缺少结构化索引/查询能力（时序/Trace/全文）。
- 缺少指标聚合（延迟分布、token/s、失败率、模型成本）与可视化面板；建议支持 Prometheus/OpenTelemetry/OTLP 导出。
- 缺少 retention、分片与冷热分层策略，长时间运行存在日志与内存压力。

## 安全与治理
- 仅移除部分 header，缺 prompt/response 中 PII/密钥/内部路径的脱敏与可配置审计策略。
- 需要权限/多租户隔离：谁能看哪些对话、哪些 agent、哪些进程。
- 需要合规审计：采集范围、保留策略、数据出境与加密存储。

## 可靠性与性能
- 事件通道/Hub 为单机内存 fan-out，缺 backpressure、持久化队列与掉线重连一致性。
- 解析与合并逻辑缺少显式测试与鲁棒性保障，异常输入可能导致事件丢失。
- 缺少采样/限流/分级采集策略，高流量场景可能影响稳定性。

## 产品体验（对标 LLM IDE/Agent）
- 缺少执行树/时间线/因果图/工具调用详情/文件变更 diff/命令记录等可视化。
- 缺少提示词模板/上下文窗口/向量检索命中/缓存/工具依赖图等专用视图。
- 缺少“可复现实验”能力：导出可回放的完整会话包。
