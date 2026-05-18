# PRD: 进程 AI 通信视图

## Problem Statement

用户使用 AgentSight 监控 AI Agent 的运行过程时，无法清晰地看到某个特定进程与 AI 服务之间的网络通信细节——发出了什么请求（prompt、model、参数）、收到了什么应答（AI 生成的文本、tool use 调用）。现有的进程树视图虽然展示了进程层级和事件列表，但 HTTP 请求和 SSE 响应混杂在其他事件中，且没有将请求与对应的响应配对展示，用户需要自己在大量事件中人肉拼凑一次完整的 AI 调用过程。

## Solution

在前端新增 `ai-traffic` 视图模式。用户从进程树的进程节点点击网络图标按钮后，切换到该视图并按 PID 过滤，展示该进程所有 AI 相关的 HTTP 请求-响应对。每对通信以折叠卡片形式呈现：标题栏显示方法、路径、状态码、主机、模型名、耗时等摘要信息；展开后提供"结构化摘要"和"原始 JSON"两个 tab，结构化摘要面向快速理解（请求侧展示 model、system prompt、messages 列表；响应侧展示 AI 回复文本、tool use、thinking），原始 JSON 面向深度调试。后端新增专用 API 端点，负责查询数据库并按 pid + tid + 时间顺序完成请求-响应配对。

## User Stories

1. As a developer monitoring an AI agent, I want to click on a process in the process tree and see all its AI API calls, so that I can understand what the agent is doing.
2. As a developer debugging a failed AI call, I want to see the HTTP status code and error response for a specific request, so that I can diagnose the issue quickly.
3. As a developer, I want to see the request and response paired together in a single card, so that I don't have to manually match them across scattered events.
4. As a developer, I want to see a structured summary of the request (model, messages, system prompt) without reading raw JSON, so that I can quickly understand what was sent to the AI.
5. As a developer, I want to see the AI's response text rendered cleanly (with markdown), so that I can read the output naturally.
6. As a developer, I want to switch to the raw JSON tab when I need to inspect headers, exact body payloads, or debug encoding issues, so that I have full visibility when needed.
7. As a developer, I want the view to default to AI-related traffic only (filtered by known AI host domains and API paths), so that I'm not overwhelmed by irrelevant HTTP noise.
8. As a developer, I want a toggle to switch between "AI traffic only" and "all HTTP traffic", so that I can also inspect non-AI requests when needed.
9. As a developer, I want the card title bar to show method, path, status code, host, model name, and duration at a glance, so that I can scan multiple calls quickly and spot anomalies.
10. As a developer, I want to see tool_use calls made by the AI in the response summary, so that I can trace the agent's tool usage.
11. As a developer, I want to see the AI's thinking/reasoning content (when extended thinking is enabled) in a collapsible section, so that I can optionally inspect the model's chain of thought.
12. As a developer, I want the system prompt displayed in a collapsible section in the request summary, so that long system prompts don't clutter the view.
13. As a developer, I want the view to show an empty state message when a process has no AI traffic, with a prompt to switch to "all HTTP traffic" view, so that I'm not confused by a blank screen.
14. As a developer, I want the URL to include the pid parameter (e.g. `?pid=123`) when viewing AI traffic, so that I can share or bookmark a specific process's traffic view.
15. As a developer, I want cards numbered sequentially (#1, #2, ...) so that I can reference specific calls in discussion.
16. As a developer, I want to see the messages list in the request summary with role labels (user/assistant/system) and content preview, so that I can follow the conversation context sent to the AI.

## Implementation Decisions

### Backend: New API Endpoint

- New route: `GET /api/analytics/process/:pid/ai-traffic`
- Query parameters: `session_id` (optional filter), `all` (boolean, when true returns all HTTP traffic, not just AI)
- The handler queries `events_http` and `events_sse` tables, both filtered by the given PID
- Pairing logic: group by `pid + tid` (thread ID), then within each group, match each HTTP request (`http_message_type = 'request'`) with the temporally nearest subsequent SSE response or HTTP response, using `http_tid` from `events_http` and parsing `pid:tid:window` from `sse_connection_id` in `events_sse`
- AI traffic filtering: default filter by host whitelist (`api.anthropic.com`, `api.openai.com`, `generativelanguage.googleapis.com`, `api.deepseek.com`) combined with path pattern matching (`/v1/messages`, `/v1/chat/completions`, `/v1/responses`, `/api/generate`)
- Response format: array of paired objects, each containing `request` (from events_http) and `response` (from events_sse or events_http response), plus computed fields like `duration_ms` (time delta between request and response end)
- The `data_json` field from both tables is included in full, giving the frontend access to headers, body, sse_events, etc.

### Frontend: New ViewMode

- Add `'ai-traffic'` to the `ViewMode` type union in `page.tsx`
- New state: `selectedPid` (number | null) to track which process is selected
- New component: `AITrafficView` that receives `pid` and renders the card list
- URL parameter: `pid` is read from and written to search params for bookmarkability

### Frontend: Process Tree Integration

- In `ProcessNode.tsx`, add a network icon button (from heroicons) next to each process node's header
- Clicking the button calls a callback `onViewAITraffic(pid)` which is threaded up to `page.tsx`
- `page.tsx` sets `viewMode = 'ai-traffic'` and `selectedPid = pid`, and updates the URL search params

### Frontend: AITrafficView Component

- Fetches data from the new API endpoint on mount and when pid changes
- Renders a list of `AITrafficCard` components
- Top bar: shows PID and process name, toggle for "AI traffic only" vs "all HTTP traffic"
- A "back to process tree" button to return to the process tree view

### Frontend: AITrafficCard Component

- **Collapsed state (title bar):** `#N  METHOD /path → STATUS  |  host  |  model-name  |  duration`
  - Status code color-coded: green for 2xx, yellow for 4xx, red for 5xx
  - Duration computed from request timestamp to response end timestamp
  - Model name extracted from request body's `model` field
- **Expanded state:** Two tabs — "Summary" and "Raw JSON"
- **Summary tab - Request side:**
  - Model + parameters line (max_tokens, temperature)
  - System prompt in a collapsible section
  - Messages list: each message shows a role badge (user/assistant/system) + content text
- **Summary tab - Response side:**
  - AI response text rendered as markdown (from `text_content` field in SSE data)
  - Tool use blocks (if any): tool name + input JSON
  - Thinking content in a collapsible section (if any extended thinking blocks)
- **Raw JSON tab:**
  - Request headers + body as formatted JSON
  - Response headers + SSE events as formatted JSON

### Internationalization

- All new UI strings added to both `zh.ts` and `en.ts` locale files

## Testing Decisions

### What makes a good test

Tests should verify external behavior through the public interface, not internal implementation details. A good test describes a user scenario, sets up the necessary state, exercises the public API, and asserts on observable output.

### Backend tests

- `handleAITraffic` handler test: insert known rows into `events_http` and `events_sse` (with specific pids, tids, timestamps), call the API, assert that requests and responses are correctly paired
- AI filter test: insert both AI-related and non-AI HTTP events, verify that default filtering returns only AI traffic, and `?all=true` returns everything
- Edge cases: process with no HTTP events returns empty array; request with no matching response returns request-only pair with null response

### Prior art

- Existing handler tests in `internal/pipeline/sink/duckdb_test.go` demonstrate the pattern of creating a test DuckDB, inserting data, and querying
- Existing `handleSecurityAlerts` and `handleTimeline` handlers show the pattern for parameterized queries with session/ID filters

### Frontend tests

- No frontend tests required for the initial implementation — the frontend components are primarily presentational

## Out of Scope

- Real-time streaming / live updates of AI traffic (current design is snapshot-based fetch)
- Token usage display in the card title bar (explicitly excluded per design discussion)
- WebSocket traffic monitoring
- Request/response body search or full-text filtering
- Diffing between consecutive AI calls (the existing prompt diff feature in the process tree covers this)
- Non-HTTP AI communication protocols (gRPC, etc.)
- Editing or replaying captured AI requests

## Further Notes

- The `events_http.data_json` field already contains the complete HTTP body (request and response), so no schema changes are needed
- The `events_sse.data_json` field contains `text_content` (pre-concatenated AI response text) and `sse_events` (individual SSE events), both useful for the structured summary
- The AI host whitelist should be easy to extend — consider making it configurable in a future iteration
- `http_tid` field in `events_http` and `sse_connection_id` (format `pid:tid:window`) in `events_sse` are the key fields for request-response pairing
