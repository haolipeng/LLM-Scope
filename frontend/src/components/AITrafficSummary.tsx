'use client';

import { useState } from 'react';
import { ChevronDownIcon, ChevronRightIcon } from '@heroicons/react/24/outline';
import { useTranslation } from '@/i18n';

interface AIPair {
  index: number;
  request: Record<string, unknown>;
  response: Record<string, unknown> | null;
  duration_ms: number | null;
}

// --- Data extraction helpers ---

function parseDataJSON(row: Record<string, unknown>): Record<string, unknown> {
  let dataJson = row.data_json;
  if (typeof dataJson === 'string') {
    try { dataJson = JSON.parse(dataJson); } catch { return {}; }
  }
  return (dataJson && typeof dataJson === 'object') ? dataJson as Record<string, unknown> : {};
}

function parseBody(data: Record<string, unknown>): Record<string, unknown> {
  const body = data.body;
  if (!body) return {};
  if (typeof body === 'string') {
    try { return JSON.parse(body); } catch { return {}; }
  }
  return (typeof body === 'object') ? body as Record<string, unknown> : {};
}

// --- Collapsible section ---

function CollapsibleSection({ title, defaultOpen = false, children }: {
  title: string;
  defaultOpen?: boolean;
  children: React.ReactNode;
}) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-gray-200 rounded-md overflow-hidden">
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-2 px-3 py-2 text-sm font-medium text-gray-700 bg-gray-50 hover:bg-gray-100 transition-colors text-left"
      >
        {open
          ? <ChevronDownIcon className="h-4 w-4 text-gray-400 shrink-0" />
          : <ChevronRightIcon className="h-4 w-4 text-gray-400 shrink-0" />
        }
        {title}
      </button>
      {open && (
        <div className="px-3 py-2 border-t border-gray-200">
          {children}
        </div>
      )}
    </div>
  );
}

// --- Role badge ---

const roleColors: Record<string, string> = {
  user: 'bg-blue-100 text-blue-800',
  assistant: 'bg-green-100 text-green-800',
  system: 'bg-purple-100 text-purple-800',
  tool: 'bg-orange-100 text-orange-800',
};

function RoleBadge({ role }: { role: string }) {
  const color = roleColors[role] || 'bg-gray-100 text-gray-800';
  return (
    <span className={`inline-block px-2 py-0.5 text-xs font-semibold rounded ${color}`}>
      {role}
    </span>
  );
}

// --- Message content extraction ---

function extractMessageText(msg: Record<string, unknown>): string {
  const content = msg.content;
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .map((block: unknown) => {
        if (typeof block === 'string') return block;
        if (block && typeof block === 'object') {
          const b = block as Record<string, unknown>;
          if (b.type === 'text' && typeof b.text === 'string') return b.text;
          if (b.type === 'tool_use') return `[tool_use: ${b.name || 'unknown'}]`;
          if (b.type === 'tool_result') return `[tool_result: ${typeof b.content === 'string' ? b.content.slice(0, 100) : '...'}]`;
          if (b.type === 'thinking' && typeof b.thinking === 'string') return `[thinking]`;
        }
        return '';
      })
      .filter(Boolean)
      .join('\n');
  }
  return '';
}

// --- Request Summary ---

function RequestSummary({ data }: { data: Record<string, unknown> }) {
  const { t } = useTranslation();
  const body = parseBody(data);

  const model = (body.model as string) || '';
  const maxTokens = body.max_tokens;
  const temperature = body.temperature;
  const system = body.system;
  const messages = Array.isArray(body.messages) ? body.messages as Record<string, unknown>[] : [];

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold text-gray-800">{t('aiTraffic.request')}</h4>

      {/* Overview line */}
      <div className="flex items-center gap-3 flex-wrap text-sm">
        {model && (
          <span className="bg-purple-100 text-purple-700 px-2 py-0.5 rounded font-medium">
            {model}
          </span>
        )}
        {maxTokens != null && (
          <span className="text-gray-500">
            {t('aiTraffic.maxTokens')}: <span className="font-mono">{String(maxTokens)}</span>
          </span>
        )}
        {temperature != null && (
          <span className="text-gray-500">
            {t('aiTraffic.temperature')}: <span className="font-mono">{String(temperature)}</span>
          </span>
        )}
      </div>

      {/* System prompt */}
      {system && (
        <CollapsibleSection title={t('aiTraffic.systemPrompt')}>
          <pre className="text-xs font-mono whitespace-pre-wrap break-words text-gray-700 max-h-60 overflow-auto">
            {typeof system === 'string' ? system : JSON.stringify(system, null, 2)}
          </pre>
        </CollapsibleSection>
      )}

      {/* Messages list */}
      {messages.length > 0 && (
        <div className="space-y-2">
          <h5 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">
            {t('aiTraffic.messages')} ({messages.length})
          </h5>
          <div className="space-y-1.5">
            {messages.map((msg, i) => {
              const role = (msg.role as string) || 'unknown';
              const text = extractMessageText(msg);
              return (
                <div key={i} className="flex gap-2 items-start">
                  <RoleBadge role={role} />
                  <pre className="text-xs font-mono whitespace-pre-wrap break-words text-gray-700 flex-1 max-h-40 overflow-auto">
                    {text || t('aiTraffic.noContent')}
                  </pre>
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// --- Response Summary ---

function ResponseSummary({ data, isSSE }: { data: Record<string, unknown>; isSSE: boolean }) {
  const { t } = useTranslation();

  // SSE response: text_content, sse_events
  // HTTP response: body (JSON string)

  let textContent = '';
  let toolUses: { name: string; input: unknown }[] = [];
  let thinkingContent = '';

  if (isSSE) {
    textContent = (data.text_content as string) || '';
    const sseEvents = Array.isArray(data.sse_events) ? data.sse_events : [];

    for (const ev of sseEvents) {
      const event = ev as Record<string, unknown>;
      const parsed = (event.parsed_data || event.data) as Record<string, unknown> | undefined;
      if (!parsed || typeof parsed !== 'object') continue;

      // Extract tool_use from content_block_start
      if (event.event === 'content_block_start') {
        const contentBlock = parsed.content_block as Record<string, unknown> | undefined;
        if (contentBlock?.type === 'tool_use') {
          toolUses.push({
            name: (contentBlock.name as string) || 'unknown',
            input: contentBlock.input || {},
          });
        }
      }

      // Accumulate tool_use input from content_block_delta
      if (event.event === 'content_block_delta') {
        const delta = parsed.delta as Record<string, unknown> | undefined;
        if (delta?.type === 'input_json_delta' && typeof delta.partial_json === 'string') {
          const last = toolUses[toolUses.length - 1];
          if (last && typeof last.input === 'string') {
            last.input = last.input + delta.partial_json;
          } else if (last) {
            last.input = delta.partial_json;
          }
        }
      }

      // Extract thinking
      if (event.event === 'content_block_delta') {
        const delta = parsed.delta as Record<string, unknown> | undefined;
        if (delta?.type === 'thinking_delta' && typeof delta.thinking === 'string') {
          thinkingContent += delta.thinking;
        }
      }
    }
  } else {
    // HTTP response body
    const body = parseBody(data);
    const content = body.content;
    if (Array.isArray(content)) {
      for (const block of content) {
        const b = block as Record<string, unknown>;
        if (b.type === 'text' && typeof b.text === 'string') {
          textContent += (textContent ? '\n' : '') + b.text;
        }
        if (b.type === 'tool_use') {
          toolUses.push({
            name: (b.name as string) || 'unknown',
            input: b.input || {},
          });
        }
        if (b.type === 'thinking' && typeof b.thinking === 'string') {
          thinkingContent += b.thinking;
        }
      }
    } else if (typeof body.text === 'string') {
      textContent = body.text;
    }
  }

  const hasContent = textContent || toolUses.length > 0 || thinkingContent;

  return (
    <div className="space-y-3">
      <h4 className="text-sm font-semibold text-gray-800">{t('aiTraffic.response')}</h4>

      {!hasContent && (
        <p className="text-xs text-gray-400 italic">{t('aiTraffic.noContent')}</p>
      )}

      {/* Thinking */}
      {thinkingContent && (
        <CollapsibleSection title={t('aiTraffic.thinking')}>
          <pre className="text-xs font-mono whitespace-pre-wrap break-words text-gray-600 max-h-60 overflow-auto">
            {thinkingContent}
          </pre>
        </CollapsibleSection>
      )}

      {/* AI reply text */}
      {textContent && (
        <div>
          <h5 className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1">
            {t('aiTraffic.aiReply')}
          </h5>
          <pre className="text-xs font-mono whitespace-pre-wrap break-words text-gray-700 max-h-80 overflow-auto bg-white border border-gray-200 rounded p-3">
            {textContent}
          </pre>
        </div>
      )}

      {/* Tool use */}
      {toolUses.length > 0 && (
        <div>
          <h5 className="text-xs font-semibold text-gray-600 uppercase tracking-wide mb-1">
            {t('aiTraffic.toolUse')} ({toolUses.length})
          </h5>
          <div className="space-y-2">
            {toolUses.map((tool, i) => (
              <div key={i} className="border border-orange-200 rounded-md bg-orange-50/30 p-2">
                <span className="text-xs font-semibold text-orange-800 bg-orange-100 px-2 py-0.5 rounded">
                  {tool.name}
                </span>
                <pre className="text-xs font-mono whitespace-pre-wrap break-words text-gray-600 mt-1 max-h-40 overflow-auto">
                  {typeof tool.input === 'string' ? tool.input : JSON.stringify(tool.input, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// --- Main component ---

export function AITrafficSummary({ pair }: { pair: AIPair }) {
  const { t } = useTranslation();

  const requestData = parseDataJSON(pair.request);
  const responseData = pair.response ? parseDataJSON(pair.response) : null;

  // Detect if response is SSE (has sse_connection_id or text_content)
  const isSSE = pair.response
    ? ('sse_connection_id' in pair.response || 'text_content' in (responseData || {}))
    : false;

  return (
    <div className="space-y-4">
      {/* Request side */}
      <RequestSummary data={requestData} />

      {/* Divider */}
      {responseData && <hr className="border-gray-200" />}

      {/* Response side */}
      {responseData ? (
        <ResponseSummary data={responseData} isSSE={isSSE} />
      ) : (
        <p className="text-sm text-gray-400 italic">{t('aiTraffic.noResponse')}</p>
      )}
    </div>
  );
}
