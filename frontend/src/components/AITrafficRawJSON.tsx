'use client';

import { useTranslation } from '@/i18n';

interface AIPair {
  index: number;
  request: Record<string, unknown>;
  response: Record<string, unknown> | null;
  duration_ms: number | null;
}

/** Parse data_json from a row, handling string or object. */
function parseDataJSON(row: Record<string, unknown>): Record<string, unknown> {
  let dataJson = row.data_json;
  if (typeof dataJson === 'string') {
    try { dataJson = JSON.parse(dataJson); } catch { return {}; }
  }
  return (dataJson && typeof dataJson === 'object') ? dataJson as Record<string, unknown> : {};
}

/** Try to parse a string as JSON for pretty-printing; return the object if successful, original string if not. */
function tryParseJSON(value: unknown): unknown {
  if (typeof value === 'string') {
    try { return JSON.parse(value); } catch { return value; }
  }
  return value;
}

/** Format a value as indented JSON string. */
function formatJSON(value: unknown): string {
  if (value === undefined || value === null) return 'null';
  if (typeof value === 'string') {
    // Try to parse as JSON for pretty display
    try {
      const parsed = JSON.parse(value);
      return JSON.stringify(parsed, null, 2);
    } catch {
      return value;
    }
  }
  return JSON.stringify(value, null, 2);
}

function JSONSection({ label, value }: { label: string; value: unknown }) {
  const formatted = formatJSON(value);
  if (!value && value !== 0) return null;

  return (
    <div className="space-y-1">
      <h5 className="text-xs font-semibold text-gray-600 uppercase tracking-wide">{label}</h5>
      <pre className="text-xs font-mono whitespace-pre-wrap break-all overflow-auto max-h-80 bg-white border border-gray-200 rounded p-3 text-gray-700">
        {formatted}
      </pre>
    </div>
  );
}

export function AITrafficRawJSON({ pair }: { pair: AIPair }) {
  const { t } = useTranslation();

  const reqData = parseDataJSON(pair.request);
  const headers = reqData.headers;
  const body = tryParseJSON(reqData.body);

  // Detect if response is SSE
  const respData = pair.response ? parseDataJSON(pair.response) : null;
  const isSSE = respData ? ('sse_events' in respData || 'text_content' in respData) : false;

  return (
    <div className="space-y-5">
      {/* Request side */}
      <div className="space-y-3">
        <h4 className="text-sm font-semibold text-gray-800">{t('aiTraffic.request')}</h4>
        <JSONSection label={t('aiTraffic.headers')} value={headers} />
        <JSONSection label={t('aiTraffic.body')} value={body} />
      </div>

      {/* Response side */}
      {respData && <hr className="border-gray-200" />}

      {respData ? (
        <div className="space-y-3">
          <h4 className="text-sm font-semibold text-gray-800">{t('aiTraffic.response')}</h4>
          {isSSE ? (
            <JSONSection label={t('aiTraffic.sseEvents')} value={respData.sse_events} />
          ) : (
            <>
              <JSONSection label={t('aiTraffic.headers')} value={respData.headers} />
              <JSONSection label={t('aiTraffic.body')} value={tryParseJSON(respData.body)} />
            </>
          )}
        </div>
      ) : (
        <p className="text-sm text-gray-400 italic">{t('aiTraffic.noResponse')}</p>
      )}
    </div>
  );
}
