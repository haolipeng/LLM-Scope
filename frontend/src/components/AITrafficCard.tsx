'use client';

import { useState } from 'react';
import { useTranslation } from '@/i18n';
import { AITrafficSummary } from './AITrafficSummary';
import { AITrafficRawJSON } from './AITrafficRawJSON';

interface AIPair {
  index: number;
  request: Record<string, unknown>;
  response: Record<string, unknown> | null;
  duration_ms: number | null;
}

function extractFromDataJSON(row: Record<string, unknown>, ...keys: string[]): unknown {
  let dataJson = row.data_json;
  if (typeof dataJson === 'string') {
    try { dataJson = JSON.parse(dataJson); } catch { return undefined; }
  }
  if (!dataJson || typeof dataJson !== 'object') return undefined;
  let current: unknown = dataJson;
  for (const key of keys) {
    if (!current || typeof current !== 'object') return undefined;
    current = (current as Record<string, unknown>)[key];
  }
  return current;
}

function formatDuration(ms: number | null): string {
  if (ms === null) return '-';
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function statusColor(code: unknown): string {
  const n = Number(code);
  if (!n || n === 0) return 'text-gray-400';
  if (n >= 200 && n < 300) return 'text-green-600';
  if (n >= 400 && n < 500) return 'text-yellow-600';
  if (n >= 500) return 'text-red-600';
  return 'text-gray-600';
}

type CardTab = 'summary' | 'raw';

export function AITrafficCard({ pair }: { pair: AIPair; index: number }) {
  const { t } = useTranslation();
  const [expanded, setExpanded] = useState(false);
  const [activeTab, setActiveTab] = useState<CardTab>('summary');

  const method = pair.request.http_method as string || 'GET';
  const path = pair.request.http_path as string || '/';
  const host = extractFromDataJSON(pair.request, 'headers', 'host') as string || '';
  const model = extractFromDataJSON(pair.request, 'body', 'model') as string || '';
  const statusCode = pair.response?.http_status_code;
  const duration = formatDuration(pair.duration_ms);

  return (
    <div className="bg-white rounded-lg shadow-sm border border-gray-200 overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full px-4 py-3 flex items-center justify-between text-left hover:bg-gray-50 transition-colors"
      >
        <div className="flex items-center gap-3 min-w-0 flex-1">
          <span className="text-gray-400 text-sm font-mono shrink-0">#{pair.index}</span>
          <span className="font-mono text-sm font-semibold text-blue-700 shrink-0">{method}</span>
          <span className="font-mono text-sm text-gray-700 truncate">{path}</span>
          {statusCode ? (
            <span className={`font-mono text-sm font-semibold shrink-0 ${statusColor(statusCode)}`}>
              {String(statusCode)}
            </span>
          ) : (
            <span className="text-sm text-gray-400 shrink-0">{t('aiTraffic.noResponse')}</span>
          )}
        </div>
        <div className="flex items-center gap-3 shrink-0 ml-4">
          {host && <span className="text-xs text-gray-500 hidden sm:inline">{host}</span>}
          {model && (
            <span className="text-xs bg-purple-100 text-purple-700 px-2 py-0.5 rounded hidden sm:inline">
              {model}
            </span>
          )}
          <span className="text-xs text-gray-500 font-mono">{duration}</span>
          <svg
            className={`w-4 h-4 text-gray-400 transition-transform ${expanded ? 'rotate-180' : ''}`}
            fill="none"
            viewBox="0 0 24 24"
            stroke="currentColor"
          >
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>

      {expanded && (
        <div className="border-t border-gray-200">
          {/* Tab bar */}
          <div className="flex border-b border-gray-200 bg-gray-50">
            <button
              onClick={() => setActiveTab('summary')}
              className={`px-4 py-2 text-sm font-medium transition-colors ${
                activeTab === 'summary'
                  ? 'text-blue-600 border-b-2 border-blue-600 bg-white'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              {t('aiTraffic.tabSummary')}
            </button>
            <button
              onClick={() => setActiveTab('raw')}
              className={`px-4 py-2 text-sm font-medium transition-colors ${
                activeTab === 'raw'
                  ? 'text-blue-600 border-b-2 border-blue-600 bg-white'
                  : 'text-gray-500 hover:text-gray-700'
              }`}
            >
              {t('aiTraffic.tabRawJSON')}
            </button>
          </div>

          {/* Tab content */}
          <div className="p-4 bg-gray-50">
            {activeTab === 'summary' ? (
              <AITrafficSummary pair={pair} />
            ) : (
              <AITrafficRawJSON pair={pair} />
            )}
          </div>
        </div>
      )}
    </div>
  );
}
