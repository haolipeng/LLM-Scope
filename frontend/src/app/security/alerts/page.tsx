// SPDX-License-Identifier: MIT
'use client';

import { Suspense, useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { useSearchParams } from 'next/navigation';
import { useTranslation } from '@/i18n';
import { LanguageSwitcher } from '@/components/common/LanguageSwitcher';

const GO_BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:7395';

export type SecurityAlertRow = {
  id?: string | number;
  session_id?: string;
  event_time?: string;
  pid?: number;
  comm?: string;
  alert_type?: string;
  risk_level?: string;
  description?: string;
  source_table?: string;
  source_event_id?: string | number | null;
  evidence_json?: unknown;
  data_json?: unknown;
};

async function fetchAlertsApi(path: string): Promise<Response> {
  try {
    return await fetch(path);
  } catch {
    return fetch(`${GO_BACKEND_URL}${path}`);
  }
}

function riskBadgeClass(level: string | undefined): string {
  switch ((level || '').toLowerCase()) {
    case 'critical':
      return 'bg-red-900 text-white';
    case 'high':
      return 'bg-red-100 text-red-900';
    case 'medium':
      return 'bg-amber-100 text-amber-900';
    case 'low':
      return 'bg-slate-100 text-slate-800';
    default:
      return 'bg-gray-100 text-gray-800';
  }
}

function parseEvidence(raw: unknown): Array<Record<string, unknown>> {
  if (raw == null) return [];
  if (typeof raw === 'string') {
    try {
      const v = JSON.parse(raw);
      return Array.isArray(v) ? v : [];
    } catch {
      return [];
    }
  }
  if (Array.isArray(raw)) return raw as Array<Record<string, unknown>>;
  return [];
}

function formatJSON(raw: unknown): string {
  if (raw == null) return '';
  if (typeof raw === 'string') {
    try {
      return JSON.stringify(JSON.parse(raw), null, 2);
    } catch {
      return raw;
    }
  }
  try {
    return JSON.stringify(raw, null, 2);
  } catch {
    return String(raw);
  }
}

function AlertsContent() {
  const { t } = useTranslation();
  const searchParams = useSearchParams();
  const idParam = searchParams.get('id');

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [list, setList] = useState<SecurityAlertRow[]>([]);
  const [detail, setDetail] = useState<SecurityAlertRow | null>(null);

  const loadList = useCallback(async () => {
    setLoading(true);
    setError('');
    try {
      const res = await fetchAlertsApi('/api/analytics/security/alerts?limit=500');
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const json = await res.json();
      setList((json.data as SecurityAlertRow[]) || []);
      setDetail(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'fetch failed');
    } finally {
      setLoading(false);
    }
  }, []);

  const loadDetail = useCallback(async (id: string) => {
    setLoading(true);
    setError('');
    try {
      const res = await fetchAlertsApi(`/api/analytics/security/alerts?id=${encodeURIComponent(id)}`);
      if (res.status === 404) {
        setError(t('security.alertNotFound'));
        setDetail(null);
        return;
      }
      if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
      const json = await res.json();
      setDetail(json.data as SecurityAlertRow);
      setList([]);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'fetch failed');
      setDetail(null);
    } finally {
      setLoading(false);
    }
  }, [t]);

  useEffect(() => {
    if (idParam) {
      loadDetail(idParam);
    } else {
      loadList();
    }
  }, [idParam, loadList, loadDetail]);

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        <div className="flex justify-between items-start mb-6">
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{t('security.title')}</h1>
            <p className="text-gray-600 text-sm mt-1">{t('security.subtitle')}</p>
          </div>
          <div className="flex items-center gap-4">
            <Link href="/" className="text-sm text-blue-600 hover:underline">
              {t('security.backHome')}
            </Link>
            <LanguageSwitcher />
          </div>
        </div>

        {loading && (
          <div className="text-sm text-gray-600">{t('security.loading')}</div>
        )}
        {error && (
          <div className="rounded-md bg-red-50 text-red-800 px-4 py-2 text-sm mb-4">{error}</div>
        )}

        {!loading && !idParam && (
          <div className="bg-white rounded-lg shadow overflow-hidden">
            <table className="min-w-full divide-y divide-gray-200 text-sm">
              <thead className="bg-gray-50">
                <tr>
                  <th className="px-4 py-2 text-left font-medium text-gray-700">{t('security.colId')}</th>
                  <th className="px-4 py-2 text-left font-medium text-gray-700">{t('security.colTime')}</th>
                  <th className="px-4 py-2 text-left font-medium text-gray-700">{t('security.colType')}</th>
                  <th className="px-4 py-2 text-left font-medium text-gray-700">{t('security.colRisk')}</th>
                  <th className="px-4 py-2 text-left font-medium text-gray-700">{t('security.colSession')}</th>
                  <th className="px-4 py-2 text-left font-medium text-gray-700">{t('security.colDesc')}</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {list.length === 0 && !error && (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center">
                      <p className="text-gray-600">{t('security.empty')}</p>
                      <p className="mt-3 text-sm text-gray-500 max-w-2xl mx-auto leading-relaxed whitespace-pre-line">
                        {t('security.emptyHint')}
                      </p>
                    </td>
                  </tr>
                )}
                {list.map((row) => (
                  <tr key={String(row.id)} className="hover:bg-gray-50">
                    <td className="px-4 py-2 font-mono text-xs">
                      <Link
                        href={`/security/alerts/?id=${row.id}`}
                        className="text-blue-600 hover:underline"
                      >
                        {row.id ?? '—'}
                      </Link>
                    </td>
                    <td className="px-4 py-2 whitespace-nowrap text-gray-700">
                      {row.event_time ? String(row.event_time).replace('T', ' ').slice(0, 19) : '—'}
                    </td>
                    <td className="px-4 py-2">{row.alert_type ?? '—'}</td>
                    <td className="px-4 py-2">
                      <span className={`inline-block px-2 py-0.5 rounded text-xs ${riskBadgeClass(row.risk_level)}`}>
                        {row.risk_level ?? '—'}
                      </span>
                    </td>
                    <td className="px-4 py-2 font-mono text-xs truncate max-w-[120px]" title={row.session_id}>
                      {row.session_id ? (
                        <Link
                          href={`/?session_id=${encodeURIComponent(String(row.session_id))}`}
                          className="text-blue-600 hover:underline"
                        >
                          {row.session_id}
                        </Link>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td className="px-4 py-2 text-gray-700 max-w-md truncate" title={row.description}>
                      {row.description ?? '—'}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {!loading && idParam && detail && (
          <div className="space-y-6">
            <div className="flex items-center gap-3">
              <Link href="/security/alerts/" className="text-sm text-blue-600 hover:underline">
                {t('security.backList')}
              </Link>
            </div>

            <div className="bg-white rounded-lg shadow p-6 space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-lg font-semibold">{detail.alert_type ?? '—'}</span>
                <span className={`inline-block px-2 py-0.5 rounded text-xs ${riskBadgeClass(detail.risk_level)}`}>
                  {detail.risk_level ?? '—'}
                </span>
                <span className="text-gray-500 text-sm font-mono">id={detail.id}</span>
              </div>
              <p className="text-gray-800">{detail.description ?? '—'}</p>

              <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
                <div>
                  <dt className="text-gray-500">{t('security.session')}</dt>
                  <dd className="font-mono break-all flex flex-wrap items-center gap-2">
                    {detail.session_id ?? '—'}
                    {detail.session_id && (
                      <Link
                        href={`/?session_id=${encodeURIComponent(String(detail.session_id))}`}
                        className="text-sm text-blue-600 hover:underline shrink-0"
                      >
                        {t('security.openTimeline')}
                      </Link>
                    )}
                  </dd>
                </div>
                <div>
                  <dt className="text-gray-500">{t('security.eventTime')}</dt>
                  <dd>{detail.event_time ? String(detail.event_time) : '—'}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">{t('security.process')}</dt>
                  <dd>
                    {detail.comm ?? '—'} (pid {detail.pid ?? '—'})
                  </dd>
                </div>
                <div>
                  <dt className="text-gray-500">{t('security.sourceTable')}</dt>
                  <dd className="font-mono">{detail.source_table ?? '—'}</dd>
                </div>
                <div>
                  <dt className="text-gray-500">{t('security.sourceEventId')}</dt>
                  <dd className="font-mono">{detail.source_event_id != null ? String(detail.source_event_id) : '—'}</dd>
                </div>
              </dl>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-md font-semibold text-gray-900 mb-3">{t('security.evidence')}</h2>
              <div className="overflow-x-auto">
                <table className="min-w-full text-sm border border-gray-200">
                  <thead className="bg-gray-50">
                    <tr>
                      <th className="px-2 py-1 text-left border-b">{t('security.evSource')}</th>
                      <th className="px-2 py-1 text-left border-b">{t('security.evType')}</th>
                      <th className="px-2 py-1 text-left border-b">PID</th>
                      <th className="px-2 py-1 text-left border-b">{t('security.evComm')}</th>
                      <th className="px-2 py-1 text-left border-b">{t('security.evTs')}</th>
                      <th className="px-2 py-1 text-left border-b">{t('security.evDetail')}</th>
                    </tr>
                  </thead>
                  <tbody>
                    {parseEvidence(detail.evidence_json).map((ev, i) => (
                      <tr key={i} className="border-t">
                        <td className="px-2 py-1 font-mono text-xs">{String(ev.source_table ?? '')}</td>
                        <td className="px-2 py-1">{String(ev.event_type ?? '')}</td>
                        <td className="px-2 py-1">{String(ev.pid ?? '')}</td>
                        <td className="px-2 py-1">{String(ev.comm ?? '')}</td>
                        <td className="px-2 py-1 font-mono text-xs">{String(ev.timestamp_ns ?? '')}</td>
                        <td className="px-2 py-1 break-all">{String(ev.detail ?? '')}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {parseEvidence(detail.evidence_json).length === 0 && (
                  <p className="text-gray-500 text-sm">{t('security.noEvidence')}</p>
                )}
              </div>
            </div>

            <div className="bg-white rounded-lg shadow p-6">
              <h2 className="text-md font-semibold text-gray-900 mb-3">{t('security.rawPayload')}</h2>
              <pre className="text-xs bg-gray-900 text-green-100 p-4 rounded overflow-x-auto max-h-96 overflow-y-auto">
                {formatJSON(detail.data_json)}
              </pre>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function SecurityAlertsPage() {
  return (
    <Suspense fallback={<div className="p-8 text-gray-600">Loading…</div>}>
      <AlertsContent />
    </Suspense>
  );
}
