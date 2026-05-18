'use client';

import { useState, useEffect } from 'react';
import { useTranslation } from '@/i18n';
import { AITrafficCard } from './AITrafficCard';

const GO_BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:7395';

interface AIPair {
  index: number;
  request: Record<string, unknown>;
  response: Record<string, unknown> | null;
  duration_ms: number | null;
}

interface AITrafficViewProps {
  pid: number;
  onBack?: () => void;
}

export function AITrafficView({ pid, onBack }: AITrafficViewProps) {
  const { t } = useTranslation();
  const [pairs, setPairs] = useState<AIPair[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const [showAll, setShowAll] = useState(false);

  useEffect(() => {
    let cancelled = false;

    async function fetchAITraffic() {
      setLoading(true);
      setError('');

      const qs = showAll ? '?all=true' : '';
      const apiPath = `/api/analytics/process/${pid}/ai-traffic${qs}`;
      try {
        let response: Response;
        try {
          response = await fetch(apiPath);
        } catch {
          response = await fetch(`${GO_BACKEND_URL}${apiPath}`);
        }

        if (!response.ok) {
          throw new Error(`${response.status} ${response.statusText}`);
        }

        const json = await response.json();
        if (!cancelled) {
          setPairs(json.data || []);
        }
      } catch (err) {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : String(err));
        }
      } finally {
        if (!cancelled) {
          setLoading(false);
        }
      }
    }

    fetchAITraffic();
    return () => { cancelled = true; };
  }, [pid, showAll]);

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="bg-white rounded-lg shadow-md p-4 flex items-center justify-between flex-wrap gap-3">
        <div>
          <h2 className="text-lg font-semibold text-gray-900">{t('aiTraffic.title')}</h2>
          <p className="text-sm text-gray-500">{t('aiTraffic.pid', { pid: String(pid) })}</p>
        </div>
        <div className="flex items-center gap-3">
          {/* Filter toggle */}
          <div className="flex items-center rounded-lg border border-gray-200 p-1">
            <button
              onClick={() => setShowAll(false)}
              className={`px-3 py-1 text-sm rounded-md transition-colors ${
                !showAll
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              {t('aiTraffic.aiOnly')}
            </button>
            <button
              onClick={() => setShowAll(true)}
              className={`px-3 py-1 text-sm rounded-md transition-colors ${
                showAll
                  ? 'bg-blue-600 text-white'
                  : 'text-gray-600 hover:bg-gray-100'
              }`}
            >
              {t('aiTraffic.allHTTP')}
            </button>
          </div>
          {onBack && (
            <button
              onClick={onBack}
              className="px-3 py-1.5 text-sm text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-md transition-colors border border-gray-300"
            >
              {t('aiTraffic.backToProcessTree')}
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <div className="bg-white rounded-lg shadow-md p-12 text-center">
          <div className="flex flex-col items-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600 mb-3"></div>
            <p className="text-gray-500">{t('aiTraffic.loading')}</p>
          </div>
        </div>
      ) : error ? (
        <div className="bg-white rounded-lg shadow-md p-12 text-center">
          <p className="text-red-600">{t('aiTraffic.error')}: {error}</p>
        </div>
      ) : pairs.length === 0 ? (
        <div className="bg-white rounded-lg shadow-md p-12 text-center">
          <p className="text-gray-500 mb-4">
            {showAll ? t('aiTraffic.emptyAll') : t('aiTraffic.empty')}
          </p>
          {!showAll && (
            <button
              onClick={() => setShowAll(true)}
              className="px-4 py-2 text-sm text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded-md transition-colors border border-blue-300"
            >
              {t('aiTraffic.showAll')}
            </button>
          )}
        </div>
      ) : (
        <div className="space-y-2">
          {pairs.map((pair) => (
            <AITrafficCard key={pair.index} pair={pair} index={pair.index} />
          ))}
        </div>
      )}
    </div>
  );
}
