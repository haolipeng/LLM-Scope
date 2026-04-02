// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

'use client';

import { useState, useEffect } from 'react';
import { LogView } from '@/components/LogView';
import { TimelineView } from '@/components/TimelineView';
import { ProcessTreeView } from '@/components/ProcessTreeView';
import { ResourceMetricsView } from '@/components/ResourceMetricsView';
import { UploadPanel } from '@/components/UploadPanel';
import { LanguageSwitcher } from '@/components/common/LanguageSwitcher';
import { Event } from '@/types/event';
import { adaptGoEvent, isGoEventFormat } from '@/utils/eventAdapter';
import { useTranslation } from '@/i18n';

type ViewMode = 'log' | 'timeline' | 'process-tree' | 'metrics';

// Go backend URL for direct SSE connection (bypasses Next.js proxy which may buffer SSE)
const GO_BACKEND_URL = process.env.NEXT_PUBLIC_BACKEND_URL || 'http://localhost:7395';

export default function Home() {
  const { t } = useTranslation();
  const [file, setFile] = useState<File | null>(null);
  const [logContent, setLogContent] = useState<string>('');
  const [events, setEvents] = useState<Event[]>([]);
  const [viewMode, setViewMode] = useState<ViewMode>('process-tree');
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [error, setError] = useState<string>('');
  const [isParsed, setIsParsed] = useState(false);
  const [showUploadPanel, setShowUploadPanel] = useState(false);

  const parseLogContent = (content: string) => {
    if (!content.trim()) {
      setError('Empty log content');
      return;
    }

    setLoading(true);
    setError('');

    try {
      const lines = content.split('\n').filter(line => line.trim());
      const parsedEvents: Event[] = [];
      const errors: string[] = [];

      lines.forEach((line, index) => {
        try {
          const raw = JSON.parse(line.trim());

          // Detect Go event format and adapt
          let event: Event;
          if (isGoEventFormat(raw)) {
            event = adaptGoEvent(raw, index);
          } else {
            event = raw as Event;
          }

          // Validate event structure - auto-generate id if missing
          if (event.timestamp && event.source && event.data) {
            if (!event.id) {
              event.id = `${event.source}-${event.timestamp}-${index}`;
            }
            parsedEvents.push(event);
          } else {
            // Track validation errors
            const missing = [];
            if (!event.timestamp) missing.push('timestamp');
            if (!event.source) missing.push('source');
            if (!event.data) missing.push('data');
            errors.push(`Line ${index + 1}: Missing required fields: ${missing.join(', ')}`);
          }
        } catch (err) {
          errors.push(`Line ${index + 1}: Invalid JSON - ${err instanceof Error ? err.message : 'Unknown error'}`);
        }
      });

      if (parsedEvents.length === 0) {
        const errorMsg = errors.length > 0
          ? `No valid events found. Errors:\n${errors.slice(0, 10).join('\n')}${errors.length > 10 ? '\n...and ' + (errors.length - 10) + ' more errors' : ''}`
          : 'No valid events found in the log file';
        setError(errorMsg);
        return;
      }

      // Show warnings for partial parsing
      if (errors.length > 0) {
        console.warn(`Parsed ${parsedEvents.length} events with ${errors.length} errors:`, errors);
      }

      // Sort events by timestamp
      const sortedEvents = parsedEvents.sort((a, b) => a.timestamp - b.timestamp);

      setEvents(sortedEvents);
      setIsParsed(true);
      setShowUploadPanel(false); // Hide upload panel after successful parse

      // Save to localStorage
      localStorage.setItem('agent-tracer-log', content);
      localStorage.setItem('agent-tracer-events', JSON.stringify(sortedEvents));

    } catch (err) {
      setError(`Failed to parse log content: ${err instanceof Error ? err.message : 'Unknown error'}`);
    } finally {
      setLoading(false);
    }
  };

  const syncData = async () => {
    setSyncing(true);
    setError('');

    try {
      let response: Response;
      try {
        response = await fetch('/api/analytics/timeline?limit=10000');
      } catch {
        response = await fetch(`${GO_BACKEND_URL}/api/analytics/timeline?limit=10000`);
      }

      if (!response.ok) {
        throw new Error(`Failed to fetch data: ${response.status} ${response.statusText}`);
      }

      const json = await response.json();
      const rows: any[] = json.data || [];

      if (rows.length === 0) {
        setError('No events captured yet. Make sure the Go backend is running with DuckDB enabled and there is activity to monitor.');
        return;
      }

      const parsedEvents: Event[] = rows.map((row, index) => {
        const timestamp = row.event_time
          ? new Date(row.event_time).getTime()
          : Date.now();

        let data = row.data_json;
        if (typeof data === 'string') {
          try { data = JSON.parse(data); } catch { /* keep as string */ }
        }
        if (!data || typeof data !== 'object') {
          data = { ...row };
        }

        return {
          id: row.id ? String(row.id) : `${row.source}-${timestamp}-${index}`,
          timestamp,
          source: row.source || 'unknown',
          pid: row.pid || 0,
          comm: row.comm || '',
          data,
        };
      });

      const sortedEvents = parsedEvents.sort((a, b) => a.timestamp - b.timestamp);
      setEvents(sortedEvents);
      setIsParsed(true);
      setShowUploadPanel(false);

      localStorage.setItem('agent-tracer-events', JSON.stringify(sortedEvents));

    } catch (err) {
      setError(`Failed to sync data: ${err instanceof Error ? err.message : 'Unknown error'}. Is the Go backend running on port 7395?`);
    } finally {
      setSyncing(false);
    }
  };

  // Load data from localStorage on component mount
  useEffect(() => {
    const savedContent = localStorage.getItem('agent-tracer-log');
    const savedEvents = localStorage.getItem('agent-tracer-events');

    if (savedContent && savedEvents) {
      setLogContent(savedContent);
      setEvents(JSON.parse(savedEvents));
      setIsParsed(true);
    }
    // Auto-sync disabled - user must manually sync data
  }, []);

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const uploadedFile = event.target.files?.[0];
    if (uploadedFile) {
      setFile(uploadedFile);
      setError('');
      setIsParsed(false);

      const reader = new FileReader();
      reader.onload = (e) => {
        const content = e.target?.result as string;
        setLogContent(content);
      };
      reader.readAsText(uploadedFile);
    }
  };

  const handleTextPaste = (content: string) => {
    setLogContent(content);
    setIsParsed(false);
    setError('');
  };

  const clearData = () => {
    setFile(null);
    setLogContent('');
    setEvents([]);
    setError('');
    setIsParsed(false);
    localStorage.removeItem('agent-tracer-log');
    localStorage.removeItem('agent-tracer-events');
  };

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* Header */}
        <div className="text-center mb-8 relative">
          <div className="absolute right-0 top-0">
            <LanguageSwitcher />
          </div>
          <h1 className="text-3xl font-bold text-gray-900 mb-2">
            {t('app.title')}
          </h1>
          <p className="text-gray-600">
            {t('app.subtitle')}
          </p>
        </div>

        {/* Upload Panel */}
        {showUploadPanel && (
          <UploadPanel
            logContent={logContent}
            loading={loading}
            error={error}
            onFileUpload={handleFileUpload}
            onTextPaste={handleTextPaste}
            onParseLog={() => parseLogContent(logContent)}
          />
        )}

        {/* Main Content - Always show */}
        <div className="space-y-6">
          {/* Controls */}
          <div className="bg-white rounded-lg shadow-md p-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="text-sm text-gray-600">
                  {t('app.eventsLoaded', { count: events.length })}
                </div>

                {file && (
                  <div className="text-sm text-gray-600">
                    {t('app.file')} <span className="font-medium">{file.name}</span>
                  </div>
                )}

                {syncing && (
                  <div className="flex items-center text-sm text-blue-600">
                    <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600 mr-2"></div>
                    {t('app.syncing')}
                  </div>
                )}

              </div>

              <div className="flex items-center space-x-4">
                {/* View Mode Toggle */}
                <div className="flex rounded-lg border border-gray-200 p-1">
                  <button
                    onClick={() => setViewMode('log')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'log'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.logView')}
                  </button>
                  <button
                    onClick={() => setViewMode('timeline')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'timeline'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.timelineView')}
                  </button>
                  <button
                    onClick={() => setViewMode('process-tree')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'process-tree'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.processTree')}
                  </button>
                  <button
                    onClick={() => setViewMode('metrics')}
                    className={`px-3 py-1 text-sm rounded-md transition-colors ${
                      viewMode === 'metrics'
                        ? 'bg-blue-600 text-white'
                        : 'text-gray-600 hover:bg-gray-100'
                    }`}
                  >
                    {t('app.metrics')}
                  </button>
                </div>

                {/* Action Buttons */}
                <button
                  onClick={() => setShowUploadPanel(!showUploadPanel)}
                  className="px-4 py-2 text-sm text-gray-600 hover:text-gray-800 hover:bg-gray-100 rounded-md transition-colors border border-gray-300"
                >
                  {showUploadPanel ? t('app.hideLog') : t('app.uploadLog')}
                </button>

                <button
                  onClick={syncData}
                  disabled={syncing}
                  className="px-4 py-2 text-sm text-blue-600 hover:text-blue-700 hover:bg-blue-50 rounded-md transition-colors border border-blue-300 disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {t('app.syncData')}
                </button>

                <button
                  onClick={clearData}
                  className="px-4 py-2 text-sm text-red-600 hover:text-red-700 hover:bg-red-50 rounded-md transition-colors"
                >
                  {t('app.clearData')}
                </button>
              </div>
            </div>
          </div>

          {/* View Content */}
          {events.length > 0 ? (
            viewMode === 'log' ? (
              <LogView events={events} />
            ) : viewMode === 'timeline' ? (
              <TimelineView events={events} />
            ) : viewMode === 'metrics' ? (
              <ResourceMetricsView events={events} />
            ) : (
              <ProcessTreeView events={events} />
            )
          ) : (
            <div className="bg-white rounded-lg shadow-md p-12 text-center">
              <div className="text-gray-500">
                {syncing ? (
                  <div className="flex flex-col items-center">
                    <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600 mb-4"></div>
                    <p className="text-lg">{t('app.loadingEvents')}</p>
                  </div>
                ) : (
                  <>
                    <p className="text-lg mb-4">{t('app.noEventsLoaded')}</p>
                    <div className="space-x-4">
                      <button
                        onClick={syncData}
                        className="px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 transition-colors"
                      >
                        {t('app.syncFromServer')}
                      </button>
                      <button
                        onClick={() => setShowUploadPanel(true)}
                        className="px-6 py-3 bg-gray-600 text-white font-semibold rounded-lg hover:bg-gray-700 transition-colors"
                      >
                        {t('app.uploadLogFile')}
                      </button>
                    </div>
                  </>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
