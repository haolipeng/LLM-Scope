// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

'use client';

import { useState } from 'react';
import { ChevronDownIcon, ChevronRightIcon, CpuChipIcon, DocumentIcon } from '@heroicons/react/24/outline';
import { ProcessNode as ProcessNodeType, ParsedEvent, TimelineItem } from '@/utils/eventParsers';
import { UnifiedBlock } from './UnifiedBlock';
import { adaptEventToUnifiedBlock } from './BlockAdapters';
import { useTranslation } from '@/i18n';

type GroupedTimelineItem =
  | { kind: 'single'; item: TimelineItem }
  | { kind: 'file_group'; events: ParsedEvent[] };

function groupTimeline(timeline: TimelineItem[]): GroupedTimelineItem[] {
  const result: GroupedTimelineItem[] = [];
  let fileRun: ParsedEvent[] = [];

  const flushFileRun = () => {
    if (fileRun.length === 0) return;
    if (fileRun.length <= 2) {
      fileRun.forEach(e => result.push({ kind: 'single', item: { type: 'event', timestamp: e.timestamp, event: e } }));
    } else {
      result.push({ kind: 'file_group', events: [...fileRun] });
    }
    fileRun = [];
  };

  for (const item of timeline) {
    if (item.type === 'event' && item.event?.type === 'file') {
      fileRun.push(item.event);
    } else {
      flushFileRun();
      result.push({ kind: 'single', item });
    }
  }
  flushFileRun();
  return result;
}

interface FileGroupProps {
  events: ParsedEvent[];
  expandedEvents: Set<string>;
  onToggleEvent: (eventId: string) => void;
}

function FileGroup({ events, expandedEvents, onToggleEvent }: FileGroupProps) {
  const [expanded, setExpanded] = useState(false);
  const { t } = useTranslation();

  return (
    <div className="border-l-2 border-cyan-200 rounded-r-lg bg-cyan-50/30">
      <div
        className="flex items-center py-2 px-3 cursor-pointer hover:bg-cyan-50 select-none"
        onClick={() => setExpanded(!expanded)}
      >
        {expanded ? (
          <ChevronDownIcon className="h-4 w-4 text-cyan-600 mr-2 flex-shrink-0" />
        ) : (
          <ChevronRightIcon className="h-4 w-4 text-cyan-600 mr-2 flex-shrink-0" />
        )}
        <DocumentIcon className="h-4 w-4 text-cyan-600 mr-2 flex-shrink-0" />
        <span className="text-sm font-medium text-cyan-800">
          {events.length} {t('badge.file_other', { count: events.length })}
        </span>
        <span className="ml-2 text-xs text-cyan-500 truncate">
          {events.slice(0, 3).map(e => {
            const path = e.metadata?.filepath || e.title || '';
            const basename = path.split('/').pop() || path;
            return basename;
          }).join(', ')}
          {events.length > 3 && ' …'}
        </span>
      </div>
      {expanded && (
        <div className="space-y-1 pl-2 pb-1">
          {events.map(event => {
            const isEventExpanded = expandedEvents.has(event.id);
            const data = adaptEventToUnifiedBlock(event);
            return (
              <UnifiedBlock
                key={event.id}
                data={data}
                isExpanded={isEventExpanded}
                onToggle={() => onToggleEvent(event.id)}
              />
            );
          })}
        </div>
      )}
    </div>
  );
}

interface ProcessNodeProps {
  process: ProcessNodeType;
  depth: number;
  expandedProcesses: Set<number>;
  expandedEvents: Set<string>;
  onToggleProcess: (pid: number) => void;
  onToggleEvent: (eventId: string) => void;
}

export function ProcessNode({
  process,
  depth,
  expandedProcesses,
  expandedEvents,
  onToggleProcess,
  onToggleEvent
}: ProcessNodeProps) {
  const { t } = useTranslation();
  const isExpanded = expandedProcesses.has(process.pid);
  const hasChildren = process.children.length > 0;
  const hasEvents = process.events.length > 0;
  const indent = depth * 24;

  // Count events by type
  const eventCounts = process.events.reduce((counts, event) => {
    counts[event.type] = (counts[event.type] || 0) + 1;
    return counts;
  }, {} as Record<string, number>);

  // Get event badges
  const getEventBadges = () => {
    const badges = [];
    if (eventCounts.prompt) {
      badges.push(
        <span key="prompt" className="px-2 py-1 bg-blue-100 text-blue-800 text-xs rounded-full font-semibold">
          {t(eventCounts.prompt === 1 ? 'badge.prompt_one' : 'badge.prompt_other', { count: eventCounts.prompt })}
        </span>
      );
    }
    if (eventCounts.response) {
      badges.push(
        <span key="response" className="px-2 py-1 bg-green-100 text-green-800 text-xs rounded-full font-semibold">
          {t(eventCounts.response === 1 ? 'badge.response_one' : 'badge.response_other', { count: eventCounts.response })}
        </span>
      );
    }
    if (eventCounts.ssl) {
      badges.push(
        <span key="ssl" className="px-2 py-1 bg-orange-100 text-orange-800 text-xs rounded-full">
          {t('badge.ssl', { count: eventCounts.ssl })}
        </span>
      );
    }
    if (eventCounts.file) {
      badges.push(
        <span key="file" className="px-2 py-1 bg-cyan-100 text-cyan-800 text-xs rounded-full">
          {t(eventCounts.file === 1 ? 'badge.file_one' : 'badge.file_other', { count: eventCounts.file })}
        </span>
      );
    }
    if (eventCounts.process) {
      badges.push(
        <span key="process" className="px-2 py-1 bg-purple-100 text-purple-800 text-xs rounded-full">
          {t('badge.process', { count: eventCounts.process })}
        </span>
      );
    }
    if (eventCounts.stdio) {
      badges.push(
        <span key="stdio" className="px-2 py-1 bg-indigo-100 text-indigo-800 text-xs rounded-full">
          {t('badge.stdio', { count: eventCounts.stdio })}
        </span>
      );
    }
    return badges;
  };

  const renderEvent = (event: ParsedEvent) => {
    const isEventExpanded = expandedEvents.has(event.id);
    const unifiedBlockData = adaptEventToUnifiedBlock(event);
    
    return (
      <UnifiedBlock
        key={event.id}
        data={unifiedBlockData}
        isExpanded={isEventExpanded}
        onToggle={() => onToggleEvent(event.id)}
      />
    );
  };

  const groupedTimeline = groupTimeline(process.timeline);

  const renderGroupedItem = (grouped: GroupedTimelineItem, index: number) => {
    if (grouped.kind === 'file_group') {
      return (
        <FileGroup
          key={`fg-${index}`}
          events={grouped.events}
          expandedEvents={expandedEvents}
          onToggleEvent={onToggleEvent}
        />
      );
    }
    const item = grouped.item;
    if (item.type === 'event' && item.event) {
      return renderEvent(item.event);
    } else if (item.type === 'process' && item.process) {
      return (
        <ProcessNode
          key={item.process.pid}
          process={item.process}
          depth={depth + 1}
          expandedProcesses={expandedProcesses}
          expandedEvents={expandedEvents}
          onToggleProcess={onToggleProcess}
          onToggleEvent={onToggleEvent}
        />
      );
    }
    return null;
  };

  return (
    <div>
      {/* Process Header */}
      <div
        className="select-none flex items-center py-3 px-4 hover:bg-gray-50 cursor-pointer border-l-2 border-indigo-200 rounded-r-lg transition-colors"
        style={{ marginLeft: `${indent}px` }}
        onClick={() => onToggleProcess(process.pid)}
      >
        <div className="flex items-center flex-1">
          {hasChildren || hasEvents ? (
            isExpanded ? (
              <ChevronDownIcon className="h-4 w-4 text-gray-500 mr-3 flex-shrink-0" />
            ) : (
              <ChevronRightIcon className="h-4 w-4 text-gray-500 mr-3 flex-shrink-0" />
            )
          ) : (
            <div className="w-7 mr-3" />
          )}
          
          <div className="flex items-center space-x-3 flex-1">
            <CpuChipIcon className="h-5 w-5 text-indigo-600 flex-shrink-0" />
            
            <div className="flex items-center space-x-2 min-w-0">
              <span className="text-sm text-gray-500 font-mono bg-gray-100 px-2 py-1 rounded">
                PID {process.pid}
              </span>
              <span className="font-semibold text-gray-900 text-lg">
                [{process.comm}]
              </span>
              {process.ppid && (
                <span className="text-xs text-gray-400">
                  ← {process.ppid}
                </span>
              )}
            </div>
            
            {/* Event badges */}
            <div className="flex items-center space-x-2 flex-wrap">
              {getEventBadges()}
            </div>
          </div>
        </div>
      </div>

      {/* Expanded Content - Timeline View */}
      {isExpanded && (
        <div style={{ marginLeft: `${indent + 32}px` }} className="mt-1 mb-2">
          {groupedTimeline.length > 0 && (
            <div className="space-y-1">
              {groupedTimeline.map((item, index) => renderGroupedItem(item, index))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
