// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

import type { en } from './en';

type TranslationKey = keyof typeof en;

export const zh: Record<TranslationKey, string> = {
  // App
  'app.title': 'AgentSight \u5206\u6790\u5668',
  'app.subtitle': '\u4e0a\u4f20\u5e76\u5206\u6790 eBPF Agent \u8ffd\u8e2a\u65e5\u5fd7\uff0c\u652f\u6301\u591a\u79cd\u89c6\u56fe\u6a21\u5f0f',
  'app.eventsLoaded': '{count} \u4e2a\u4e8b\u4ef6\u5df2\u52a0\u8f7d',
  'app.file': '\u6587\u4ef6\uff1a',
  'app.syncing': '\u540c\u6b65\u4e2d...',
  'app.streaming': '\u6d41\u5f0f\u63a5\u6536\u4e2d',
  'app.logView': '\u65e5\u5fd7\u89c6\u56fe',
  'app.timelineView': '\u65f6\u95f4\u7ebf\u89c6\u56fe',
  'app.processTree': '\u8fdb\u7a0b\u6811',
  'app.metrics': '\u6027\u80fd\u6307\u6807',
  'app.hideLog': '\u9690\u85cf\u4e0a\u4f20',
  'app.uploadLog': '\u4e0a\u4f20\u65e5\u5fd7',
  'app.syncData': '\u540c\u6b65\u6570\u636e',
  'app.stopStreaming': '\u505c\u6b62\u6d41\u5f0f\u63a5\u6536',
  'app.startStreaming': '\u5f00\u59cb\u6d41\u5f0f\u63a5\u6536',
  'app.clearData': '\u6e05\u9664\u6570\u636e',
  'app.loadingEvents': '\u6b63\u5728\u4ece\u670d\u52a1\u5668\u52a0\u8f7d\u4e8b\u4ef6...',
  'app.noEventsLoaded': '\u6682\u65e0\u4e8b\u4ef6\u6570\u636e',
  'app.syncFromServer': '\u4ece\u670d\u52a1\u5668\u540c\u6b65\u6570\u636e',
  'app.uploadLogFile': '\u4e0a\u4f20\u65e5\u5fd7\u6587\u4ef6',

  // Upload
  'upload.title': '\u4e0a\u4f20\u65e5\u5fd7\u6587\u4ef6',
  'upload.chooseFile': '\u9009\u62e9\u65e5\u5fd7\u6587\u4ef6',
  'upload.or': '\u6216',
  'upload.pasteContent': '\u7c98\u8d34\u65e5\u5fd7\u5185\u5bb9',
  'upload.pastePlaceholder': '\u5728\u6b64\u7c98\u8d34\u65e5\u5fd7\u5185\u5bb9\uff08\u4f8b\u5982\u6765\u81ea {path}\uff09',
  'upload.parseLog': '\u89e3\u6790\u65e5\u5fd7',
  'upload.parsing': '\u6b63\u5728\u89e3\u6790\u65e5\u5fd7\u5185\u5bb9...',

  // Modal
  'modal.eventDetails': '\u4e8b\u4ef6\u8be6\u60c5',
  'modal.id': 'ID',
  'modal.source': '\u6765\u6e90',
  'modal.process': '\u8fdb\u7a0b',
  'modal.pid': 'PID',
  'modal.time': '\u65f6\u95f4',
  'modal.timestamp': '\u65f6\u95f4\u6233',
  'modal.unixTimestamp': 'Unix \u65f6\u95f4\u6233',
  'modal.decodedStdio': '\u89e3\u7801\u540e\u7684\u6807\u51c6 I/O',
  'modal.direction': '\u65b9\u5411',
  'modal.fdRole': 'FD \u89d2\u8272',
  'modal.kind': '\u7c7b\u578b',
  'modal.messageId': '\u6d88\u606f ID',
  'modal.method': '\u65b9\u6cd5',
  'modal.tool': '\u5de5\u5177',
  'modal.rawData': '\u539f\u59cb\u6570\u636e',

  // Filters
  'filter.searchEvents': '\u641c\u7d22\u4e8b\u4ef6...',
  'filter.allSources': '\u5168\u90e8\u6765\u6e90',
  'filter.allProcesses': '\u5168\u90e8\u8fdb\u7a0b',
  'filter.allPids': '\u5168\u90e8 PID',
  'filter.pid': 'PID {pid}',

  // Process Tree
  'processTree.title': '\u8fdb\u7a0b\u6811 & AI \u63d0\u793a',
  'processTree.subtitle': '\u4ee5\u5c42\u7ea7\u89c6\u56fe\u5c55\u793a\u8fdb\u7a0b\u53ca\u5176 AI \u63d0\u793a\u548c API \u8c03\u7528',
  'processTree.noProcesses': '\u6682\u65e0\u8fdb\u7a0b\u53ef\u663e\u793a',
  'processTree.noMatch': '\u6ca1\u6709\u5339\u914d\u5f53\u524d\u7b5b\u9009\u6761\u4ef6\u7684\u8fdb\u7a0b',

  // Process Tree Filters
  'processTree.filters': '\u7b5b\u9009',
  'processTree.active': '\u5df2\u542f\u7528',
  'processTree.aiOnly': '\u4ec5 AI',
  'processTree.filesOnly': '\u4ec5\u6587\u4ef6',
  'processTree.processesOnly': '\u4ec5\u8fdb\u7a0b',
  'processTree.showing': '\u663e\u793a {filtered} / {total} \u4e2a\u4e8b\u4ef6',
  'processTree.clearAll': '\u6e05\u9664\u5168\u90e8',
  'processTree.search': '\u641c\u7d22',
  'processTree.searchPlaceholder': '\u641c\u7d22\u5185\u5bb9\u3001\u6a21\u578b\u3001\u547d\u4ee4...',
  'processTree.eventTypes': '\u4e8b\u4ef6\u7c7b\u578b',
  'processTree.aiModels': 'AI \u6a21\u578b',
  'processTree.sources': '\u6570\u636e\u6765\u6e90',
  'processTree.commands': '\u547d\u4ee4',
  'processTree.timeRange': '\u65f6\u95f4\u8303\u56f4',
  'processTree.to': '\u81f3',

  // Badges
  'badge.prompt_one': '{count} \u4e2a\u63d0\u793a',
  'badge.prompt_other': '{count} \u4e2a\u63d0\u793a',
  'badge.response_one': '{count} \u4e2a\u54cd\u5e94',
  'badge.response_other': '{count} \u4e2a\u54cd\u5e94',
  'badge.ssl': '{count} SSL',
  'badge.file_one': '{count} \u4e2a\u6587\u4ef6',
  'badge.file_other': '{count} \u4e2a\u6587\u4ef6',
  'badge.process': '{count} \u4e2a\u8fdb\u7a0b',
  'badge.stdio': '{count} \u4e2a\u6807\u51c6 I/O',

  // Tags
  'tag.aiPrompt': 'AI \u63d0\u793a',
  'tag.aiResponse': 'AI \u54cd\u5e94',
  'tag.changed': '\u5df2\u53d8\u66f4',
  'tag.ssl': 'SSL',
  'tag.stdio': '\u6807\u51c6 I/O',

  // Resource Metrics
  'metrics.noData': '\u6682\u65e0\u7cfb\u7edf\u8d44\u6e90\u6307\u6807\u6570\u636e',
  'metrics.noDataHint': '\u4f7f\u7528 --system \u53c2\u6570\u6216 record \u547d\u4ee4\u65f6\u4f1a\u91c7\u96c6\u7cfb\u7edf\u6307\u6807',
  'metrics.title': '\u8d44\u6e90\u6307\u6807',
  'metrics.cpu': 'CPU',
  'metrics.memory': '\u5185\u5b58',
  'metrics.allProcesses': '\u5168\u90e8\u8fdb\u7a0b\uff08{count} \u4e2a\u91c7\u6837\uff09',
  'metrics.processOption': '{comm}\uff08PID {pid}\uff09- {count} \u4e2a\u91c7\u6837',
  'metrics.avgCpu': '\u5e73\u5747 CPU',
  'metrics.peakCpu': '\u5cf0\u503c CPU',
  'metrics.avgMemory': '\u5e73\u5747\u5185\u5b58',
  'metrics.peakMemory': '\u5cf0\u503c\u5185\u5b58',
  'metrics.alerts': '\u544a\u8b66',
  'metrics.cpuOverTime': 'CPU \u4f7f\u7528\u7387\u53d8\u5316',
  'metrics.memoryOverTime': '\u5185\u5b58\u4f7f\u7528\u53d8\u5316',
  'metrics.dataPoints': '{count} \u4e2a\u6570\u636e\u70b9',
  'metrics.detailedMetrics': '\u8be6\u7ec6\u6307\u6807',
  'metrics.table.time': '\u65f6\u95f4',
  'metrics.table.process': '\u8fdb\u7a0b',
  'metrics.table.pid': 'PID',
  'metrics.table.cpuPercent': 'CPU %',
  'metrics.table.memoryRss': '\u5185\u5b58 (RSS)',
  'metrics.table.threads': '\u7ebf\u7a0b',
  'metrics.table.children': '\u5b50\u8fdb\u7a0b',

  // Timeline
  'timeline.title': '\u65f6\u95f4\u7ebf\u89c6\u56fe',
  'timeline.durationInfo': '\u6301\u7eed\u65f6\u95f4\uff1a{duration} \u00b7 {count} \u4e2a\u4e8b\u4ef6',
  'timeline.zoomHelp': '\u4f7f\u7528\u9f20\u6807\u6eda\u8f6e + Ctrl/Cmd \u7f29\u653e\uff0c\u6216\u4f7f\u7528 Ctrl/Cmd + +/- \u952e\u3002\u6309 Ctrl/Cmd + 0 \u91cd\u7f6e\u3002',
  'timeline.scrollHelp': '\u7f29\u653e\u540e\u53ef\u4f7f\u7528\u9f20\u6807\u6eda\u8f6e\u6216\u65b9\u5411\u952e\u6eda\u52a8\u3002',
  'timeline.noEvents': '\u6682\u65e0\u4e8b\u4ef6\u53ef\u663e\u793a',
  'timeline.eventDetails': '\u65f6\u95f4\u7ebf\u4e8b\u4ef6\u8be6\u60c5',

  // Zoom Controls
  'timeline.zoomOut': '\u7f29\u5c0f',
  'timeline.zoomIn': '\u653e\u5927',
  'timeline.resetZoom': '\u91cd\u7f6e\u7f29\u653e',
  'timeline.reset': '\u91cd\u7f6e',
  'timeline.scrollLeft': '\u5411\u5de6\u6eda\u52a8',
  'timeline.scroll': '\u6eda\u52a8',
  'timeline.scrollRight': '\u5411\u53f3\u6eda\u52a8',

  // Timeline Minimap
  'timeline.overview': '\u65f6\u95f4\u7ebf\u6982\u89c8',
  'timeline.scrolled': '\u5df2\u6eda\u52a8 {percent}%',

  // Timeline ScrollBar
  'timeline.scrollPosition': '\u6eda\u52a8\u4f4d\u7f6e',

  // Log
  'log.noEvents': '\u6ca1\u6709\u627e\u5230\u5339\u914d\u5f53\u524d\u7b5b\u9009\u6761\u4ef6\u7684\u4e8b\u4ef6\u3002',
  'log.eventDetails': '\u65e5\u5fd7\u4e8b\u4ef6\u8be6\u60c5',
};
