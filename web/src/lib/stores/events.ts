import { derived, writable } from 'svelte/store';

export const MAX_EVENTS = 1200;

export const events = writable([]);
export const filterText = writable('');
export const sourceFilter = writable([]);
export const commFilter = writable('');
export const pidFilter = writable('');
export const timeStart = writable('');
export const timeEnd = writable('');
export const timeWindowMinutes = writable(0);
export const sampleStep = writable(1);
export const bucketSizeSeconds = writable(0);
export const viewMode = writable('detail');
export const paused = writable(false);
export const selectedEvent = writable(null);
export const now = writable(Date.now());

export function appendEvent(payload) {
  events.update((list) => {
    const next = [...list, payload];
    if (next.length > MAX_EVENTS) {
      return next.slice(next.length - MAX_EVENTS);
    }
    return next;
  });
}

export const sources = derived(events, ($events) => {
  const set = new Set();
  $events.forEach((event) => set.add(event.source));
  return Array.from(set).sort();
});

export const comms = derived(events, ($events) => {
  const set = new Set();
  $events.forEach((event) => event.comm && set.add(event.comm));
  return Array.from(set).sort();
});

export const pids = derived(events, ($events) => {
  const set = new Set();
  $events.forEach((event) => event.pid && set.add(String(event.pid)));
  return Array.from(set).sort((a, b) => Number(a) - Number(b));
});

function parseDateTime(value) {
  if (!value) return 0;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export const filteredEvents = derived(
  [
    events,
    filterText,
    sourceFilter,
    commFilter,
    pidFilter,
    timeStart,
    timeEnd,
    timeWindowMinutes,
    sampleStep,
    now
  ],
  ([
    $events,
    $filterText,
    $sourceFilter,
    $commFilter,
    $pidFilter,
    $timeStart,
    $timeEnd,
    $timeWindowMinutes,
    $sampleStep,
    $now
  ]) => {
    const token = $filterText.trim().toLowerCase();
    const startMs = parseDateTime($timeStart);
    const endMs = parseDateTime($timeEnd);
    const windowMs = $timeWindowMinutes > 0 ? $timeWindowMinutes * 60_000 : 0;

    const filtered = $events.filter((event) => {
      if ($sourceFilter.length > 0 && !$sourceFilter.includes(event.source)) {
        return false;
      }
      if ($commFilter && event.comm !== $commFilter) {
        return false;
      }
      if ($pidFilter && String(event.pid) !== $pidFilter) {
        return false;
      }
      const ts = event.timestamp_unix_ms || 0;
      if (startMs && ts && ts < startMs) {
        return false;
      }
      if (endMs && ts && ts > endMs) {
        return false;
      }
      if (!startMs && !endMs && windowMs && ts && ts < $now - windowMs) {
        return false;
      }
      if (!token) {
        return true;
      }
      const raw = JSON.stringify(event).toLowerCase();
      return raw.includes(token);
    });

    const step = Math.max(1, Number($sampleStep) || 1);
    if (step === 1) {
      return filtered;
    }

    return filtered.filter((_, index) => index % step === 0);
  }
);

export const groupedEvents = derived(
  [filteredEvents, bucketSizeSeconds],
  ([$filteredEvents, $bucketSizeSeconds]) => {
    if ($bucketSizeSeconds <= 0) {
      return [
        {
          key: 'all',
          label: '事件流',
          events: $filteredEvents
        }
      ];
    }

    const bucketMs = $bucketSizeSeconds * 1000;
    const groups = [];
    const indexMap = new Map();

    $filteredEvents.forEach((event) => {
      const ts = event.timestamp_unix_ms || 0;
      if (!ts) {
        const key = 'unknown';
        let idx = indexMap.get(key);
        if (idx === undefined) {
          idx = groups.length;
          groups.push({ key, label: '未知时间', events: [] });
          indexMap.set(key, idx);
        }
        groups[idx].events.push(event);
        return;
      }

      const bucket = Math.floor(ts / bucketMs) * bucketMs;
      const key = String(bucket);
      let idx = indexMap.get(key);
      if (idx === undefined) {
        idx = groups.length;
        const label = new Date(bucket).toLocaleTimeString();
        groups.push({ key, label, events: [] });
        indexMap.set(key, idx);
      }
      groups[idx].events.push(event);
    });

    return groups;
  }
);

export const stats = derived([events, now], ([$events, $now]) => {
  const bySource = {};
  let lastMinute = 0;
  $events.forEach((event) => {
    const source = event.source || 'unknown';
    bySource[source] = (bySource[source] || 0) + 1;
    const ts = event.timestamp_unix_ms || 0;
    if (ts > 0 && $now - ts <= 60_000) {
      lastMinute += 1;
    }
  });

  return {
    total: $events.length,
    lastMinute,
    bySource
  };
});
