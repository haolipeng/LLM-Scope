// SPDX-License-Identifier: MIT
// Copyright (c) 2026 eunomia-bpf org.

import { Event } from '@/types/event';

export interface RawGoEvent {
  timestamp_ns: number;
  timestamp_unix_ms?: number;
  source: string;
  pid: number;
  comm: string;
  data: any;
}

export function adaptGoEvent(raw: RawGoEvent, index: number): Event {
  const timestamp = raw.timestamp_unix_ms || Math.floor(raw.timestamp_ns / 1_000_000);
  return {
    id: `${raw.source}-${timestamp}-${index}`,
    timestamp,
    source: raw.source,
    pid: raw.pid,
    comm: raw.comm,
    data: raw.data,
  };
}

export function isGoEventFormat(obj: any): boolean {
  return 'timestamp_ns' in obj || 'timestamp_unix_ms' in obj;
}
