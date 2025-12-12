// src/types.ts

export type SortKey = 'timestamp' | 'client' | 'remote_ip' | 'count' | 'source' | "domain";
export type TimeWindow = 'all' | "30m" | '1h' | '2h'  | '4h'  | '8h'  | '16h'  | '24h';

export interface LogEntryRaw {
  timestamp: string;
  client: string;
  host: string;
  domain: string | null;
  remote_ip: string | null;
  source: string | null;
  raw: string;
}

export interface LogEntryDisplay extends LogEntryRaw {
  key: string;
  count: number;
}

export interface BytesClientEntry {
  bytes_in: number;
  bytes_out: number;
  bytes_total: number;
  mb_in: number;
  mb_out: number;
  mb_total: number;
  last_seen_any: string
  last_seen_out: string
}

export interface BytesData {
  updated_at: string | null;
  clients: Record<string, BytesClientEntry>;
}


export interface SummaryRow {
  ip: string;
  mb_in: number;
  mb_out: number;
  mb_total: number;
  online: boolean;
  last_seen: string | null;
}


