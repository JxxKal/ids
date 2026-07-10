// Spiegelt die Pydantic-Modelle des Backends (engine/verdict.py)

export type HopVerdict = 'ALLOW' | 'DENY' | 'UNKNOWN';
export type TraceVerdict = 'ALLOW' | 'DENY' | 'DEGRADED';
export type EgressClass = 'LOCAL' | 'VDOM_LINK' | 'OVERLAY' | 'DEFAULT' | 'UNKNOWN';
export type Provenance = 'fmg' | 'itop' | 'dns' | 'ip';

export interface NameEntry {
  name: string;
  provenance: Provenance;
}

export interface Endpoint {
  ip: string;
  names: NameEntry[];
  provenance: Provenance;
}

export interface Candidate {
  policyid: number | null;
  name: string;
  action: string;
  srcintf: string[];
  dstintf: string[];
  srcaddr: string[];
  dstaddr: string[];
  service: string[];
  comments: string;
  hit: boolean;
}

export interface Suggestion {
  device: string;
  vdom: string;
  adom: string;
  package: string | null;
  src_zone: string;
  dst_zone: string;
  src_obj: { name: string; existing: boolean; subnet?: string };
  dst_obj: { name: string; existing: boolean; subnet?: string };
  service: { name: string; existing: boolean; protocol?: string; port?: number };
  policy_name: string;
  cli: string;
  jsonrpc: string[];
  note: string;
}

export interface Hop {
  index: number;
  device: string;
  vdom: string;
  adom: string | null;
  srcintf: string;
  src_zone: string | null;
  egress: string | null;
  egress_zone: string | null;
  egress_class: EgressClass;
  route: { interface: string; gateway: string | null; source: string } | null;
  verdict: HopVerdict;
  matched_policy: Candidate | null;
  candidates: Candidate[];
  suggestion: Suggestion | null;
  warnings: string[];
  degraded: boolean;
  after_deny: boolean;
}

export interface TraceResult {
  verdict: TraceVerdict;
  src: Endpoint;
  dst: Endpoint;
  protocol: string;
  dst_port: number | null;
  src_port: number | null;
  icmp_type: number | null;
  icmp_code: number | null;
  hops: Hop[];
  warnings: string[];
  vip: { name: string; extip: string; mappedip: string | null } | null;
  duration_ms: number;
  inventory_synced_at: string | null;
}

export interface TraceRequest {
  src: string;
  dst: string;
  protocol: string;
  dst_port?: number | null;
  src_port?: number | null;
  icmp_type?: number | null;
  icmp_code?: number | null;
}

export interface TraceHistoryEntry {
  id: number;
  created_at: string;
  username: string;
  request: TraceRequest;
  verdict: TraceVerdict;
  duration_ms: number;
}

export interface SearchHit {
  name: string;
  ip?: string | null;
  fqdn?: string | null;
  provenance: Provenance;
  adom?: string;
}

export interface SyncStatus {
  phase: 'idle' | 'running' | 'done' | 'error';
  log: string[];
  stats: Record<string, number>;
  started_at: string | null;
  finished_at: string | null;
}

export interface InventorySummary {
  synced_at: string | null;
  adoms: string[];
  devices: Record<string, { adom: string; vdoms: string[] }>;
  counts: Record<string, number>;
}

export interface UserEntry {
  id: number;
  username: string;
  role: 'admin' | 'viewer';
}

export interface Session {
  token: string;
  username: string;
  role: 'admin' | 'viewer';
}
