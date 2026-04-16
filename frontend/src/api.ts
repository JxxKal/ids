import type { Alert, KnownNetwork, TestRun, ThreatLevel } from './types';

const BASE = import.meta.env.VITE_API_URL ?? '';

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...init?.headers },
    ...init,
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  return res.json() as Promise<T>;
}

// ── Alerts ────────────────────────────────────────────────────────────────────

export interface AlertFilters {
  severity?: string;
  source?: string;
  rule_id?: string;
  src_ip?: string;
  is_test?: boolean;
  limit?: number;
  offset?: number;
}

export async function fetchAlerts(filters: AlertFilters = {}): Promise<{
  alerts: Alert[];
  total: number;
}> {
  const params = new URLSearchParams();
  if (filters.severity) params.set('severity', filters.severity);
  if (filters.source)   params.set('source',   filters.source);
  if (filters.rule_id)  params.set('rule_id',  filters.rule_id);
  if (filters.src_ip)   params.set('src_ip',   filters.src_ip);
  params.set('is_test', String(filters.is_test ?? false));
  params.set('limit',   String(filters.limit  ?? 100));
  params.set('offset',  String(filters.offset ?? 0));
  return req(`/api/alerts?${params}`);
}

export async function setFeedback(
  alertId: string,
  feedback: 'fp' | 'tp',
  note?: string,
): Promise<Alert> {
  return req(`/api/alerts/${alertId}/feedback`, {
    method: 'PATCH',
    body: JSON.stringify({ feedback, note }),
  });
}

export function pcapUrl(alertId: string): string {
  return `${BASE}/api/alerts/${alertId}/pcap`;
}

// ── Threat Level ──────────────────────────────────────────────────────────────

export async function fetchThreatLevel(): Promise<ThreatLevel> {
  return req('/api/stats/threat-level');
}

// ── Networks ──────────────────────────────────────────────────────────────────

export async function fetchNetworks(): Promise<KnownNetwork[]> {
  return req('/api/networks');
}

export async function createNetwork(data: {
  cidr: string;
  name: string;
  description?: string;
  color?: string;
}): Promise<KnownNetwork> {
  return req('/api/networks', { method: 'POST', body: JSON.stringify(data) });
}

export async function deleteNetwork(id: string): Promise<void> {
  await req(`/api/networks/${id}`, { method: 'DELETE' });
}

// ── Tests ─────────────────────────────────────────────────────────────────────

export async function runTest(scenarioId: string): Promise<TestRun> {
  return req('/api/tests/run', {
    method: 'POST',
    body: JSON.stringify({ scenario_id: scenarioId }),
  });
}

export async function fetchTestRuns(): Promise<TestRun[]> {
  return req('/api/tests/runs');
}
