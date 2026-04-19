import type { Alert, Host, KnownNetwork, RuleListResponse, RuleSource, SamlConfig, TestRun, ThreatLevel, UpdateStatus, User } from './types';

const BASE = import.meta.env.VITE_API_URL ?? '';

const TOKEN_KEY = 'ids_token';

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}

export function setToken(token: string): void {
  localStorage.setItem(TOKEN_KEY, token);
}

export function clearToken(): void {
  localStorage.removeItem(TOKEN_KEY);
}

async function req<T>(path: string, init?: RequestInit): Promise<T> {
  const token = getToken();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
    ...init,
  });
  if (res.status === 401) {
    clearToken();
    window.dispatchEvent(new Event('ids:unauthorized'));
    throw new Error('401 Unauthorized');
  }
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(`${res.status} ${res.statusText}: ${text}`);
  }
  if (res.status === 204 || res.headers.get('content-length') === '0') {
    return undefined as T;
  }
  return res.json() as Promise<T>;
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export interface LoginResponse {
  access_token: string;
  token_type:   string;
  user:         User;
}

export async function login(username: string, password: string): Promise<LoginResponse> {
  const res = await fetch(`${BASE}/api/auth/login`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });
  if (!res.ok) {
    const text = await res.text().catch(() => '');
    throw new Error(text.includes('Ungültige') ? 'Ungültige Anmeldedaten' : `${res.status}: ${text}`);
  }
  return res.json();
}

export async function fetchMe(): Promise<User> {
  return req('/api/auth/me');
}

// ── Alerts ────────────────────────────────────────────────────────────────────

export interface AlertFilters {
  severity?: string;
  source?: string;
  rule_id?: string;
  src_ip?: string;
  ts_from?: number;   // Unix-Timestamp (Sekunden)
  ts_to?: number;
  is_test?: boolean | null;  // null = alle (kein Filter)
  limit?: number;
  offset?: number;
}

export async function fetchAlerts(filters: AlertFilters = {}): Promise<{
  alerts: Alert[];
  total: number;
}> {
  const params = new URLSearchParams();
  if (filters.severity)              params.set('severity', filters.severity);
  if (filters.source)                params.set('source',   filters.source);
  if (filters.rule_id)               params.set('rule_id',  filters.rule_id);
  if (filters.src_ip)                params.set('src_ip',   filters.src_ip);
  if (filters.ts_from !== undefined) params.set('ts_from',  String(filters.ts_from));
  if (filters.ts_to   !== undefined) params.set('ts_to',    String(filters.ts_to));
  if (filters.is_test !== null && filters.is_test !== undefined)
    params.set('is_test', String(filters.is_test));
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

// ── Hosts ─────────────────────────────────────────────────────────────────────

export async function fetchHosts(params: { trusted?: boolean; search?: string } = {}): Promise<Host[]> {
  const p = new URLSearchParams();
  if (params.trusted !== undefined) p.set('trusted', String(params.trusted));
  if (params.search)                p.set('search',  params.search);
  return req(`/api/hosts?${p}`);
}

export async function createHost(data: {
  ip: string;
  display_name?: string;
  trusted?: boolean;
}): Promise<Host> {
  return req('/api/hosts', { method: 'POST', body: JSON.stringify({ ...data, trust_source: 'manual', trusted: true }) });
}

export async function updateHost(ip: string, data: { display_name?: string; trusted?: boolean }): Promise<Host> {
  return req(`/api/hosts/${encodeURIComponent(ip)}`, { method: 'PUT', body: JSON.stringify(data) });
}

export async function deleteHost(ip: string): Promise<void> {
  await req(`/api/hosts/${encodeURIComponent(ip)}`, { method: 'DELETE' });
}

export async function importHostsCsv(file: File): Promise<{ imported: number; skipped: number; errors: string[] }> {
  const fd = new FormData();
  fd.append('file', file);
  const res = await fetch(`${BASE}/api/hosts/import/csv`, { method: 'POST', body: fd });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
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

export async function deleteTestRun(runId: string): Promise<void> {
  return req(`/api/tests/runs/${runId}`, { method: 'DELETE' });
}

export async function deleteAllTestRuns(): Promise<void> {
  return req('/api/tests/runs', { method: 'DELETE' });
}

// ── Users ─────────────────────────────────────────────────────────────────────

export async function fetchUsers(): Promise<User[]> {
  return req('/api/users');
}

export async function createUser(data: {
  username: string;
  email?: string;
  display_name?: string;
  role: 'admin' | 'viewer';
  password: string;
}): Promise<User> {
  return req('/api/users', { method: 'POST', body: JSON.stringify(data) });
}

export async function updateUser(id: string, data: {
  email?: string;
  display_name?: string;
  role?: 'admin' | 'viewer';
  active?: boolean;
  password?: string;
}): Promise<User> {
  return req(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
}

export async function deleteUser(id: string): Promise<void> {
  return req(`/api/users/${id}`, { method: 'DELETE' });
}

// ── Rules Engine ─────────────────────────────────────────────────────────────

export async function fetchRuleSources(): Promise<RuleSource[]> {
  return req('/api/rules/sources');
}

export async function addRuleSource(data: { name: string; url: string; enabled: boolean }): Promise<RuleSource> {
  return req('/api/rules/sources', { method: 'POST', body: JSON.stringify(data) });
}

export async function patchRuleSource(id: string, data: { enabled?: boolean; name?: string; url?: string }): Promise<RuleSource> {
  return req(`/api/rules/sources/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
}

export async function deleteRuleSource(id: string): Promise<void> {
  return req(`/api/rules/sources/${id}`, { method: 'DELETE' });
}

export async function fetchRules(params: { search?: string; limit?: number; offset?: number } = {}): Promise<RuleListResponse> {
  const p = new URLSearchParams();
  if (params.search) p.set('search', params.search);
  if (params.limit  !== undefined) p.set('limit',  String(params.limit));
  if (params.offset !== undefined) p.set('offset', String(params.offset));
  return req(`/api/rules?${p}`);
}

export async function triggerRuleUpdate(): Promise<UpdateStatus> {
  return req('/api/rules/update', { method: 'POST' });
}

export async function fetchRuleUpdateStatus(): Promise<UpdateStatus> {
  return req('/api/rules/update/status');
}

// ── SAML Config ───────────────────────────────────────────────────────────────

export async function fetchSamlConfig(): Promise<SamlConfig> {
  const r = await req<{ key: string; value: SamlConfig }>('/api/config/saml');
  return r.value;
}

export async function saveSamlConfig(value: SamlConfig): Promise<void> {
  await req('/api/config/saml', { method: 'PATCH', body: JSON.stringify({ value }) });
}
