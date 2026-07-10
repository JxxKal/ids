// API-Client (ids-Muster: fetch-Wrapper + Demo-Mode-Gate pro Funktion).
import * as demo from './demo/api';
import { isDemoMode } from './demo/mode';
import type {
  InventorySummary, SearchHit, Session, SyncStatus,
  TraceHistoryEntry, TraceRequest, TraceResult, UserEntry,
} from './types';

let token: string | null = localStorage.getItem('fwpt-token');

export function setToken(t: string | null): void {
  token = t;
  if (t) localStorage.setItem('fwpt-token', t);
  else localStorage.removeItem('fwpt-token');
}

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
  });
  if (res.status === 401) {
    setToken(null);
    window.dispatchEvent(new Event('fwpt-logout'));
  }
  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail);
    } catch { /* Klartext-Fehler */ }
    throw new ApiError(res.status, detail);
  }
  if (res.status === 204) return undefined as T;
  return res.json();
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export async function login(username: string, password: string): Promise<Session> {
  if (isDemoMode() || (username === 'demo' && password === 'demo')) {
    localStorage.setItem('fwpt-demo', '1');
    return demo.login();
  }
  const r = await request<{ token: string; username: string; role: 'admin' | 'viewer' }>(
    '/api/auth/login',
    { method: 'POST', body: JSON.stringify({ username, password }) },
  );
  setToken(r.token);
  return { token: r.token, username: r.username, role: r.role };
}

// ── Trace ─────────────────────────────────────────────────────────────────────

export async function runTrace(req: TraceRequest): Promise<TraceResult> {
  if (isDemoMode()) return demo.trace(req);
  return request('/api/trace', { method: 'POST', body: JSON.stringify(req) });
}

export async function fetchTraces(): Promise<TraceHistoryEntry[]> {
  if (isDemoMode()) return demo.traces();
  return request('/api/traces');
}

export async function searchEndpoints(q: string): Promise<SearchHit[]> {
  if (isDemoMode()) return demo.search(q);
  return request(`/api/search?q=${encodeURIComponent(q)}`);
}

// ── Settings ──────────────────────────────────────────────────────────────────

export async function getConfig(key: string): Promise<Record<string, unknown>> {
  if (isDemoMode()) return {};
  const r = await request<{ value: Record<string, unknown> }>(`/api/config/${key}`);
  return r.value;
}

export async function patchConfig(
  key: string, value: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  if (isDemoMode()) return value;
  const r = await request<{ value: Record<string, unknown> }>(`/api/config/${key}`, {
    method: 'PATCH', body: JSON.stringify({ value }),
  });
  return r.value;
}

export async function fmgTest(): Promise<{ ok: boolean; version?: string; adoms: string[] }> {
  if (isDemoMode()) return { ok: true, version: '7.4.5-demo', adoms: ['corp'] };
  return request('/api/fmg/test', { method: 'POST' });
}

export async function fmgSync(): Promise<void> {
  if (isDemoMode()) return;
  await request('/api/fmg/sync', { method: 'POST' });
}

export async function fmgSyncStatus(): Promise<SyncStatus> {
  if (isDemoMode()) return demo.syncStatus();
  return request('/api/fmg/sync/status');
}

export async function inventorySummary(): Promise<InventorySummary> {
  if (isDemoMode()) return demo.inventorySummary();
  return request('/api/fmg/inventory/summary');
}

export async function itopTest(): Promise<{ ok: boolean; organisations: string[] }> {
  if (isDemoMode()) return { ok: true, organisations: ['Demo Org'] };
  return request('/api/itop/test', { method: 'POST' });
}

// ── Users ─────────────────────────────────────────────────────────────────────

export async function fetchUsers(): Promise<UserEntry[]> {
  if (isDemoMode()) return [{ id: 1, username: 'demo', role: 'admin' }];
  return request('/api/users');
}

export async function createUser(
  username: string, password: string, role: string,
): Promise<void> {
  if (isDemoMode()) return;
  await request('/api/users', {
    method: 'POST', body: JSON.stringify({ username, password, role }),
  });
}

export async function deleteUser(id: number): Promise<void> {
  if (isDemoMode()) return;
  await request(`/api/users/${id}`, { method: 'DELETE' });
}
