import type { Alert, Host, KnownNetwork, MLConfig, MLStatus, RemoteTap, RemoteTapPairingToken, RuleListResponse, RuleSource, SamlConfig, SystemUpdateStatus, TestRun, ThreatLevel, UpdateStatus, User } from './types';
import * as demo from './demo/api';
import { isDemoMode } from './demo/mode';

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
  // WICHTIG: `...init` MUSS vor `headers:` stehen, sonst überschreibt ein
  // mitgebrachtes `init.headers` (z.B. Content-Type) die hier konstruierten
  // Headers KOMPLETT inkl. Authorization. Genau das hat
  // setInterfaceRole/POST 401 zurückgegeben, obwohl der Token gültig war.
  const res = await fetch(`${BASE}${path}`, {
    ...init,
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...init?.headers,
    },
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
  if (username === 'demo' && password === 'DemoCyjan2026!') {
    return { ...demo.login(), token_type: 'bearer' };
  }
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
  if (isDemoMode()) return demo.fetchMe();
  return req('/api/auth/me');
}

