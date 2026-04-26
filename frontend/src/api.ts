import type { Alert, Host, KnownNetwork, MLConfig, MLStatus, RuleListResponse, RuleSource, SamlConfig, SystemUpdateStatus, TestRun, ThreatLevel, UpdateStatus, User } from './types';
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
  if (username === 'demo' && password === 'demo') {
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
  if (isDemoMode()) return demo.fetchAlerts(filters);
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

export async function clearFeedback(alertId: string): Promise<Alert> {
  return req(`/api/alerts/${alertId}/feedback`, { method: 'DELETE' });
}

export async function setFeedback(
  alertId: string,
  feedback: 'fp' | 'tp',
  note?: string,
): Promise<Alert> {
  if (isDemoMode()) return demo.setFeedback(alertId, feedback, note);
  return req(`/api/alerts/${alertId}/feedback`, {
    method: 'PATCH',
    body: JSON.stringify({ feedback, note }),
  });
}

// raw=true liefert das ungefilterte ±60s-Capture-Fenster aus pcap-store
// (sonst per Default nur die Pakete die zum Alert-Flow passen).
export function pcapUrl(alertId: string, raw = false): string {
  return `${BASE}/api/alerts/${alertId}/pcap${raw ? '?raw=true' : ''}`;
}

export function alertsExportUrl(params: {
  severity?: string; source?: string; rule_id?: string;
  src_ip?: string; ts_from?: number; ts_to?: number;
  is_test?: boolean | null; feedback?: string; limit?: number;
} = {}): string {
  const p = new URLSearchParams();
  if (params.severity)              p.set('severity', params.severity);
  if (params.source)                p.set('source',   params.source);
  if (params.rule_id)               p.set('rule_id',  params.rule_id);
  if (params.src_ip)                p.set('src_ip',   params.src_ip);
  if (params.ts_from !== undefined) p.set('ts_from',  String(params.ts_from));
  if (params.ts_to   !== undefined) p.set('ts_to',    String(params.ts_to));
  if (params.is_test !== null && params.is_test !== undefined)
    p.set('is_test', String(params.is_test));
  if (params.feedback)              p.set('feedback', params.feedback);
  p.set('limit', String(params.limit ?? 5000));
  return `${BASE}/api/alerts/export.csv?${p}`;
}

// ── Threat Level ──────────────────────────────────────────────────────────────

export async function fetchThreatLevel(): Promise<ThreatLevel> {
  if (isDemoMode()) return demo.fetchThreatLevel();
  return req('/api/stats/threat-level');
}

// ── Networks ──────────────────────────────────────────────────────────────────

export async function fetchNetworks(): Promise<KnownNetwork[]> {
  if (isDemoMode()) return demo.fetchNetworks();
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

export async function updateNetwork(id: string, data: { name?: string; description?: string; color?: string }): Promise<KnownNetwork> {
  return req(`/api/networks/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
}

export async function deleteNetwork(id: string): Promise<void> {
  await req(`/api/networks/${id}`, { method: 'DELETE' });
}

// ── Hosts ─────────────────────────────────────────────────────────────────────

export interface UnknownHost {
  ip: string;
  alert_count: number;
  last_seen: string | null;
  first_seen: string | null;
  top_severity: string | null;
}

export async function fetchUnknownHosts(days = 30): Promise<UnknownHost[]> {
  if (isDemoMode()) return [
    { ip: '10.0.0.55', alert_count: 12, last_seen: new Date().toISOString(), first_seen: new Date(Date.now() - 86400000).toISOString(), top_severity: 'medium' },
    { ip: '192.168.5.22', alert_count: 4, last_seen: new Date().toISOString(), first_seen: new Date(Date.now() - 3600000).toISOString(), top_severity: 'high' },
  ];
  return req(`/api/hosts/unknown?days=${days}`);
}

export async function fetchHosts(params: { trusted?: boolean; search?: string } = {}): Promise<Host[]> {
  if (isDemoMode()) return demo.fetchHosts(params);
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
  const token = getToken();
  const res = await fetch(`${BASE}/api/hosts/import/csv`, {
    method: 'POST', body: fd,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export async function downloadHostsExampleCsv(): Promise<void> {
  const token = getToken();
  const res = await fetch(`${BASE}/api/hosts/example.csv`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error(`${res.status}`);
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'hosts_example.csv'; a.click();
  URL.revokeObjectURL(url);
}

export async function importNetworksCsv(file: File): Promise<{ imported: number; skipped: number; errors: string[] }> {
  const fd = new FormData();
  fd.append('file', file);
  const token = getToken();
  const res = await fetch(`${BASE}/api/networks/import/csv`, {
    method: 'POST', body: fd,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

export async function downloadNetworksExampleCsv(): Promise<void> {
  const token = getToken();
  const res = await fetch(`${BASE}/api/networks/example.csv`, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  });
  if (!res.ok) throw new Error(`${res.status}`);
  const blob = await res.blob();
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href = url; a.download = 'networks_example.csv'; a.click();
  URL.revokeObjectURL(url);
}

// ── Tests ─────────────────────────────────────────────────────────────────────

export async function runTest(scenarioId: string): Promise<TestRun> {
  return req('/api/tests/run', {
    method: 'POST',
    body: JSON.stringify({ scenario_id: scenarioId }),
  });
}

export async function fetchTestRuns(): Promise<TestRun[]> {
  if (isDemoMode()) return demo.fetchTestRuns();
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
  if (isDemoMode()) return demo.fetchUsers();
  return req('/api/users');
}

export async function createUser(data: {
  username: string;
  email?: string;
  display_name?: string;
  role: 'admin' | 'viewer' | 'api';
  password: string;
}): Promise<User> {
  return req('/api/users', { method: 'POST', body: JSON.stringify(data) });
}

export async function updateUser(id: string, data: {
  email?: string;
  display_name?: string;
  role?: 'admin' | 'viewer' | 'api';
  active?: boolean;
  password?: string;
}): Promise<User> {
  return req(`/api/users/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
}

export async function deleteUser(id: string): Promise<void> {
  return req(`/api/users/${id}`, { method: 'DELETE' });
}

export async function generateApiToken(userId: string): Promise<{ token: string; expires_in_days: number }> {
  return req(`/api/users/${userId}/token`, { method: 'POST' });
}

// ── ML / KI-Engine ───────────────────────────────────────────────────────────

export async function fetchMLStatus(): Promise<MLStatus> {
  if (isDemoMode()) return demo.fetchMLStatus() as unknown as MLStatus;
  return req('/api/ml/status');
}

export async function fetchMLConfig(): Promise<MLConfig> {
  if (isDemoMode()) return demo.fetchMLConfig() as unknown as MLConfig;
  return req('/api/ml/config');
}

export async function saveMLConfig(data: Partial<MLConfig>): Promise<MLConfig> {
  return req('/api/ml/config', { method: 'PATCH', body: JSON.stringify(data) });
}

export async function triggerMLRetrain(): Promise<{ triggered: boolean; triggered_at: number }> {
  return req('/api/ml/retrain', { method: 'POST' });
}

// ── Connection Graph ─────────────────────────────────────────────────────────

export interface ConnectionSummary {
  src_ip:     string;
  dst_ip:     string;
  dst_port:   number | null;
  proto:      string;
  flow_count: number;
  pkt_count:  number;
  byte_count: number;
  first_seen: string;
  last_seen:  string;
}

export interface ConnectionGraphData {
  src_ip:      string;
  dst_ip:      string;
  window_min:  number;
  total_flows: number;
  connections: ConnectionSummary[];
}

export async function fetchConnectionGraph(
  srcIp: string,
  dstIp: string,
  centerTs: number,   // Unix seconds
  windowMin = 5,
): Promise<ConnectionGraphData> {
  if (isDemoMode()) return demo.fetchConnectionGraph(srcIp, dstIp);
  const p = new URLSearchParams({
    src_ip:     srcIp,
    dst_ip:     dstIp,
    center_ts:  String(centerTs),
    window_min: String(windowMin),
  });
  return req(`/api/flows/graph?${p}`);
}

// ── Rules Engine ─────────────────────────────────────────────────────────────

export async function fetchRuleSources(): Promise<RuleSource[]> {
  if (isDemoMode()) return demo.fetchRuleSources();
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
  if (isDemoMode()) return { rules: [], total: 0 } as unknown as RuleListResponse;
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
  if (isDemoMode()) return demo.fetchRuleUpdateStatus() as unknown as UpdateStatus;
  return req('/api/rules/update/status');
}

export interface SuricataImportResult {
  status:         string;
  files_imported: string[];
  rules_count:    number;
  reload:         string;
  note?:          string | null;
}

// ── Host-Connection-View ─────────────────────────────────────────────────────

export type HostConnectionWindow = '15m' | '1h' | '6h' | '24h';

export interface HostConnectionPeer {
  ip:            string;
  direction:     'in' | 'out' | 'both';
  flow_count:    number;
  total_bytes:   number;
  bytes_in:      number;
  bytes_out:     number;
  top_ports:     { port: number; proto: string; count: number }[];
  alert_count:   number;
  max_severity:  'low' | 'medium' | 'high' | 'critical' | null;
}

export interface HostConnectionHistogramBucket {
  ts:    number;
  flows: number;
  bytes: number;
}

export interface HostConnectionsResponse {
  ip:           string;
  window:       HostConnectionWindow;
  window_sec:   number;
  window_start: number;
  window_end:   number;
  bucket_sec:   number;
  peers:        HostConnectionPeer[];
  histogram:    HostConnectionHistogramBucket[];
}

export async function fetchHostConnections(
  ip:     string,
  window: HostConnectionWindow,
  until?: number,
): Promise<HostConnectionsResponse> {
  const p = new URLSearchParams({ window });
  if (until) p.set('until', String(until));
  return req(`/api/hosts/${encodeURIComponent(ip)}/connections?${p}`);
}

export interface RuleFileMeta {
  name:     string;
  size:     number;
  rules:    number;
  modified: number;
  builtin:  boolean;
}

export interface RuleFileContent {
  name:    string;
  content: string;
  size:    number;
  rules:   number;
}

export interface RuleFileSaveResponse {
  name:        string;
  saved:       boolean;
  rules_count: number;
  test_ok:     boolean;
  test_output?: string | null;
  reload:      string;
  note?:       string | null;
}

export async function fetchRuleFiles(): Promise<RuleFileMeta[]> {
  return req('/api/rules/files');
}

export async function fetchRuleFile(name: string): Promise<RuleFileContent> {
  return req(`/api/rules/files/${encodeURIComponent(name)}`);
}

export async function saveRuleFile(name: string, content: string): Promise<RuleFileSaveResponse> {
  return req(`/api/rules/files/${encodeURIComponent(name)}`, {
    method: 'PUT',
    body:   JSON.stringify({ content }),
  });
}

export async function deleteRuleFile(name: string): Promise<void> {
  await req(`/api/rules/files/${encodeURIComponent(name)}`, { method: 'DELETE' });
}

// `req()` darf nicht verwendet werden – es setzt Content-Type: application/json
// und überschreibt damit den vom Browser für FormData generierten Header
// (multipart/form-data; boundary=…). Daher direkter fetch() mit Bearer-Header.
export async function importSuricataRules(file: File): Promise<SuricataImportResult> {
  const token = getToken();
  const fd = new FormData();
  fd.append('file', file, file.name);
  const res = await fetch(`${BASE}/api/rules/suricata/import`, {
    method:  'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body:    fd,
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
  return res.json();
}

// ── SAML Config ───────────────────────────────────────────────────────────────

const SAML_DEFAULTS: SamlConfig = {
  enabled: false,
  idp_entity_id: '', idp_sso_url: '', idp_slo_url: '', idp_x509_cert: '',
  sp_entity_id: '', acs_url: '', slo_url: '',
  attribute_username: 'uid', attribute_email: 'email',
  attribute_display_name: 'displayName', default_role: 'viewer',
};

export async function fetchSamlConfig(): Promise<SamlConfig> {
  if (isDemoMode()) return { ...SAML_DEFAULTS };
  try {
    const r = await req<{ key: string; value: SamlConfig }>('/api/config/saml');
    return { ...SAML_DEFAULTS, ...r.value };
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return { ...SAML_DEFAULTS };
    throw e;
  }
}

export async function fetchSamlEnabled(): Promise<{ enabled: boolean; login_url: string }> {
  try {
    const r = await fetch('/api/auth/saml/enabled');
    if (!r.ok) return { enabled: false, login_url: '' };
    return r.json();
  } catch { return { enabled: false, login_url: '' }; }
}

// ── IRMA Config ───────────────────────────────────────────────────────────────

export async function fetchIrmaConfig(): Promise<import('./types').IrmaConfig> {
  if (isDemoMode()) return {
    enabled: false, base_url: 'https://10.133.168.115/rest',
    user: 'demo-irma', password: '', poll_interval: 30, ssl_verify: false,
  };
  try {
    const r = await req<{ key: string; value: import('./types').IrmaConfig }>('/api/config/irma');
    return r.value;
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) {
      return { enabled: false, base_url: 'https://10.133.168.115/rest', user: '', password: '', poll_interval: 30, ssl_verify: false };
    }
    throw e;
  }
}

export async function saveIrmaConfig(value: import('./types').IrmaConfig): Promise<void> {
  if (isDemoMode()) return;
  await req('/api/config/irma', {
    method: 'PATCH',
    body: JSON.stringify({ value }),
  });
}

export async function saveSamlConfig(value: SamlConfig): Promise<void> {
  await req('/api/config/saml', { method: 'PATCH', body: JSON.stringify({ value }) });
}

// ── iTop CMDB ─────────────────────────────────────────────────────────────────

const ITOP_DEFAULT: import('./types').ItopConfig = {
  enabled: false, base_url: '', user: '', password: '', org_filter: '', ssl_verify: false,
};

export async function fetchItopConfig(): Promise<import('./types').ItopConfig> {
  if (isDemoMode()) return { ...ITOP_DEFAULT };
  try {
    const r = await req<{ key: string; value: import('./types').ItopConfig }>('/api/config/itop');
    return r.value;
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return { ...ITOP_DEFAULT };
    throw e;
  }
}

export async function saveItopConfig(value: import('./types').ItopConfig): Promise<void> {
  if (isDemoMode()) return;
  await req('/api/config/itop', { method: 'PATCH', body: JSON.stringify({ value }) });
}

export async function testItopConnection(): Promise<{ ok: boolean; organisations: string[] }> {
  return req('/api/itop/test', { method: 'POST' });
}

export async function triggerItopSync(): Promise<void> {
  await req('/api/itop/sync', { method: 'POST' });
}

export async function getItopSyncStatus(): Promise<import('./types').ItopSyncState> {
  return req('/api/itop/sync/status');
}

// ── SSL / TLS ─────────────────────────────────────────────────────────────────

export interface SslStatus {
  mode: 'none' | 'upload' | 'self-signed' | 'acme';
  active: boolean;
  subject?: string;
  issuer?: string;
  not_after?: string;
  domains?: string[];
  acme_email?: string;
  acme_ca?: string;
  hostname?: string;
}

export interface SslSelfSignedRequest {
  common_name: string;
  days: number;
  country?: string;
  org?: string;
}

export interface SslAcmeConfig {
  domains: string[];
  email: string;
  ca_url?: string;
}

export async function fetchSslStatus(): Promise<SslStatus> {
  if (isDemoMode()) return demo.fetchSslStatus() as unknown as SslStatus;
  return req('/api/ssl/status');
}

export async function applySslSelfSigned(cfg: SslSelfSignedRequest): Promise<SslStatus> {
  return req('/api/ssl/self-signed', { method: 'POST', body: JSON.stringify(cfg) });
}

export async function applySslAcme(cfg: SslAcmeConfig): Promise<SslStatus> {
  return req('/api/ssl/acme', { method: 'POST', body: JSON.stringify(cfg) });
}

export async function uploadSslCert(cert: File, key: File, ca?: File): Promise<SslStatus> {
  const token = getToken();
  const fd = new FormData();
  fd.append('cert', cert);
  fd.append('key', key);
  if (ca) fd.append('ca', ca);
  const res = await fetch(`${BASE}/api/ssl/upload`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: fd,
  });
  if (!res.ok) { const t = await res.text().catch(() => ''); throw new Error(`${res.status}: ${t}`); }
  return res.json();
}

export async function uploadSslPfx(pfx: File, password: string): Promise<SslStatus> {
  const token = getToken();
  const fd = new FormData();
  fd.append('pfx', pfx);
  fd.append('password', password);
  const res = await fetch(`${BASE}/api/ssl/upload-pfx`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: fd,
  });
  if (!res.ok) { const t = await res.text().catch(() => ''); throw new Error(`${res.status}: ${t}`); }
  return res.json();
}

export async function setSslHostname(hostname: string): Promise<{ hostname: string }> {
  return req('/api/ssl/hostname', { method: 'POST', body: JSON.stringify({ hostname }) });
}

// ── Syslog ────────────────────────────────────────────────────────────────────

export interface SyslogConfig {
  enabled:      boolean;
  host:         string;
  port:         number;
  protocol:     'udp' | 'tcp';
  format:       'rfc5424' | 'cef' | 'leef';
  min_severity: 'low' | 'medium' | 'high' | 'critical';
}

export interface SyslogTestRequest {
  host:     string;
  port:     number;
  protocol: 'udp' | 'tcp';
  format:   'rfc5424' | 'cef' | 'leef';
}

export async function fetchSyslogConfig(): Promise<SyslogConfig> {
  if (isDemoMode()) return demo.fetchSyslogConfig() as unknown as SyslogConfig;
  return req('/api/syslog/config');
}

export async function saveSyslogConfig(cfg: SyslogConfig): Promise<SyslogConfig> {
  return req('/api/syslog/config', { method: 'PATCH', body: JSON.stringify(cfg) });
}

export async function testSyslog(body: SyslogTestRequest): Promise<{ status: string; message: string }> {
  return req('/api/syslog/test', { method: 'POST', body: JSON.stringify(body) });
}

// ── System-Update ─────────────────────────────────────────────────────────────

export async function startSystemUpdate(file: File, pullImages: boolean): Promise<{ status: string }> {
  const token = getToken();
  const fd = new FormData();
  fd.append('file', file);
  fd.append('pull_images', String(pullImages));
  const res = await fetch(`${BASE}/api/system/update`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: fd,
  });
  if (!res.ok) { const t = await res.text().catch(() => ''); throw new Error(`${res.status}: ${t}`); }
  return res.json();
}

export async function fetchSystemUpdateStatus(): Promise<SystemUpdateStatus> {
  if (isDemoMode()) return { phase: 'idle', log: [], progress: 0, started_at: null, finished_at: null };
  return req<SystemUpdateStatus>('/api/system/update/status');
}

export async function restartStack(): Promise<{ status: string }> {
  if (isDemoMode()) return { status: 'started' };
  return req('/api/system/restart', { method: 'POST' });
}

export async function getInterfaces(): Promise<import('./types').InterfaceInfo[]> {
  if (isDemoMode()) return [
    { name: 'eth0', role: 'management', operstate: 'up', addresses: ['192.168.1.100/24'], mac: '00:11:22:33:44:55' },
    { name: 'eth1', role: 'sniffer',    operstate: 'up', addresses: [],                  mac: '00:11:22:33:44:56' },
  ];
  return req('/api/system/interfaces');
}

export async function setInterfaceRole(
  role: 'sniffer' | 'management',
  iface: string,
): Promise<{ status: string; note?: string }> {
  if (isDemoMode()) return { status: 'saved' };
  // `headers` bewusst nicht setzen – req() ergänzt Content-Type und
  // Authorization eh, ein eigenes headers-Objekt würde die jetzt sauber
  // gemergten Defaults aushebeln (siehe req()-Kommentar).
  return req('/api/system/interfaces/config', {
    method: 'POST',
    body: JSON.stringify({ role, iface }),
  });
}

export interface SystemStats {
  cpu_pct:  number | null;
  mem:      { total_mb: number; used_mb: number; pct: number | null };
  disk:     { total_gb: number; used_gb: number; pct: number | null };
  net:      { rx_bps: number | null; tx_bps: number | null; rx_pps: number | null; tx_pps: number | null; rx_dropped: number } | null;
  sniffer:  { pps: number | null; drop_pct: number | null; total_captured: number; total_dropped: number; kafka_errors: number };
  iface:    string;
}

export async function fetchSystemStats(): Promise<SystemStats> {
  if (isDemoMode()) return {
    cpu_pct: 23.4, iface: 'eth1',
    mem:     { total_mb: 16384, used_mb: 6800, pct: 41.5 },
    disk:    { total_gb: 500, used_gb: 120, pct: 24.0 },
    net:     { rx_bps: 12500000, tx_bps: 800000, rx_pps: 1200, tx_pps: 80, rx_dropped: 0 },
    sniffer: { pps: 1200, drop_pct: 0.0, total_captured: 5000000, total_dropped: 0, kafka_errors: 0 },
  };
  return req('/api/system/stats');
}

export interface LearnedPattern {
  rule_id:         string;
  src_ip:          string;
  dst_ip:          string;
  source:          'manual' | 'learned';  // manual = User hat FP markiert
  mean_h:          number;   // Baseline: mittlere Alerts pro Stunde
  std_h:           number;   // Baseline: Standardabweichung
  hours_with_data: number;   // Datenpunkte in der Baseline
  total_baseline:  number;   // Summe der Baseline-Alerts
  recent_1h:       number;   // Aktuelle Rate (letzte Stunde)
  z_score:         number;   // (recent - mean) / std
  suppressed:      boolean;  // z_score < threshold
  first_seen:      string | null;
  last_seen:       string | null;
}

export interface LearnedPatternsResponse {
  config: { window_days: number; min_hours: number; z_threshold: number };
  patterns: LearnedPattern[];
}

export async function fetchLearnedPatterns(): Promise<LearnedPatternsResponse> {
  if (isDemoMode()) return {
    config: { window_days: 14, min_hours: 24, z_threshold: 2.0 },
    patterns: [
      { rule_id: 'DOS_UDP_001', src_ip: '10.0.0.12', dst_ip: '192.168.2.50', source: 'manual',
        mean_h: 8.4, std_h: 2.1, hours_with_data: 96, total_baseline: 806,
        recent_1h: 9, z_score: 0.29, suppressed: true,
        first_seen: new Date(Date.now() - 5*86400000).toISOString(), last_seen: new Date().toISOString() },
      { rule_id: 'ANOMALY_HOST_001', src_ip: '10.0.0.55', dst_ip: '192.168.1.1', source: 'manual',
        mean_h: 3.2, std_h: 1.8, hours_with_data: 72, total_baseline: 230,
        recent_1h: 18, z_score: 8.22, suppressed: false,
        first_seen: new Date(Date.now() - 4*86400000).toISOString(), last_seen: new Date().toISOString() },
      { rule_id: 'DNS_QUERY_001', src_ip: '10.0.1.10', dst_ip: '8.8.8.8', source: 'learned',
        mean_h: 24.0, std_h: 6.5, hours_with_data: 180, total_baseline: 4320,
        recent_1h: 26, z_score: 0.31, suppressed: true,
        first_seen: new Date(Date.now() - 8*86400000).toISOString(), last_seen: new Date().toISOString() },
    ],
  };
  return req('/api/ml/learned-patterns');
}

// ── Datenbank-Wartung ─────────────────────────────────────────────────────────

export interface DbTableStat {
  name:       string;
  rows:       number;
  size_bytes: number;
  oldest:     string | null;
  newest:     string | null;
}

export interface DbHypertable {
  name:       string;
  size_bytes: number;
  chunks:     number;
}

export interface DbRetentionPolicy {
  hypertable: string;
  config:     Record<string, unknown>;
}

export interface DbStatsResponse {
  db_size_bytes: number;
  tables:        DbTableStat[];
  hypertables:   DbHypertable[];
  retention:     DbRetentionPolicy[];
}

export interface MaintenanceAuditEntry {
  id:          number;
  ts:          string;
  username:    string;
  action:      string;
  params:      Record<string, unknown> | null;
  result:      Record<string, unknown> | null;
  success:     boolean;
  error_msg:   string | null;
  duration_ms: number;
}

export async function fetchDbStats(): Promise<DbStatsResponse> {
  return req('/api/maintenance/stats');
}

export async function cleanupDb(body: {
  password:        string;
  target:          'alerts' | 'flows' | 'training_samples' | 'test_runs' | 'all';
  older_than_days?: number;
  only_test?:       boolean;
}): Promise<{ success: boolean; deleted: number; details: Record<string, unknown>; duration_ms: number }> {
  return req('/api/maintenance/cleanup', {
    method: 'POST',
    body:   JSON.stringify(body),
  });
}

export async function vacuumDb(body: {
  password: string;
  full?:    boolean;
  analyze?: boolean;
  table?:   string;
}): Promise<{ success: boolean; sql: string; duration_ms: number }> {
  return req('/api/maintenance/vacuum', {
    method: 'POST',
    body:   JSON.stringify({ full: false, analyze: true, ...body }),
  });
}

export async function setRetentionPolicy(body: {
  password:   string;
  hypertable: string;
  days:       number | null;
}): Promise<{ success: boolean; message: string }> {
  return req('/api/maintenance/retention', {
    method: 'PATCH',
    body:   JSON.stringify(body),
  });
}

export function backupDbUrl(): string {
  return `${BASE}/api/maintenance/backup`;
}

export async function restoreDb(password: string, file: File): Promise<{ success: boolean; duration_ms: number; bytes: number }> {
  const fd = new FormData();
  fd.append('password', password);
  fd.append('dump',     file);
  const token = getToken();
  const res = await fetch(`${BASE}/api/maintenance/restore`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body:    fd,
  });
  if (!res.ok) {
    const txt = await res.text().catch(() => '');
    throw new Error(`${res.status}: ${txt}`);
  }
  return res.json();
}

export async function fetchMaintenanceAudit(limit = 100): Promise<MaintenanceAuditEntry[]> {
  return req(`/api/maintenance/audit?limit=${limit}`);
}
