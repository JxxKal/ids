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

// ── Auth ───────────────────────────────────────────────────────────────────

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

// ── Alerts ─────────────────────────────────────────────────────────────────────

export interface AlertFilters {
  severity?: string;
  source?: string;
  rule_id?: string;
  src_ip?: string;
  ts_from?: number;   // Unix-Timestamp (Sekunden)
  ts_to?: number;
  is_test?: boolean | null;  // null = alle (kein Filter)
  // Egress-Boundary
  egress_only?: boolean;
  show_whitelisted?: boolean;
  boundary_priority?: 'P0' | 'P1' | 'P2' | 'P3';
  sort_by?: 'ts' | 'priority';
  // Tap-Filter: '' = alle, 'master' = nur Master-lokal (tap_id IS NULL),
  // sonst UUID des Taps. Server-side angewandt; clientseitiger Filter im
  // Live-Mode ergänzt das (WebSocket broadcastet alle Alerts).
  tap_id?: string;
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
  if (filters.egress_only)        params.set('egress_only',      'true');
  if (filters.show_whitelisted)   params.set('show_whitelisted', 'true');
  if (filters.boundary_priority)  params.set('boundary_priority', filters.boundary_priority);
  if (filters.sort_by)            params.set('sort_by',           filters.sort_by);
  if (filters.tap_id)             params.set('tap_id',            filters.tap_id);
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

// ── Threat Level ───────────────────────────────────────────────────────────

export async function fetchThreatLevel(): Promise<ThreatLevel> {
  if (isDemoMode()) return demo.fetchThreatLevel();
  return req('/api/stats/threat-level');
}

// ── Networks ───────────────────────────────────────────────────────────────

export async function fetchNetworks(): Promise<KnownNetwork[]> {
  if (isDemoMode()) return demo.fetchNetworks();
  return req('/api/networks');
}

export async function createNetwork(data: {
  cidr: string;
  name: string;
  description?: string;
  color?: string;
  kind?: 'ot' | 'it';
}): Promise<KnownNetwork> {
  return req('/api/networks', { method: 'POST', body: JSON.stringify(data) });
}

export async function updateNetwork(id: string, data: {
  name?: string;
  description?: string;
  color?: string;
  kind?: 'ot' | 'it';
}): Promise<KnownNetwork> {
  return req(`/api/networks/${id}`, { method: 'PATCH', body: JSON.stringify(data) });
}

export async function deleteNetwork(id: string): Promise<void> {
  await req(`/api/networks/${id}`, { method: 'DELETE' });
}

// Massenlöschen — admin-only. Ohne kind-Filter werden ALLE Netze gelöscht
// (Recovery-Pfad nach fehlerhaftem Import). Frontend muss vorher confirmen.
export async function bulkDeleteNetworks(kind?: 'ot' | 'it'): Promise<{ deleted: number; kind_filter: 'ot' | 'it' | null }> {
  const qs = kind ? `?kind=${kind}` : '';
  return req(`/api/networks${qs}`, { method: 'DELETE' });
}

// ── Hosts ──────────────────────────────────────────────────────────────────

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

export async function importNetworksCsv(file: File): Promise<{ imported: number; skipped: number; skipped_ot_priority?: number; errors: string[] }> {
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

// ── Tests ──────────────────────────────────────────────────────────────────

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

// ── Users ──────────────────────────────────────────────────────────────────

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

// ── Rules Engine ───────────────────────────────────────────────────────────

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
  name:          string;
  size:          number;
  rules:         number;
  modified:      number;
  builtin:       boolean;
  ai_rule_count: number;
}

export interface RuleFileContent {
  name:          string;
  content:       string;
  size:          number;
  rules:         number;
  ai_rule_count: number;
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
  if (isDemoMode()) return [];
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

// ── MQTT-Bridge Config ────────────────────────────────────────────────────────

const MQTT_DEFAULT: import('./types').MqttConfig = {
  enabled:                false,
  broker_host:            'mosquitto.example.com',
  broker_port:            8883,
  use_tls:                true,
  tls_verify:             true,
  username:               'cyjan',
  password:               '',
  client_id:              '',
  master_host_id:         'master',
  topic_prefix:           'cyjan',
  qos_events:             1,
  qos_state:              0,
  rate_limit_per_sec:     200,
  inflight_max:           10,
  threat_publish_interval_s: 30,
  tap_publish_interval_s: 30,
  severity_min:           'low',
  sources_allowed:        ['signature', 'ml', 'suricata', 'external'],
  rule_id_blocklist:      [],
};

export async function fetchMqttConfig(): Promise<import('./types').MqttConfig> {
  if (isDemoMode()) return MQTT_DEFAULT;
  try {
    const r = await req<{ key: string; value: import('./types').MqttConfig }>('/api/config/mqtt');
    return { ...MQTT_DEFAULT, ...r.value };
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return MQTT_DEFAULT;
    throw e;
  }
}

export async function saveMqttConfig(value: import('./types').MqttConfig): Promise<void> {
  if (isDemoMode()) return;
  await req('/api/config/mqtt', {
    method: 'PATCH',
    body: JSON.stringify({ value }),
  });
}

export async function testMqttConnection(value: import('./types').MqttConfig): Promise<import('./types').MqttTestResult> {
  if (isDemoMode()) return { ok: true, duration_ms: 42, test_topic: `${value.topic_prefix}/${value.master_host_id}/test` };
  return await req<import('./types').MqttTestResult>('/api/mqtt/test', {
    method: 'POST',
    body: JSON.stringify({
      broker_host:    value.broker_host,
      broker_port:    value.broker_port,
      use_tls:        value.use_tls,
      tls_verify:     value.tls_verify,
      username:       value.username,
      password:       value.password,
      client_id:      value.client_id,
      topic_prefix:   value.topic_prefix,
      master_host_id: value.master_host_id,
    }),
  });
}

export async function saveSamlConfig(value: SamlConfig): Promise<void> {
  await req('/api/config/saml', { method: 'PATCH', body: JSON.stringify({ value }) });
}

// ── DNS-Resolver-Allowlist ─────────────────────────────────────────────────────

export interface DnsResolversConfig { resolvers: string[] }

export async function fetchDnsResolvers(): Promise<DnsResolversConfig> {
  if (isDemoMode()) return { resolvers: [] };
  try {
    const r = await req<{ key: string; value: DnsResolversConfig }>('/api/config/dns_resolvers');
    return { resolvers: Array.isArray(r.value?.resolvers) ? r.value.resolvers : [] };
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return { resolvers: [] };
    throw e;
  }
}

export async function saveDnsResolvers(value: DnsResolversConfig): Promise<void> {
  if (isDemoMode()) return;
  await req('/api/config/dns_resolvers', { method: 'PATCH', body: JSON.stringify({ value }) });
}

// ── Signature-Engine YAML-Regeln + Per-Regel-Overrides ───────────────────────

export interface SigRuleParamSchema {
  type:    'int' | 'float';
  default: number;
  min:     number | null;
  max:     number | null;
  label:   string;
  // Phase 2: symbolischer Name der Counting-Funktion (unique_dst_ports etc.).
  // Frontend nutzt das nur als Marker "ML-tunbar".
  metric:  string | null;
}

// Phase 1+ Object-Form mit Provenance + scope-Split.
export interface SigRuleParamOverride {
  value:           number;
  value_internal:  number | null;
  source:          'manual' | 'ml' | null;
  ml:              Record<string, unknown> | null;
}

export interface SigRuleEntry {
  id:                  string;
  name:                string;
  description:         string;
  severity:            string;
  severity_default:    string;
  tags:                string[];
  file:                string;
  builtin:             boolean;
  enabled:             boolean;
  severity_override:   string | null;
  parameters_schema:   Record<string, SigRuleParamSchema>;
  parameters_default:  Record<string, number>;
  parameters:          Record<string, number>;          // effektiv (default ⊕ override, Skalar)
  parameters_override: Record<string, number>;
  // Object-Form mit Provenance — gefüllt für Params mit value_internal/source/ml.
  parameters_full?:    Record<string, SigRuleParamOverride>;
}

export interface SigRuleOverride {
  enabled?:    boolean | null;
  severity?:   'critical' | 'high' | 'medium' | 'low' | null;
  // Backwards-compat: Skalar = manueller Override. Object = Provenance + scope.
  parameters?: Record<string, number | SigRuleParamOverride> | null;
}

export interface SigRulesOverridesResponse {
  overrides: Record<string, SigRuleOverride>;
}

// ── ML-Tuning (Phase 3+4) ────────────────────────────────────────────────────

export interface MlTuningStateBlock {
  state:           'idle' | 'training' | 'tuning' | 'paused';
  started_at:      string | null;
  training_until:  string | null;
  last_tuning_at:  string | null;
  paused_from:     'idle' | 'training' | 'tuning' | null;
}

export interface MlTuningConfigBlock {
  window_s:                    number;
  target_alert_rate_per_hour:  number;
  scope_split_enabled:         boolean;
  quantile:                    number;
  max_change_per_cycle:        number;
  blacklist:                   string[];
}

export interface MlTuningStatus {
  state:          MlTuningStateBlock;
  config:         MlTuningConfigBlock;
  total_samples:  number;
}

export interface MlBaselineEntry {
  rule_id:       string;
  param_name:    string;
  scope:         'internal' | 'external' | 'global';
  p50:           number | null;
  p99:           number | null;
  p995:          number | null;
  p999:          number | null;
  sample_count:  number;
  updated_at:    string;
}

export async function fetchMlStatus(): Promise<MlTuningStatus> {
  if (isDemoMode()) {
    return {
      state: { state: 'idle', started_at: null, training_until: null, last_tuning_at: null, paused_from: null },
      config: { window_s: 36000, target_alert_rate_per_hour: 0.5, scope_split_enabled: true, quantile: 0.995, max_change_per_cycle: 0.20, blacklist: [] },
      total_samples: 0,
    };
  }
  return req<MlTuningStatus>('/api/sig-rules/ml/status');
}

export interface MlStartTrainingPayload {
  window_s?:                    number;
  target_alert_rate_per_hour?:  number;
  scope_split_enabled?:         boolean;
  quantile?:                    number;
  max_change_per_cycle?:        number;
  blacklist?:                   string[];
}

export async function startMlTraining(body: MlStartTrainingPayload): Promise<MlTuningStatus> {
  if (isDemoMode()) return fetchMlStatus();
  return req<MlTuningStatus>('/api/sig-rules/ml/start-training', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function pauseMlTuning(): Promise<MlTuningStatus> {
  if (isDemoMode()) return fetchMlStatus();
  return req<MlTuningStatus>('/api/sig-rules/ml/pause', { method: 'POST' });
}

export async function resumeMlTuning(): Promise<MlTuningStatus> {
  if (isDemoMode()) return fetchMlStatus();
  return req<MlTuningStatus>('/api/sig-rules/ml/resume', { method: 'POST' });
}

export async function fetchMlBaselines(ruleId?: string): Promise<MlBaselineEntry[]> {
  if (isDemoMode()) return [];
  const path = ruleId
    ? `/api/sig-rules/ml/baselines?rule_id=${encodeURIComponent(ruleId)}`
    : '/api/sig-rules/ml/baselines';
  return req<MlBaselineEntry[]>(path);
}

export async function fetchSigRules(): Promise<SigRuleEntry[]> {
  if (isDemoMode()) return [];
  return req<SigRuleEntry[]>('/api/sig-rules/list');
}

export async function fetchSigRulesOverrides(): Promise<SigRulesOverridesResponse> {
  if (isDemoMode()) return { overrides: {} };
  return req<SigRulesOverridesResponse>('/api/sig-rules/overrides');
}

export async function saveSigRulesOverrides(
  overrides: Record<string, SigRuleOverride>,
): Promise<SigRulesOverridesResponse> {
  if (isDemoMode()) return { overrides: {} };
  return req<SigRulesOverridesResponse>('/api/sig-rules/overrides', {
    method: 'PUT',
    body: JSON.stringify({ overrides }),
  });
}

// ── Suricata SID-Overrides ────────────────────────────────────────────────────

export interface SuricataOverrideEntry {
  enabled?:  boolean | null;
  severity?: 'critical' | 'high' | 'medium' | 'low' | null;
}

export interface SuricataOverridesResponse {
  overrides: Record<string, SuricataOverrideEntry>;
}

export async function fetchSuricataOverrides(): Promise<SuricataOverridesResponse> {
  if (isDemoMode()) return { overrides: {} };
  return req<SuricataOverridesResponse>('/api/sig-rules/suricata-overrides');
}

export async function saveSuricataOverrides(
  overrides: Record<string, SuricataOverrideEntry>,
): Promise<SuricataOverridesResponse> {
  if (isDemoMode()) return { overrides: {} };
  return req<SuricataOverridesResponse>('/api/sig-rules/suricata-overrides', {
    method: 'PUT',
    body: JSON.stringify({ overrides }),
  });
}

// ── Egress-Whitelist ───────────────────────────────────────────────────────────

export interface EgressWhitelistEntry {
  id:             string;
  src_ip:         string;
  dst_ip:         string | null;
  dst_net:        string | null;
  dst_port:       number | null;
  proto:          string | null;
  reason:         string;
  created_by:     string | null;
  created_at:     string;
  expires_at:     string | null;
  active:         boolean;
  deactivated_at: string | null;
}

export interface EgressWhitelistCreate {
  src_ip:     string;
  dst_ip?:    string | null;
  dst_net?:   string | null;
  dst_port?:  number | null;
  proto?:     'TCP' | 'UDP' | 'ICMP' | null;
  reason:     string;
  expires_at?: string | null;
}

export async function fetchEgressWhitelist(includeInactive = false): Promise<EgressWhitelistEntry[]> {
  if (isDemoMode()) return [];
  const qs = includeInactive ? '?include_inactive=true' : '';
  return req<EgressWhitelistEntry[]>(`/api/egress-whitelist${qs}`);
}

export async function createEgressWhitelist(body: EgressWhitelistCreate): Promise<EgressWhitelistEntry> {
  if (isDemoMode()) return Promise.reject(new Error('Demo mode'));
  return req<EgressWhitelistEntry>('/api/egress-whitelist', {
    method: 'POST',
    body: JSON.stringify(body),
  });
}

export async function deactivateEgressWhitelist(id: string): Promise<EgressWhitelistEntry> {
  if (isDemoMode()) return Promise.reject(new Error('Demo mode'));
  return req<EgressWhitelistEntry>(`/api/egress-whitelist/${encodeURIComponent(id)}/deactivate`, {
    method: 'PATCH',
  });
}

// ── Boundary-Priority-Map (system_config) ────────────────────────────────────

export type BoundaryPriorityMap = Record<string, string | null>;

export async function fetchBoundaryPriorityMap(): Promise<BoundaryPriorityMap | null> {
  if (isDemoMode()) return null;
  try {
    const r = await req<{ key: string; value: BoundaryPriorityMap }>('/api/config/boundary_priority_map');
    return r.value && typeof r.value === 'object' ? r.value : null;
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return null;
    throw e;
  }
}

export async function saveBoundaryPriorityMap(value: BoundaryPriorityMap): Promise<void> {
  if (isDemoMode()) return;
  await req('/api/config/boundary_priority_map', { method: 'PATCH', body: JSON.stringify({ value }) });
}

// V2 (Phase B+C): zone-basierte 3×3-Matrix. Schlüssel "<src_zone>/<dst_zone>"
// mit zone ∈ {ot, it, internet}. Diagonale (gleiche Zone) ist null per
// Default — kein Alert für In-Zone-Traffic.
export type BoundaryPriorityMapV2 = Record<string, string | null>;

export async function fetchBoundaryPriorityMapV2(): Promise<BoundaryPriorityMapV2 | null> {
  if (isDemoMode()) return null;
  try {
    const r = await req<{ key: string; value: BoundaryPriorityMapV2 }>('/api/config/boundary_priority_map_v2');
    return r.value && typeof r.value === 'object' ? r.value : null;
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return null;
    throw e;
  }
}

export async function saveBoundaryPriorityMapV2(value: BoundaryPriorityMapV2): Promise<void> {
  if (isDemoMode()) return;
  await req('/api/config/boundary_priority_map_v2', { method: 'PATCH', body: JSON.stringify({ value }) });
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

// ── SSL / TLS ────────────────────────────────────────────────────────────────

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

// ── Syslog ───────────────────────────────────────────────────────────────────

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

export interface SystemUpdateStartResponse {
  status:   string;
  // Nur gefüllt seit dem Backend-Version-Check (v1.5.2+):
  incoming?: string;
  current?:  string;
}

export async function startSystemUpdate(
  file: File,
  pullImages: boolean,
  force: boolean = false,
  onProgress?: (pct: number) => void,
): Promise<SystemUpdateStartResponse> {
  // XHR statt fetch() weil fetch() keine Upload-Progress-Events anbietet.
  // Wir wollen aber die Progress-Bar im UI füllen können während der
  // multipart-Body über die Wire geht — bei einem 1+ GB Update-ZIP über ein
  // entferntes Netz dauert das gerne mal 30+ Sekunden.
  const token = getToken();
  const fd = new FormData();
  fd.append('file', file);
  fd.append('pull_images', String(pullImages));
  if (force) fd.append('force', 'true');
  return new Promise<SystemUpdateStartResponse>((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `${BASE}/api/system/update`);
    if (token) xhr.setRequestHeader('Authorization', `Bearer ${token}`);
    if (onProgress) {
      xhr.upload.onprogress = e => {
        if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100));
      };
    }
    xhr.onload = () => {
      if (xhr.status === 401) {
        clearToken();
        window.dispatchEvent(new Event('ids:unauthorized'));
        reject(new Error('401 Unauthorized'));
        return;
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        try {
          resolve(JSON.parse(xhr.responseText));
        } catch (e) {
          reject(new Error(`Antwort nicht parsebar: ${e instanceof Error ? e.message : String(e)}`));
        }
      } else {
        // Body als Error-Message durchreichen — UI macht Force-Retry-Heuristik
        // anhand 400 + 'Downgrade'/'kein Update notwendig' im Text.
        reject(new Error(`${xhr.status}: ${xhr.responseText || xhr.statusText}`));
      }
    };
    xhr.onerror = () => reject(new Error('Netzwerkfehler beim Upload'));
    xhr.onabort = () => reject(new Error('Upload abgebrochen'));
    xhr.send(fd);
  });
}

export async function fetchSystemUpdateStatus(): Promise<SystemUpdateStatus> {
  if (isDemoMode()) return { phase: 'idle', log: [], progress: 0, started_at: null, finished_at: null };
  return req<SystemUpdateStatus>('/api/system/update/status');
}

export async function fetchVersion(): Promise<{ version: string }> {
  if (isDemoMode()) return { version: 'demo' };
  return req<{ version: string }>('/api/system/version');
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

// ── Datenbank-Wartung ───────────────────────────────────────────────────────────

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

// ── PCAP-Retention (MinIO Lifecycle für ids-pcaps Bucket) ────────────────

export interface PcapRetentionState {
  persisted_days: number | null;   // aus system_config (UI-Override)
  active_days:    number | null;   // aus MinIO-Bucket (real)
  default_days:   number;          // PCAP_RETENTION_DAYS env-Var
  bucket: {
    name:            string;
    object_count:    number;
    total_gb:        number;
    oldest_iso:      string | null;
    oldest_age_days: number | null;
  };
}

export async function fetchPcapRetention(): Promise<PcapRetentionState> {
  return req('/api/maintenance/pcap-retention');
}

export async function setPcapRetention(days: number): Promise<{
  success: boolean; days: number; active_days: number | null; message: string;
}> {
  return req('/api/maintenance/pcap-retention', {
    method: 'PATCH',
    body:   JSON.stringify({ days }),
  });
}

export async function forcePcapCleanup(days: number): Promise<{
  success: boolean; deleted: number; bytes_freed: number; message: string;
}> {
  return req('/api/maintenance/pcap-cleanup', {
    method: 'POST',
    body:   JSON.stringify({ days }),
  });
}

export async function triggerTapPushUpdate(tapId: string): Promise<{ queued: boolean; tap_id: string }> {
  return req(`/api/taps/${tapId}/trigger-update`, { method: 'POST' });
}

// ── Tap-Update-Bundle (Master-side) ──────────────────────────────────────

export interface TapUpdateStatus {
  bundle_present:    boolean;
  bundle_size_bytes: number | null;
  bundle_size_mb:    number | null;
  manifest_version:  string | null;
  manifest_created:  string | null;
  manifest_sha256:   string | null;
  refresh_running:   boolean;
  refresh_last_ok:   boolean | null;
  refresh_started:   number;
  refresh_finished:  number;
  refresh_log_tail:  string[];
}

export async function fetchTapUpdateStatus(): Promise<TapUpdateStatus> {
  return req('/api/tap-update');
}

export async function triggerTapUpdateRefresh(): Promise<{ started: boolean; started_at: number }> {
  return req('/api/tap-update/refresh', { method: 'POST' });
}

// ── Remote Taps ───────────────────────────────────────────────────────────

export async function fetchTaps(): Promise<RemoteTap[]> {
  if (isDemoMode()) return [];
  return req('/api/taps');
}

export async function createTapPairingToken(body: {
  name:   string;
  site?:  string;
  ttl_min?: number;
}): Promise<RemoteTapPairingToken> {
  return req('/api/taps/pairing-tokens', {
    method: 'POST',
    body:   JSON.stringify(body),
  });
}

export async function revokeTap(id: string): Promise<void> {
  await req(`/api/taps/${id}`, { method: 'DELETE' });
}

// ── Auto-Pairing: Pending-Liste, Approve/Reject, Audit-Log ───────────────────────

export interface PendingTap {
  id:           string;
  name:         string;
  hardware_id:  string;
  source_ip:    string;
  hostname:     string | null;
  version:      string | null;
  fingerprint:  string;
  announced_at: string;   // ISO
  status:       string;
}

export interface TapAuditEntry {
  id:           number;
  ts:           string;   // ISO
  event:        string;   // announce | approved | rejected | rejected_ip_not_private | rejected_ip_not_known | rejected_rate_limit | poll | rejected_csr_invalid
  source_ip:    string | null;
  hardware_id:  string | null;
  name:         string | null;
  pending_id:   string | null;
  details:      Record<string, unknown>;
}

export async function fetchPendingTaps(): Promise<PendingTap[]> {
  if (isDemoMode()) return [];
  return req('/api/taps/pending');
}

export async function approvePendingTap(
  id: string,
  body: { name?: string; site?: string } = {},
): Promise<{ tap_id: string; name: string; expires_at: string }> {
  return req(`/api/taps/pending/${id}/approve`, {
    method: 'POST',
    body:   JSON.stringify(body),
  });
}

export async function rejectPendingTap(id: string): Promise<void> {
  await req(`/api/taps/pending/${id}/reject`, { method: 'POST' });
}

export async function fetchTapAuditLog(limit = 200): Promise<TapAuditEntry[]> {
  if (isDemoMode()) return [];
  return req(`/api/taps/audit-log?limit=${limit}`);
}

// ── GeoIP-Datenbanken ────────────────────────────────────────────────────────

export interface GeoIpFileMeta {
  present: boolean;
  size:    number;
  mtime:   string | null;
  valid:   boolean;
}

export interface GeoIpStatus {
  geoip_dir: string;
  city:      GeoIpFileMeta;
  asn:       GeoIpFileMeta;
}

export async function fetchGeoIpStatus(): Promise<GeoIpStatus> {
  if (isDemoMode()) {
    return {
      geoip_dir: '/opt/ids/geoip',
      city: { present: true, size: 131_000_000, mtime: new Date(Date.now() - 3 * 86400e3).toISOString(), valid: true },
      asn:  { present: true, size:   9_500_000, mtime: new Date(Date.now() - 3 * 86400e3).toISOString(), valid: true },
    };
  }
  return req<GeoIpStatus>('/api/system/geoip/status');
}

export async function uploadGeoIp(city: File | null, asn: File | null): Promise<{ status: string; written: string[]; message: string }> {
  if (isDemoMode()) return { status: 'ok', written: [], message: 'demo' };
  const fd = new FormData();
  if (city) fd.append('city', city, city.name);
  if (asn)  fd.append('asn',  asn,  asn.name);
  const token = getToken();
  const res = await fetch(`${BASE}/api/system/geoip/upload`, {
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
    const txt = await res.text().catch(() => '');
    throw new Error(`${res.status}: ${txt}`);
  }
  return res.json();
}

// ── Weekly Report ───────────────────────────────────────────────────────────

export interface WeeklyReportTrend {
  prev:       number;
  delta_pct:  number | null;
  direction:  'up' | 'down' | 'flat';
}

export interface WeeklyReportSummary {
  alerts_total:       number;
  alerts_total_trend: WeeklyReportTrend;
  by_severity:        { critical: number; high: number; medium: number; low: number };
  by_severity_prev:   { critical: number; high: number; medium: number; low: number };
  headline:           string;
}

export interface WeeklyReportDay {
  date:     string;  // YYYY-MM-DD
  critical: number;
  high:     number;
  medium:   number;
  low:      number;
}

export interface WeeklyReportTopRule {
  rule_id:     string;
  source:      string;
  severity:    string;
  description: string | null;
  count:       number;
}

export interface WeeklyReportTopSource {
  src_ip:       string;
  display_name: string | null;
  hostname:     string | null;
  max_severity: string | null;
  count:        number;
}

export interface WeeklyReportTopDest {
  dst_ip:       string;
  country:      string | null;
  country_code: string | null;
  asn:          string | null;
  count:        number;
}

export interface WeeklyReportTap {
  id:          string;
  name:        string;
  site:        string | null;
  status:      string;
  last_seen:   string | null;
  alerts_week: number;
}

// OT-/IT-Boundary-Breaches: Top-Talker Richtung unbekannter Netze (also
// boundary_net_known != true), exkl. whitelist-suppressed Alerts.
export interface WeeklyReportBoundaryTalker {
  src_ip:       string;
  display_name: string | null;
  hostname:     string | null;
  count:        number;
  top_priority: 'P0' | 'P1' | 'P2' | 'P3' | null;
}

export interface WeeklyReportBoundaryPair {
  src_ip:           string;
  dst_ip:           string;
  dst_country:      string | null;
  dst_country_code: string | null;
  dst_asn:          string | null;
  count:            number;
  top_priority:     'P0' | 'P1' | 'P2' | 'P3' | null;
}

export interface WeeklyReportBoundary {
  total:       number;
  by_priority: { P0: number; P1: number; P2: number; P3: number };
  whitelisted: number;
  top_talkers: WeeklyReportBoundaryTalker[];
  top_pairs:   WeeklyReportBoundaryPair[];
  // V2 (Phase C): Zone-Aufschlüsselung. Schlüssel "<src_zone>/<dst_zone>".
  // Pre-V2-Bestandsalerts (vor Migration 017) liegen im 'unzoned'-Counter.
  by_zone?:    Record<string, number>;
  unzoned?:    number;
}

export interface WeeklyReport {
  // archived=true: Snapshot kommt aus MinIO (frozen). archived=false/undefined:
  // live aus DB-Aggregat. Frontend zeigt einen Indikator "Archiv" wenn true.
  week:    { year: number; week: number; from: string; to: string; generated: string; archived?: boolean };
  summary: WeeklyReportSummary;
  detection: {
    daily:              WeeklyReportDay[];
    top_rules:          WeeklyReportTopRule[];
    top_sources:        WeeklyReportTopSource[];
    top_external_dests: WeeklyReportTopDest[];
  };
  ops: {
    taps:               WeeklyReportTap[];
    ml:                 { fp_marked: number; tp_marked: number; tuner_cycles: number };
    suricata_top_sids:  Array<{ sid: string; count: number }>;
  };
  // Optional, weil ältere Archiv-Snapshots aus pre-V2-Zeit das Feld noch
  // nicht haben — UI rendert dann nur fallback "keine Daten".
  boundary?: WeeklyReportBoundary;
  audit: {
    active_users:    Array<{ username: string; last_login: string }>;
    whitelist_adds:  number;
  };
  // Compliance: MITRE-Coverage + Mapping auf NIS-2/ISO27001/BSI.
  // Optional weil ältere Snapshots ohne RedTeam-Pipeline-Plumbing das Feld
  // nicht haben.
  compliance?: WeeklyReportCompliance;
}

export interface ComplianceControl {
  framework:    string;     // "NIS-2" | "ISO-27001" | "BSI"
  control_id:   string;     // "Art-21(2)(i)" / "A.8.5" / "ORP.4.A22"
  control_name: string;
}

export interface ComplianceTechnique {
  technique_id:        string;     // "T1558.004" etc.
  scenarios:           string[];
  run_count:           number;
  detection_count:     number;
  true_positive_rate:  number | null;
  compliance:          ComplianceControl[];
}

export interface FrameworkCoverageControl {
  control_id:        string;
  control_name:      string;
  technique_ids:     string[];
  run_count:         number;
  detection_count:   number;
}

export interface FrameworkCoverage {
  controls_tested:   number;
  controls_detected: number;
  controls:          FrameworkCoverageControl[];
}

export interface WeeklyReportCompliance {
  schema_version:    number;
  evaluated_window:  { from: string; to: string };
  mitre_coverage: {
    techniques_tested:         number;
    techniques_with_detection: number;
    true_positive_rate:        number | null;
    total_runs:                number;
    total_detections:          number;
    by_technique:              ComplianceTechnique[];
  };
  framework_coverage: Record<string, FrameworkCoverage>;
  evidence_artifacts: Array<{
    name:    string;
    format:  string;
    section: string;
    purpose: string;
  }>;
  note?: string;
}

export interface WeeklyReportHistoryEntry {
  week_str:     string;       // "2026-W18"
  year:         number;
  week:         number;
  from:         string | null;
  to:           string | null;
  generated:    string | null;
  alerts_total: number;
  headline:     string;
}

export interface WeeklyReportHistoryResponse {
  items: WeeklyReportHistoryEntry[];
  count: number;
}

export async function fetchWeeklyReport(week?: string): Promise<WeeklyReport> {
  if (isDemoMode()) return demoWeeklyReport(week);
  const qs = week ? `?week=${encodeURIComponent(week)}` : '';
  return req<WeeklyReport>(`/api/reports/weekly${qs}`);
}

export async function fetchWeeklyReportHistory(limit = 12): Promise<WeeklyReportHistoryResponse> {
  if (isDemoMode()) return demoWeeklyHistory(limit);
  return req<WeeklyReportHistoryResponse>(`/api/reports/history?limit=${limit}`);
}

export function weeklyReportCsvUrl(week?: string): string {
  const q = new URLSearchParams({ fmt: 'csv' });
  if (week) q.set('week', week);
  return `${BASE}/api/reports/weekly?${q}`;
}

function demoWeeklyHistory(limit: number): WeeklyReportHistoryResponse {
  // Demo-Stub: gibt ein paar plausible Wochen-Einträge zurück, damit die
  // History-Liste in der Demo nicht leer aussieht.
  const items: WeeklyReportHistoryEntry[] = [];
  const today = new Date();
  for (let i = 1; i <= Math.min(limit, 6); i++) {
    const monday = new Date(today);
    monday.setDate(monday.getDate() - ((monday.getDay() + 6) % 7) - 7 * i);
    const year = monday.getFullYear();
    const wk   = 18 - i;
    items.push({
      week_str:     `${year}-W${String(wk).padStart(2, '0')}`,
      year, week: wk,
      from:         monday.toISOString(),
      to:           new Date(monday.getTime() + 7 * 86400e3).toISOString(),
      generated:    new Date(monday.getTime() + 8 * 86400e3).toISOString(),
      alerts_total: Math.floor(150 + Math.random() * 200),
      headline:     `${Math.floor(2 + Math.random() * 8)} kritische Alerts in KW ${wk}.`,
    });
  }
  return { items, count: items.length };
}

// Demo-Stub mit plausiblen Werten (damit der Demo-User die Page nicht leer
// sieht). Schema folgt dem echten Endpoint.
function demoWeeklyReport(_week?: string): WeeklyReport {
  const today = new Date();
  const monday = new Date(today);
  monday.setDate(monday.getDate() - ((monday.getDay() + 6) % 7));
  const days: WeeklyReportDay[] = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(monday);
    d.setDate(monday.getDate() + i);
    days.push({
      date: d.toISOString().slice(0, 10),
      critical: Math.floor(Math.random() * 3),
      high:     Math.floor(Math.random() * 8),
      medium:   Math.floor(Math.random() * 18),
      low:      Math.floor(Math.random() * 30),
    });
  }
  return {
    week: { year: 2026, week: 18,
      from: monday.toISOString(), to: new Date(monday.getTime() + 7*86400e3).toISOString(),
      generated: new Date().toISOString() },
    summary: {
      alerts_total:       248,
      alerts_total_trend: { prev: 312, delta_pct: -20.5, direction: 'down' },
      by_severity:      { critical: 4,  high: 28, medium: 96, low: 120 },
      by_severity_prev: { critical: 9,  high: 41, medium: 113, low: 149 },
      headline: '4 kritische Alerts diese Woche; Spitzenreiter: SCAN_001 mit 67 Treffern.',
    },
    detection: {
      daily: days,
      top_rules: [
        { rule_id: 'SCAN_001', source: 'signature', severity: 'medium',
          description: 'TCP-SYN-Port-Scan Heuristik', count: 67 },
        { rule_id: 'RECON_002', source: 'signature', severity: 'medium',
          description: 'Systematischer Port-Sweep', count: 38 },
        { rule_id: 'DOS_UDP_001', source: 'signature', severity: 'critical',
          description: 'UDP Flood gegen einzelnen Host', count: 4 },
      ],
      top_sources: [
        { src_ip: '192.168.1.85', display_name: 'kali-lab', hostname: null, max_severity: 'critical', count: 73 },
        { src_ip: '192.168.1.66', display_name: null, hostname: 'workstation-04', max_severity: 'medium', count: 42 },
      ],
      top_external_dests: [
        { dst_ip: '8.8.8.8', country: 'United States', country_code: 'US', asn: 'GOOGLE', count: 19 },
        { dst_ip: '94.198.93.10', country: 'Germany', country_code: 'DE', asn: 'Hetzner', count: 11 },
      ],
    },
    ops: {
      taps: [
        { id: 'demo-tap', name: 'cyjankali', site: 'lab', status: 'active',
          last_seen: new Date(Date.now() - 8000).toISOString(), alerts_week: 73 },
      ],
      ml: { fp_marked: 12, tp_marked: 1, tuner_cycles: 28 },
      suricata_top_sids: [
        { sid: 'SURICATA:1:2006380:17', count: 8 },
        { sid: 'SURICATA:1:2022082:6',  count: 3 },
      ],
    },
    boundary: {
      total: 24,
      by_priority: { P0: 2, P1: 6, P2: 11, P3: 5 },
      whitelisted: 4,
      top_talkers: [
        { src_ip: '192.168.1.66', display_name: 'workstation-04', hostname: null, count: 9, top_priority: 'P1' },
        { src_ip: '10.10.5.12',   display_name: null, hostname: 'plc-room-a',     count: 7, top_priority: 'P0' },
        { src_ip: '192.168.1.85', display_name: 'kali-lab', hostname: null, count: 4, top_priority: 'P2' },
      ],
      top_pairs: [
        { src_ip: '192.168.1.66', dst_ip: '185.199.108.153', dst_country: 'United States', dst_country_code: 'US', dst_asn: 'GitHub Inc.', count: 5, top_priority: 'P1' },
        { src_ip: '10.10.5.12',   dst_ip: '88.198.12.7',     dst_country: 'Germany',       dst_country_code: 'DE', dst_asn: 'Hetzner',     count: 4, top_priority: 'P0' },
        { src_ip: '192.168.1.85', dst_ip: '8.8.8.8',         dst_country: 'United States', dst_country_code: 'US', dst_asn: 'GOOGLE',      count: 2, top_priority: 'P2' },
      ],
      by_zone: {
        'ot/it':       3,
        'ot/internet': 2,
        'it/ot':       6,
        'it/internet': 8,
        'internet/ot': 5,
      },
      unzoned: 0,
    },
    audit: {
      active_users: [
        { username: 'admin', last_login: new Date(Date.now() - 6 * 3600e3).toISOString() },
      ],
      whitelist_adds: 2,
    },
  };
}

// ── Feature-Flags ──────────────────────────────────────────────────────────

export async function fetchFeatureFlags(): Promise<import('./types').FeatureFlags> {
  if (isDemoMode()) {
    return { redteam_enabled: false, pattern_export_enabled: false, pattern_import_enabled: true };
  }
  return await req<import('./types').FeatureFlags>('/api/system/feature-flags');
}

export async function updateFeatureFlags(
  patch: Partial<import('./types').FeatureFlags>,
): Promise<import('./types').FeatureFlags> {
  if (isDemoMode()) {
    return { redteam_enabled: false, pattern_export_enabled: false, pattern_import_enabled: true };
  }
  return await req<import('./types').FeatureFlags>('/api/system/feature-flags', {
    method: 'PATCH', body: JSON.stringify(patch),
  });
}

// ── Pattern-Federation Customer-Side ──────────────────────────────────────

export async function uploadPatternBundle(file: File): Promise<import('./types').StagedBundle> {
  if (isDemoMode()) {
    return {
      import_id: 'demo-staged',
      bundle_sha256: 'demo' + 'a'.repeat(60),
      lab_id: 'cyjan-lab-demo',
      schema_version: 1,
      signature_status: 'absent',
      state: 'staged',
      diff: {
        rules_custom:           { added: ['MODBUS_NEW.yml'], modified: ['SCAN_001.yml'], removed: [] },
        rules_suricata:         { added: [], modified: [], removed: [] },
        defaults_recalibration: [{
          rule_id: 'SCAN_001', param: 'port_count',
          old_default: 50, new_default: 35,
          reason: 'Lab-Sweep optimum bei 35',
          manual_lock_at_customer: false, will_be_applied: true,
        }],
        tests_regression: ['SCAN_001_distributed.yml'],
        mitre_coverage: null,
      },
      warnings: ['Bundle ist nicht signiert — Anwendung erfordert force_unverified=true'],
    };
  }
  const fd = new FormData();
  fd.append('file', file);
  const token = getToken();
  const res = await fetch(`${BASE}/api/pattern/upload`, {
    method: 'POST',
    headers: token ? { Authorization: `Bearer ${token}` } : {},
    body: fd,
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return await res.json();
}

export async function applyPatternBundle(
  importId: string,
  components: import('./types').BundleComponent[],
  forceUnverified: boolean = false,
): Promise<{ import_id: string; state: string; applied: Record<string, unknown>; errors: Record<string, string> }> {
  if (isDemoMode()) return { import_id: importId, state: 'applied', applied: {}, errors: {} };
  return await req(`/api/pattern/apply/${importId}`, {
    method: 'POST',
    body: JSON.stringify({ components, force_unverified: forceUnverified }),
  });
}

export async function fetchPatternImports(): Promise<import('./types').BundleImportRecord[]> {
  if (isDemoMode()) return [];
  const r = await req<{ imports: import('./types').BundleImportRecord[] }>('/api/pattern/imports');
  return r.imports ?? [];
}

export async function fetchPatternTrustKeys(): Promise<import('./types').PatternTrustKey[]> {
  if (isDemoMode()) return [];
  const r = await req<{ keys: import('./types').PatternTrustKey[] }>('/api/pattern/trust-keys');
  return r.keys ?? [];
}

export async function addPatternTrustKey(
  labId: string, pubkeyPem: string, description: string,
): Promise<import('./types').PatternTrustKey> {
  return await req('/api/pattern/trust-keys', {
    method: 'POST',
    body: JSON.stringify({ lab_id: labId, public_key: pubkeyPem, description }),
  });
}

export async function deletePatternTrustKey(id: string): Promise<void> {
  await req(`/api/pattern/trust-keys/${id}`, { method: 'DELETE' });
}

// ── Pattern-Export (Lab-only) ─────────────────────────────────────────────

export async function fetchSigningKeys(): Promise<import('./types').PatternSigningKey[]> {
  if (isDemoMode()) return [];
  try {
    const r = await req<{ keys: import('./types').PatternSigningKey[] }>('/api/pattern/signing-keys');
    return r.keys ?? [];
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return [];
    throw e;
  }
}

export async function addSigningKey(
  body: import('./types').PatternSigningKeyCreate,
): Promise<import('./types').PatternSigningKey> {
  return await req('/api/pattern/signing-keys', {
    method: 'POST', body: JSON.stringify(body),
  });
}

export async function deleteSigningKey(id: string): Promise<void> {
  await req(`/api/pattern/signing-keys/${id}`, { method: 'DELETE' });
}

export async function previewPatternExport(
  body: import('./types').ExportRequest,
): Promise<import('./types').ExportPreview> {
  if (isDemoMode()) {
    return { components: {}, estimated_size: 0, requested: body.components } as import('./types').ExportPreview;
  }
  return await req<import('./types').ExportPreview>("/api/pattern/export/preview", {
    method: "POST", body: JSON.stringify(body),
  });
}

export async function exportPatternBundle(body: import('./types').ExportRequest): Promise<Blob> {
  if (isDemoMode()) return new Blob(['demo-bundle'], { type: 'application/zip' });
  const token = getToken();
  const res = await fetch(`${BASE}/api/pattern/export`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status}: ${await res.text()}`);
  return await res.blob();
}

export async function fetchExportLog(): Promise<import('./types').PatternExportRecord[]> {
  if (isDemoMode()) return [];
  try {
    const r = await req<{ exports: import('./types').PatternExportRecord[] }>('/api/pattern/exports');
    return r.exports ?? [];
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith('404')) return [];
    throw e;
  }
}


// ── RedTeam (Lab-only) ─────────────────────────────────────────────────────

export async function fetchRedTeamHealth(): Promise<import("./types").RedTeamHealth> {
  if (isDemoMode()) return { reachable: false, error: "Demo-Mode" };
  try {
    return await req<import("./types").RedTeamHealth>("/api/redteam/health");
  } catch (e: unknown) {
    if (e instanceof Error && e.message.startsWith("404")) {
      return { reachable: false, error: "REDTEAM_ENABLED=false" };
    }
    throw e;
  }
}

export async function runRedTeamTool(
  body: import("./types").RedTeamRunRequest,
): Promise<import("./types").RedTeamRunResponse> {
  return await req<import("./types").RedTeamRunResponse>("/api/redteam/run", {
    method: "POST", body: JSON.stringify(body),
  });
}

export async function fetchRedTeamScenarios(): Promise<import("./types").RedTeamScenario[]> {
  if (isDemoMode()) return [];
  try {
    const r = await req<{ scenarios: import("./types").RedTeamScenario[] }>("/api/redteam/scenarios");
    return r.scenarios ?? [];
  } catch { return []; }
}

export async function runRedTeamScenario(
  body: import("./types").RedTeamScenarioRunRequest,
): Promise<import("./types").RedTeamScenarioRunResponse> {
  return await req<import("./types").RedTeamScenarioRunResponse>(
    "/api/redteam/scenarios/run",
    { method: "POST", body: JSON.stringify(body) },
  );
}

export async function fetchRedTeamAuditLog(limit = 50): Promise<import("./types").RedTeamAuditEntry[]> {
  if (isDemoMode()) return [];
  try {
    const r = await req<{ entries: import("./types").RedTeamAuditEntry[] }>(
      `/api/redteam/audit-log?limit=${limit}`,
    );
    return r.entries ?? [];
  } catch { return []; }
}

export interface McpTokenResponse {
  token:           string;
  token_id:        string;
  description:     string;
  expires_at:      string;
  expires_in_days: number;
}

export async function generateMcpToken(
  body: { description?: string; expires_days?: number },
): Promise<McpTokenResponse> {
  return await req<McpTokenResponse>("/api/redteam/mcp-token", {
    method: "POST",
    body: JSON.stringify(body),
  });
}


// ── Notification-Channels ──────────────────────────────────────────────────

export async function fetchNotificationTypes(): Promise<import("./types").NotificationTypesInfo> {
  if (isDemoMode()) return { types: ['webhook','ntfy','email'], severity_levels: ['low','medium','high','critical'], source_options: ['signature','ml','suricata','external'] };
  return await req<import("./types").NotificationTypesInfo>('/api/notifications/types');
}

export async function fetchNotificationChannels(): Promise<import("./types").NotificationChannel[]> {
  if (isDemoMode()) return [];
  return await req<import("./types").NotificationChannel[]>('/api/notifications/channels');
}

export async function createNotificationChannel(
  body: import("./types").NotificationChannelCreate,
): Promise<import("./types").NotificationChannel> {
  return await req<import("./types").NotificationChannel>('/api/notifications/channels', {
    method: 'POST', body: JSON.stringify(body),
  });
}

export async function updateNotificationChannel(
  id: string,
  body: import("./types").NotificationChannelUpdate,
): Promise<import("./types").NotificationChannel> {
  return await req<import("./types").NotificationChannel>(`/api/notifications/channels/${id}`, {
    method: 'PATCH', body: JSON.stringify(body),
  });
}

export async function deleteNotificationChannel(id: string): Promise<void> {
  await req(`/api/notifications/channels/${id}`, { method: 'DELETE' });
}

export async function testNotificationChannel(id: string): Promise<{ok: boolean; channel: string}> {
  return await req(`/api/notifications/channels/${id}/test`, { method: 'POST' });
}

export async function fetchNotificationDeliveries(
  channelId?: string, limit = 100,
): Promise<import("./types").NotificationDelivery[]> {
  if (isDemoMode()) return [];
  const qs = new URLSearchParams({ limit: String(limit) });
  if (channelId) qs.set('channel_id', channelId);
  return await req<import("./types").NotificationDelivery[]>(`/api/notifications/deliveries?${qs}`);
}
