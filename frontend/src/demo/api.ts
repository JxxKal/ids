import type { Alert, Host, KnownNetwork, ThreatLevel, User } from '../types';
import { DEMO_NETWORKS, DEMO_USER, computeThreatLevel, demoHosts, generateConnectionGraph } from './data';
import { getAlerts, updateAlert } from './store';

// ─── Auth ───────────────────────────────────────────────────────────────────

export function login(): { access_token: string; user: User } {
  return { access_token: 'demo-token', user: DEMO_USER };
}

export function fetchMe(): User {
  return DEMO_USER;
}

// ─── Alerts ─────────────────────────────────────────────────────────────────

export function fetchAlerts(filters: {
  ts_from?: number;
  limit?:   number;
  is_test?: boolean | null;
  source?:  string;
}): { alerts: Alert[]; total: number } {
  let list = getAlerts();
  if (filters.source === 'ml') list = list.filter(a => a.source === 'ml');
  if (filters.is_test === false) list = list.filter(a => !a.is_test);
  if (filters.ts_from) {
    const cutMs = filters.ts_from * 1000;
    list = list.filter(a => Date.parse(a.ts) >= cutMs);
  }
  const sliced = list.slice(0, filters.limit ?? 500);
  return { alerts: sliced, total: list.length };
}

export function setFeedback(alertId: string, feedback: 'fp' | 'tp', note?: string): Alert {
  const list = getAlerts();
  const found = list.find(a => a.alert_id === alertId);
  if (!found) throw new Error('alert not found');
  const updated: Alert = {
    ...found,
    feedback,
    feedback_ts: new Date().toISOString(),
    feedback_note: note,
  };
  updateAlert(updated);
  return updated;
}

export function fetchThreatLevel(): ThreatLevel {
  return computeThreatLevel(getAlerts());
}

// ─── Netzwerke / Hosts ──────────────────────────────────────────────────────

export function fetchNetworks(): KnownNetwork[] {
  return [...DEMO_NETWORKS];
}

export function fetchHosts(params: { trusted?: boolean; search?: string } = {}): Host[] {
  let list = demoHosts();
  if (params.trusted === true)  list = list.filter(h => h.trusted);
  if (params.trusted === false) list = list.filter(h => !h.trusted);
  if (params.search) {
    const q = params.search.toLowerCase();
    list = list.filter(h => h.ip.includes(q) || h.hostname?.toLowerCase().includes(q));
  }
  return list;
}

// ─── Flow-Graph ─────────────────────────────────────────────────────────────

export function fetchConnectionGraph(srcIp: string, dstIp: string) {
  return generateConnectionGraph(srcIp, dstIp);
}

// ─── Settings-Stubs (damit Pages nicht crashen) ─────────────────────────────

export function fetchUsers(): User[] {
  return [DEMO_USER];
}

export function fetchMLStatus() {
  return {
    trained:         true,
    model_version:   42,
    last_train_ts:   new Date(Date.now() - 6 * 3600 * 1000).toISOString(),
    next_train_ts:   new Date(Date.now() + 18 * 3600 * 1000).toISOString(),
    samples_total:   18432,
    samples_fp:      1247,
    samples_tp:      386,
    bootstrap: { done: true, current_flows: 18432, required: 500, progress_pct: 100 },
    features: [],
  };
}

export function fetchMLConfig() {
  return {
    retrain_interval_s: 86400,
    dedup_window_s: 300,
    bootstrap_min: 500,
    score_threshold: 0.45,
    feature_filters: {},
  };
}

export function fetchRuleSources() { return []; }
export function fetchRules()       { return []; }
export function fetchRuleUpdateStatus() {
  return { requested: null, last_run_ts: null, last_run_status: 'idle', last_run_error: null };
}
export function fetchSslStatus() {
  return { has_cert: true, issuer: 'Demo CA', subject: 'CN=demo.cyjan.local', not_after: '2027-04-22T00:00:00Z', mode: 'self-signed' as const };
}
export function fetchSamlConfig() {
  return {
    enabled: false, idp_metadata_url: '', sp_entity_id: 'cyjan-demo', acs_url: 'https://demo/saml/acs',
    attribute_username: 'uid', attribute_email: 'mail', attribute_display_name: 'displayName', default_role: 'viewer' as const,
  };
}
export function fetchSyslogConfig() {
  return { enabled: false, host: '', port: 514, protocol: 'udp' as const, facility: 'local0', severity_min: 'medium' as const };
}

export function fetchTestRuns() { return []; }
