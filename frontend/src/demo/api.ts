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

// Form muss exakt zum types.ts MLStatus-Schema passen — sonst crashen die
// Settings-Subpages (MLOverviewSettings, MLStatusDisplay) beim Destructuring
// (model.n_samples, stats_24h.ml_alerts, etc.).
export function fetchMLStatus() {
  const nowSec = Math.floor(Date.now() / 1000);
  return {
    phase:        'active',
    phase_label:  'Aktiv (Demo)',
    model: {
      trained:       true,
      n_samples:     18_432,
      trained_at:    nowSec - 6 * 3600,
      contamination: 0.05,
      n_attack:      386,
    },
    bootstrap: {
      required:              500,
      current_flows:         18_432,
      progress_pct:          100,
      estimated_remaining_s: null,
    },
    stats_24h: {
      flows_total:     1_240_000,
      ml_alerts:       42,
      filter_rate_pct: 99.7,
      alert_threshold: 0.45,
    },
    top_anomaly_features: [
      { name: 'pps',          label: 'Pakete/Sekunde',     unit: 'pps',  avg_in_alerts: 8400, avg_normal: 320,  deviation_pct: 26.3 },
      { name: 'flow_rate_30', label: 'Flows / 30 s',       unit: '',     avg_in_alerts: 142,  avg_normal: 18,   deviation_pct:  7.9 },
      { name: 'iat_entropy',  label: 'IAT-Entropie',       unit: 'bits', avg_in_alerts: 4.1,  avg_normal: 1.2,  deviation_pct:  3.4 },
    ],
    retrain_state: {
      currently_training:   false,
      last_trained_at:      nowSec - 6 * 3600,
      last_run_duration_s:  42.3,
      last_run_samples:     18_432,
      retrain_interval_s:   86_400,
      next_scheduled_at:    nowSec + 18 * 3600,
      last_error:           null,
      updated_at:           nowSec - 6 * 3600,
    },
  };
}

// Form muss exakt zum types.ts MLConfig-Schema passen — sonst crasht
// MLFilterConfig beim Render.
export function fetchMLConfig() {
  return {
    alert_threshold:       0.45,
    contamination:         0.05,
    bootstrap_min_samples: 500,
    partial_fit_interval:  300,
    retrain_interval_s:    86_400,
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
