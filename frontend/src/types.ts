export interface Geo {
  country?: string;
  country_code?: string;
  city?: string;
  lat?: number;
  lon?: number;
}

export interface ASN {
  number: number;
  org: string;
}

export interface NetworkBadge {
  cidr: string;
  name: string;
  color?: string;
}

export interface Enrichment {
  src_hostname?: string;
  dst_hostname?: string;
  src_network?: NetworkBadge;
  dst_network?: NetworkBadge;
  src_ping_ms?: number;
  dst_ping_ms?: number;
  src_asn?: ASN;
  dst_asn?: ASN;
  src_geo?: Geo;
  dst_geo?: Geo;
  // Trust
  src_trusted?: boolean;
  dst_trusted?: boolean;
  src_trust_source?: string;
  dst_trust_source?: string;
  src_display_name?: string;
  dst_display_name?: string;
}

export interface Host {
  ip: string;
  hostname?: string;
  display_name?: string;
  trusted: boolean;
  trust_source?: string;
  asn?: ASN;
  geo?: Geo;
  ping_ms?: number;
  last_seen?: string;
  updated_at: string;
}

export interface Alert {
  alert_id: string;
  ts: string;
  flow_id?: string;
  source: string;
  rule_id?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  score: number;
  src_ip?: string;
  dst_ip?: string;
  src_port?: number;
  dst_port?: number;
  proto?: string;
  description?: string;
  tags: string[];
  enrichment?: Enrichment;
  pcap_available: boolean;
  pcap_key?: string;
  feedback?: 'fp' | 'tp' | null;
  feedback_ts?: string;
  feedback_note?: string;
  is_test: boolean;
}

export interface ThreatLevel {
  level: number;
  label: 'green' | 'yellow' | 'orange' | 'red';
  alert_counts: Record<string, number>;
  window_min: number;
}

export interface KnownNetwork {
  id: string;
  cidr: string;
  name: string;
  description?: string;
  color?: string;
}

export interface TestRun {
  id: string;
  scenario_id: string;
  started_at: string;
  completed_at?: string;
  status: 'running' | 'completed' | 'failed';
  expected_rule?: string;
  triggered?: boolean;
  alert_id?: string;
  latency_ms?: number;
  error?: string;
}

export interface User {
  id:           string;
  username:     string;
  email?:       string;
  display_name?: string;
  role:         'admin' | 'viewer';
  source:       'local' | 'saml';
  active:       boolean;
  created_at:   string;
  last_login?:  string;
}

export interface SamlConfig {
  enabled:              boolean;
  idp_metadata_url:     string;
  sp_entity_id:         string;
  acs_url:              string;
  attribute_username:   string;
  attribute_email:      string;
  attribute_display_name: string;
  default_role:         'admin' | 'viewer';
}

export interface MLModelInfo {
  trained:       boolean;
  n_samples:     number;
  trained_at:    number | null;
  contamination: number;
  n_attack:      number;
}

export interface MLBootstrapInfo {
  required:              number;
  current_flows:         number;
  progress_pct:          number;
  estimated_remaining_s: number | null;
}

export interface MLStats24h {
  flows_total:      number;
  ml_alerts:        number;
  filter_rate_pct:  number;
  alert_threshold:  number;
}

export interface MLFeatureDeviation {
  name:          string;
  label:         string;
  unit:          string;
  avg_in_alerts: number;
  avg_normal:    number;
  deviation_pct: number;
}

export interface MLConfig {
  alert_threshold:       number;
  contamination:         number;
  bootstrap_min_samples: number;
  partial_fit_interval:  number;
}

export interface MLStatus {
  phase:                 'passthrough' | 'learning' | 'active';
  phase_label:           string;
  model:                 MLModelInfo;
  bootstrap:             MLBootstrapInfo;
  stats_24h:             MLStats24h;
  top_anomaly_features:  MLFeatureDeviation[];
}

export interface RuleSource {
  id:      string;
  name:    string;
  url:     string;
  enabled: boolean;
  builtin: boolean;
  tags:    string[];
}

export interface Rule {
  sid:       number | null;
  msg:       string;
  action:    string;
  classtype: string | null;
  enabled:   boolean;
  file:      string;
}

export interface RuleListResponse {
  rules: Rule[];
  total: number;
}

export interface UpdateStatus {
  requested:    boolean;
  requested_at: number | null;
  last_updated: number | null;
}

export type WsMessage =
  | { type: 'initial';          data: Alert[] }
  | { type: 'alert';            data: Alert }
  | { type: 'alert_enriched';   data: { alert_id: string; enrichment: Enrichment } }
  | { type: 'pcap_available';   data: { alert_id: string } }
  | { type: 'feedback_updated'; data: { alert_id: string; feedback: 'fp' | 'tp'; feedback_ts: string | null; feedback_note: string | null } };
