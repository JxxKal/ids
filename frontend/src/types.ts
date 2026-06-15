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
  // Egress-Boundary (vom enrichment-service annotiert; alte Alerts haben null)
  boundary_net_known?: boolean | null;
  boundary_src_known?: boolean | null;
  boundary_dst_known?: boolean | null;
  boundary_priority?:  'P0' | 'P1' | 'P2' | 'P3' | null;
  boundary_whitelisted?: boolean;
  // Remote-Tap-Herkunft: NULL = lokal am Master erzeugt, sonst UUID des Taps
  // (siehe Remote-Tap-Architektur). Frontend zeigt eine Spalte "Tap" wenn
  // wenigstens ein Tap konfiguriert ist.
  tap_id?: string | null;
}

// Tags, die der alert-manager bei Auto-/ML-Suppression setzt (mit Severity-
// Downgrade auf "low"). Werden im Dashboard per "Show suppressed"-Schalter
// ein-/ausgeblendet.
export const SUPPRESSED_TAGS = ['ml-suppressed', 'auto-suppressed'] as const;

export function isSuppressed(a: Pick<Alert, 'tags'>): boolean {
  return !!a.tags?.some(t => t === 'ml-suppressed' || t === 'auto-suppressed');
}

export interface RemoteTap {
  id: string;
  name: string;
  site?: string | null;
  cert_fingerprint: string;
  cert_expires_at: string;
  status: 'active' | 'revoked';
  paired_at: string;
  paired_by?: string | null;
  last_seen?: string | null;
  alerts_received: number;
  // Vom Tap selbst gemeldete Version (hello-Frame beim Connect, gefüttert
  // aus /opt/ids/VERSION). null wenn der Tap noch keinen hello geschickt
  // hat (alte tap-uplink-Version).
  version?: string | null;
  version_reported_at?: string | null;
}

export interface RemoteTapPairingToken {
  token: string;
  expires_at: string;
  name: string;
  site?: string | null;
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
  // 'ot' | 'it' — Zone-Tag für die OT-Boundary-Klassifikation.
  // Default 'ot' für Bestandseinträge (Migration 016).
  kind?: 'ot' | 'it';
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
  role:         'admin' | 'viewer' | 'api';
  source:       'local' | 'saml';
  active:       boolean;
  created_at:   string;
  last_login?:  string;
}

export interface IrmaConfig {
  enabled:       boolean;
  base_url:      string;
  user:          string;
  password:      string;
  poll_interval: number;
  ssl_verify:    boolean;
}

export interface MqttConfig {
  enabled:                boolean;
  broker_host:            string;
  broker_port:            number;
  use_tls:                boolean;
  tls_verify:             boolean;
  username:               string;
  password:               string;
  client_id:              string;
  master_host_id:         string;
  topic_prefix:           string;
  qos_events:             number;     // 0 | 1
  qos_state:              number;     // 0 | 1
  rate_limit_per_sec:     number;
  inflight_max:           number;
  threat_publish_interval_s: number;
  tap_publish_interval_s: number;
  severity_min:           'low' | 'medium' | 'high' | 'critical';
  sources_allowed:        string[];   // signature, ml, suricata, external
  rule_id_blocklist:      string[];   // mit Wildcard-Support: "ASSET::*"
}

export interface MqttTestResult {
  ok:          boolean;
  duration_ms: number;
  test_topic:  string;
  detail?:     string | null;
}

// ── Cyjan Feature-Flags ─────────────────────────────────────────────────────

export interface FeatureFlags {
  redteam_enabled:        boolean;
  pattern_export_enabled: boolean;
  pattern_import_enabled: boolean;
}

// ── Pattern-Federation (Customer + Lab) ─────────────────────────────────────

export type BundleComponent =
  | 'rules.custom'
  | 'rules.suricata'
  | 'defaults.recalibration'
  | 'tests.regression'
  | 'evidence.mitre';

export type SignatureStatus = 'valid' | 'invalid' | 'absent' | 'unverified';
export type BundleState     = 'staged' | 'applied' | 'rejected' | 'expired';

export interface BundleDiff {
  rules_custom:           { added: string[]; modified: string[]; removed: string[] };
  rules_suricata:         { added: string[]; modified: string[]; removed: string[] };
  defaults_recalibration: Array<{
    rule_id:                  string;
    param:                    string;
    old_default:              number | null;
    new_default:              number;
    reason:                   string;
    manual_lock_at_customer:  boolean;
    will_be_applied:          boolean;
  }>;
  tests_regression:       string[];
  mitre_coverage?:        {
    schema_version: number;
    techniques: Array<{
      technique_id:     string;
      detection_count:  number;
      run_count:        number;
      scenarios: Array<{
        scenario_id:      string;
        expected_rule_id: string | null;
        run_count:        number;
        detected_count:   number;
        tpr:              number;
      }>;
    }>;
  } | null;
}

export interface StagedBundle {
  import_id:         string;
  bundle_sha256:     string;
  lab_id:            string | null;
  schema_version:    number;
  signature_status:  SignatureStatus;
  state:             BundleState;
  diff:              BundleDiff;
  warnings:          string[];
  rejected_reason?:  string | null;
}

export interface BundleImportRecord {
  id:                 string;
  bundle_sha256:      string;
  bundle_size:        number;
  lab_id:             string | null;
  state:              BundleState;
  signature_status:   SignatureStatus;
  components_applied: Record<string, unknown>;
  uploaded_at:        string;
  applied_at?:        string | null;
}

export interface PatternTrustKey {
  id:            string;
  lab_id:        string;
  pubkey_sha256: string;
  description?:  string;
  enabled:       boolean;
  added_at:      string;
}

// ── Pattern-Export (Lab-only) ───────────────────────────────────────────────

export interface PatternSigningKey {
  id:            string;
  lab_id:        string;
  key_id:        string;
  pubkey_sha256: string;
  enabled:       boolean;
  description?:  string;
  created_at:    string;
}

export interface PatternSigningKeyCreate {
  lab_id:       string;
  key_id:       string;
  pubkey_pem:   string;
  privkey_path: string;
  description?: string;
}

export interface ExportRequest {
  components:        BundleComponent[];
  sign_with_key_id:  string | null;
  description:       string;
  lab_run_id?:       string;
}

// ── RedTeam (Lab-only) ──────────────────────────────────────────────────────

export interface RedTeamHealth {
  reachable:         boolean;
  status?:           string;
  kali_container?:   string;
  allowed_src_cidrs?: string[];
  error?:            string;
}

export interface RedTeamRunRequest {
  tool:        'nmap' | 'hydra' | 'hping3' | 'ncat' | 'ping';
  target_ip:   string;
  args:        string[];
  timeout_sec: number;
  expected_alert_rule_id?: string | null;
  attach_iface: boolean;
}

export interface RedTeamRunResponse {
  run_id:         string;
  tool:           string;
  target_ip:      string;
  args:           string[];
  exit_code:      number;
  duration_ms:    number;
  timed_out:      boolean;
  stdout_excerpt: string;
  stderr_excerpt: string;
  matched_alerts: unknown[];
}

export interface RedTeamScenario {
  scenario_id:             string;
  file:                    string;
  rule_id?:                string | null;
  expected_alert_rule_id?: string | null;
  description?:            string | null;
  protocol?:               'tcp' | 'udp' | null;
  target_port?:            number | null;
  tags?:                   string[];
  mitre?:                  string[];
}

export interface RedTeamScenarioRunRequest {
  scenario_id: string;
  target_ip:   string;
  timeout_sec?: number;
}

export interface RedTeamScenarioRunResponse {
  run_id:            string;
  scenario_id:       string;
  target_ip:         string;
  target_port:       number;
  protocol:          string;
  sent_bytes:        number | null;
  exit_code:         number;
  duration_ms:       number | null;
  stderr_excerpt:    string;
  matched_alerts:    Array<{ rule_id: string; severity?: string; signature?: string }>;
  detection_success: boolean | null;
  expected_rule:     string | null;
}

export interface RedTeamAuditEntry {
  id:             number;
  ts:             string;
  mcp_tool:       string;
  target_ip:      string | null;
  decision:       'allowed' | 'rejected_validation' | 'rejected_rate_limit';
  reject_reason:  string | null;
  duration_ms:    number | null;
  result_summary: Record<string, unknown> | null;
  args_excerpt:   string;
}

// ── Notification-Channels ───────────────────────────────────────────────────

export type NotificationChannelType = 'webhook' | 'ntfy' | 'email' | string;
export type SeverityLevel = 'low' | 'medium' | 'high' | 'critical';

export interface NotificationChannel {
  id:                  string;
  user_id:             string | null;
  name:                string;
  type:                NotificationChannelType;
  config:              Record<string, unknown>;
  enabled:             boolean;
  severity_min:        SeverityLevel;
  rule_prefix_filter:  string | null;
  source_filter:       string[] | null;
  throttle_seconds:    number;
  created_at:          string;
  updated_at:          string;
  last_used:           string | null;
}

export interface NotificationChannelCreate {
  name:                string;
  type:                NotificationChannelType;
  config:              Record<string, unknown>;
  enabled?:            boolean;
  severity_min?:       SeverityLevel;
  rule_prefix_filter?: string | null;
  source_filter?:      string[] | null;
  throttle_seconds?:   number;
}

export interface NotificationChannelUpdate {
  name?:               string;
  config?:             Record<string, unknown>;
  enabled?:            boolean;
  severity_min?:       SeverityLevel;
  rule_prefix_filter?: string | null;
  source_filter?:      string[] | null;
  throttle_seconds?:   number;
}

export interface NotificationDelivery {
  id:          number;
  ts:          string;
  channel_id:  string;
  alert_id:    string | null;
  rule_id:     string | null;
  severity:    string | null;
  status:      'sent' | 'failed' | 'rate_limited' | 'filtered' | 'disabled';
  status_code: number | null;
  latency_ms:  number | null;
  error:       string | null;
}

export interface NotificationTypesInfo {
  types:           string[];
  severity_levels: SeverityLevel[];
  source_options:  string[];
}


// ── Pattern-Export-Preview ──────────────────────────────────────────────────
// Spiegelt das component_manifest aus pattern_export.py:preview_export

export interface ExportPreviewSuricataFile {
  name:           string;
  sha256:         string;
  ai_rule_count:  number;
  size_bytes:     number;
  source:         'active' | 'legacy';
}

export interface ExportPreviewCustomFile {
  name:       string;
  rule_id:    string;
  sha256:     string;
  size_bytes: number;
}

export interface ExportPreviewScenarioFile {
  path:       string;
  sha256:     string;
  origin:     'ai-generated' | 'builtin-template' | 'other';
  size_bytes: number;
}

export interface ExportPreview {
  components: {
    'rules.custom'?: {
      file_count: number;
      files:      ExportPreviewCustomFile[];
    };
    'rules.suricata'?: {
      file_count:    number;
      ai_rule_count: number;
      files:         ExportPreviewSuricataFile[];
    };
    'tests.regression'?: {
      file_count:        number;
      ai_scenario_count: number;
      builtin_count:     number;
      files:             ExportPreviewScenarioFile[];
    };
    'defaults.recalibration'?: { entry_count: number };
    'evidence.mitre'?: { technique_count: number };
  };
  estimated_size: number;
  requested:      string[];
}

export interface PatternExportRecord {
  id:                  string;
  bundle_sha256:       string;
  bundle_size:         number;
  lab_run_id:          string;
  components_exported: Record<string, unknown>;
  exported_at:         string;
  description?:        string;
}

export interface ItopConfig {
  enabled:    boolean;
  base_url:   string;
  user:       string;
  password:   string;
  org_filter: string;
  ssl_verify: boolean;
}

export interface ItopSyncState {
  phase:       'idle' | 'running' | 'done' | 'error';
  log:         string[];
  stats:       { networks_upserted?: number; networks_errors?: number; hosts_upserted?: number; hosts_errors?: number };
  started_at:  string | null;
  finished_at: string | null;
}

export interface SamlConfig {
  enabled:              boolean;
  // IdP-Felder (via XML-Import oder manuell befüllt)
  idp_entity_id:        string;
  idp_sso_url:          string;
  idp_slo_url:          string;
  idp_x509_cert:        string;
  // SP-Felder
  sp_entity_id:         string;
  acs_url:              string;
  slo_url:              string;
  // Attribut-Mapping
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
  retrain_interval_s:    number;
}

export interface MLRetrainState {
  currently_training:   boolean;
  last_trained_at:      number | null;   // unix-seconds
  last_run_duration_s:  number | null;
  last_run_samples:     number | null;
  retrain_interval_s:   number | null;
  next_scheduled_at:    number | null;
  last_error:           string | null;
  updated_at:           number | null;
}

export interface MLStatus {
  phase:                 'passthrough' | 'learning' | 'active';
  phase_label:           string;
  model:                 MLModelInfo;
  bootstrap:             MLBootstrapInfo;
  stats_24h:             MLStats24h;
  top_anomaly_features:  MLFeatureDeviation[];
  retrain_state?:        MLRetrainState | null;
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

export interface SystemUpdateStatus {
  phase: 'idle' | 'extracting' | 'loading' | 'building' | 'restarting' | 'done' | 'error';
  log: string[];
  progress: number;
  started_at: string | null;
  finished_at: string | null;
  version?: string;
}

export type InterfaceRole = 'management' | 'sniffer';

export interface InterfaceInfo {
  name:       string;
  // `role` ist der Legacy-Wert (erste Rolle); `roles` ist die saubere Liste,
  // damit ein Single-NIC-Setup gleichzeitig Management UND Sniffer sein kann
  // ohne dass eine Markierung still verloren geht.
  role:       InterfaceRole | null;
  roles?:     InterfaceRole[];
  operstate:  string;   // 'up' | 'down' | 'unknown'
  addresses:  string[]; // CIDR strings, e.g. '192.168.1.100/24'
  mac:        string;
}

export type WsMessage =
  | { type: 'initial';          data: Alert[] }
  | { type: 'alert';            data: Alert }
  | { type: 'alert_enriched';   data: { alert_id: string; enrichment: Enrichment } }
  | { type: 'pcap_available';   data: { alert_id: string } }
  | { type: 'feedback_updated'; data: { alert_id: string; feedback: 'fp' | 'tp'; feedback_ts: string | null; feedback_note: string | null; severity?: Alert['severity']; tags?: string[] } };
