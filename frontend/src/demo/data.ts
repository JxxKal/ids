import type { Alert, Host, KnownNetwork, ThreatLevel, User } from '../types';

// ─── Konstante Stammdaten ───────────────────────────────────────────────────

export const DEMO_USER: User = {
  id:        'demo-user-id',
  username:  'demo',
  email:     'demo@cyjan.local',
  role:      'admin',
  source:    'local',
  active:    true,
  last_login: new Date().toISOString(),
  created_at: '2026-01-01T00:00:00Z',
};

export const DEMO_NETWORKS: KnownNetwork[] = [
  { id: 'net-ot',    cidr: '10.10.20.0/24',    name: 'OT-Segment',    description: 'PLC/HMI Produktion',   color: '#fb923c' },
  { id: 'net-scada', cidr: '10.10.30.0/24',    name: 'SCADA-Ring',    description: 'Leitsystem',           color: '#f97316' },
  { id: 'net-it',    cidr: '10.0.1.0/24',      name: 'Office-IT',     description: 'Büro-Netz',            color: '#38bdf8' },
  { id: 'net-dmz',   cidr: '192.168.100.0/24', name: 'DMZ',           description: 'Externe Dienste',      color: '#a78bfa' },
  { id: 'net-mgmt',  cidr: '10.0.2.0/24',      name: 'Management',    description: 'Switches/Firewalls',   color: '#22c55e' },
];

interface DemoHost {
  ip: string;
  name: string;
  kind: 'PLC' | 'HMI' | 'RTU' | 'SCADA' | 'ENG' | 'SRV' | 'WS' | 'PRT' | 'GW' | 'SW' | 'FW' | 'EXT';
  trusted: boolean;
  network?: { id: string; name: string; cidr: string };
}

export const DEMO_HOSTS_META: DemoHost[] = [
  { ip: '10.10.20.10', name: 'plc-boiler-01',     kind: 'PLC',   trusted: true,  network: { id: 'net-ot',    name: 'OT-Segment',  cidr: '10.10.20.0/24' } },
  { ip: '10.10.20.11', name: 'plc-valve-02',      kind: 'PLC',   trusted: true,  network: { id: 'net-ot',    name: 'OT-Segment',  cidr: '10.10.20.0/24' } },
  { ip: '10.10.20.12', name: 'plc-press-03',      kind: 'PLC',   trusted: true,  network: { id: 'net-ot',    name: 'OT-Segment',  cidr: '10.10.20.0/24' } },
  { ip: '10.10.20.20', name: 'hmi-ops-01',        kind: 'HMI',   trusted: true,  network: { id: 'net-ot',    name: 'OT-Segment',  cidr: '10.10.20.0/24' } },
  { ip: '10.10.20.21', name: 'hmi-maint-02',      kind: 'HMI',   trusted: true,  network: { id: 'net-ot',    name: 'OT-Segment',  cidr: '10.10.20.0/24' } },
  { ip: '10.10.20.30', name: 'rtu-substation-A',  kind: 'RTU',   trusted: true,  network: { id: 'net-ot',    name: 'OT-Segment',  cidr: '10.10.20.0/24' } },
  { ip: '10.10.30.10', name: 'scada-core',        kind: 'SCADA', trusted: true,  network: { id: 'net-scada', name: 'SCADA-Ring',  cidr: '10.10.30.0/24' } },
  { ip: '10.10.30.11', name: 'scada-historian',   kind: 'SRV',   trusted: true,  network: { id: 'net-scada', name: 'SCADA-Ring',  cidr: '10.10.30.0/24' } },
  { ip: '10.10.30.20', name: 'eng-ws-siemens',    kind: 'ENG',   trusted: true,  network: { id: 'net-scada', name: 'SCADA-Ring',  cidr: '10.10.30.0/24' } },
  { ip: '10.10.30.21', name: 'eng-ws-abb',        kind: 'ENG',   trusted: true,  network: { id: 'net-scada', name: 'SCADA-Ring',  cidr: '10.10.30.0/24' } },
  { ip: '10.0.1.10',   name: 'ad-dc1',            kind: 'SRV',   trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.11',   name: 'fileserver',        kind: 'SRV',   trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.50',   name: 'laptop-ceo',        kind: 'WS',    trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.51',   name: 'laptop-anna',       kind: 'WS',    trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.52',   name: 'laptop-ben',        kind: 'WS',    trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.53',   name: 'laptop-max',        kind: 'WS',    trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.80',   name: 'laptop-guest',      kind: 'WS',    trusted: false, network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.100',  name: 'printer-floor3',    kind: 'PRT',   trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '10.0.1.101',  name: 'voip-gateway',      kind: 'GW',    trusted: true,  network: { id: 'net-it',    name: 'Office-IT',   cidr: '10.0.1.0/24' } },
  { ip: '192.168.100.10', name: 'reverse-proxy',  kind: 'GW',    trusted: true,  network: { id: 'net-dmz',   name: 'DMZ',         cidr: '192.168.100.0/24' } },
  { ip: '192.168.100.11', name: 'web-portal',     kind: 'SRV',   trusted: true,  network: { id: 'net-dmz',   name: 'DMZ',         cidr: '192.168.100.0/24' } },
  { ip: '10.0.2.5',    name: 'fw-main',           kind: 'FW',    trusted: true,  network: { id: 'net-mgmt',  name: 'Management',  cidr: '10.0.2.0/24' } },
  { ip: '10.0.2.6',    name: 'switch-core',       kind: 'SW',    trusted: true,  network: { id: 'net-mgmt',  name: 'Management',  cidr: '10.0.2.0/24' } },
  { ip: '8.8.8.8',     name: 'google-dns',        kind: 'EXT',   trusted: false },
  { ip: '193.99.144.80', name: 'heise.de',        kind: 'EXT',   trusted: false },
  { ip: '45.33.32.156',  name: 'c2-suspicious',   kind: 'EXT',   trusted: false },
];

export function demoHosts(): Host[] {
  const now = new Date().toISOString();
  return DEMO_HOSTS_META.map(h => ({
    ip:           h.ip,
    hostname:     h.name,
    display_name: h.name,
    trusted:      h.trusted,
    trust_source: h.trusted ? 'manual' : undefined,
    ping_ms:      h.kind === 'EXT' ? Math.round(10 + Math.random() * 40) : Math.round(0.2 + Math.random() * 3),
    last_seen:    now,
    updated_at:   now,
  }));
}

// ─── Alert-Templates ────────────────────────────────────────────────────────

interface AlertTpl {
  rule_id:     string;
  severity:    Alert['severity'];
  source:      'signature' | 'ml' | 'suricata' | 'external';
  proto:       'TCP' | 'UDP' | 'ICMP';
  description: string;
  tags:        string[];
  dst_port?:   number;
  srcPool:     string[];
  dstPool:     string[];
  scoreRange:  [number, number];
}

const OT_HOSTS  = ['10.10.20.10','10.10.20.11','10.10.20.12','10.10.20.20','10.10.20.21','10.10.20.30'];
const SCADA     = ['10.10.30.10','10.10.30.11','10.10.30.20','10.10.30.21'];
const OFFICE    = ['10.0.1.10','10.0.1.11','10.0.1.50','10.0.1.51','10.0.1.52','10.0.1.53','10.0.1.80'];
const EXTERN    = ['45.33.32.156','193.99.144.80'];

const TEMPLATES: AlertTpl[] = [
  { rule_id: 'MODBUS_UNAUTH_502',        severity: 'high',     source: 'signature', proto: 'TCP', description: 'Unauthorisierter Modbus-TCP-Write auf kritischem PLC-Register',                   tags: ['modbus','ics','ot','write'],              dst_port: 502,   srcPool: OFFICE,  dstPool: OT_HOSTS,  scoreRange: [0.78, 0.92] },
  { rule_id: 'DNP3_OUTSTATION_SCAN',     severity: 'medium',   source: 'signature', proto: 'TCP', description: 'DNP3 Outstation-Scan aus IT-Netz auf SCADA-Ring',                                   tags: ['dnp3','ics','ot','recon'],                dst_port: 20000, srcPool: OFFICE,  dstPool: SCADA,     scoreRange: [0.55, 0.70] },
  { rule_id: 'S7COMM_WRITE_VAR',         severity: 'critical', source: 'signature', proto: 'TCP', description: 'S7Comm WRITE_VAR auf DB1 – Eingriff in Produktionslogik möglich',                  tags: ['s7comm','ics','ot','critical'],           dst_port: 102,   srcPool: ['10.0.1.80'], dstPool: OT_HOSTS, scoreRange: [0.88, 0.98] },
  { rule_id: 'OPC_UA_UNAUTH_SUB',        severity: 'medium',   source: 'signature', proto: 'TCP', description: 'OPC-UA Subscription ohne gültiges Security-Profile',                                tags: ['opc-ua','ot','auth'],                     dst_port: 4840,  srcPool: OFFICE,  dstPool: SCADA,     scoreRange: [0.40, 0.55] },
  { rule_id: 'ML_ANOMALY_FLOWRATE',      severity: 'high',     source: 'ml',        proto: 'TCP', description: 'IsolationForest: Ungewöhnlich hohe Flow-Rate · IAT-Entropie tief',                  tags: ['ml','anomaly','flow'],                                    srcPool: OT_HOSTS, dstPool: EXTERN, scoreRange: [0.72, 0.89] },
  { rule_id: 'ML_ANOMALY_BEACON',        severity: 'high',     source: 'ml',        proto: 'TCP', description: 'Periodisches Beacon-Pattern erkannt – möglicher C2-Kanal',                          tags: ['ml','anomaly','c2','beaconing'],                          srcPool: OT_HOSTS, dstPool: EXTERN, scoreRange: [0.80, 0.95] },
  { rule_id: 'ML_ANOMALY_LATERAL',       severity: 'medium',   source: 'ml',        proto: 'TCP', description: 'Ungewohnte laterale Verbindung: Workstation → PLC',                                  tags: ['ml','anomaly','lateral'],                                 srcPool: OFFICE,   dstPool: OT_HOSTS, scoreRange: [0.55, 0.72] },
  { rule_id: 'ML_ANOMALY_DATASIZE',      severity: 'medium',   source: 'ml',        proto: 'TCP', description: 'Ungewöhnlich große Payload bei OT-Protokoll',                                       tags: ['ml','anomaly','exfil'],                                    srcPool: SCADA,    dstPool: EXTERN, scoreRange: [0.48, 0.65] },
  { rule_id: 'ML_ANOMALY_ENTROPY',       severity: 'low',      source: 'ml',        proto: 'UDP', description: 'Niedrige Paket-Inter-Arrival-Entropie – möglicher Tunnel',                          tags: ['ml','anomaly','entropy'],                                 srcPool: OFFICE,   dstPool: EXTERN, scoreRange: [0.22, 0.45] },
  { rule_id: 'SURICATA:1:2019401:1',     severity: 'medium',   source: 'suricata',  proto: 'TCP', description: 'ET SCADA Modbus Force Single Coil',                                                  tags: ['suricata','scada','modbus'],              dst_port: 502,   srcPool: OFFICE, dstPool: OT_HOSTS,  scoreRange: [0.50, 0.65] },
  { rule_id: 'SURICATA:1:2018927:1',     severity: 'high',     source: 'suricata',  proto: 'TCP', description: 'ET SCADA Modbus Read Coils Probe auf Engineering-Netz',                             tags: ['suricata','scada','modbus','probe'],      dst_port: 502,   srcPool: OFFICE, dstPool: OT_HOSTS,  scoreRange: [0.70, 0.85] },
  { rule_id: 'SURICATA:1:2221034:1',     severity: 'medium',   source: 'suricata',  proto: 'TCP', description: 'SURICATA HTTP Request unrecognized authorization method',                           tags: ['suricata','http','auth'],                 dst_port: 80,    srcPool: OFFICE, dstPool: ['192.168.100.11'], scoreRange: [0.45, 0.60] },
  { rule_id: 'SURICATA:1:2210054:1',     severity: 'medium',   source: 'suricata',  proto: 'TCP', description: 'SURICATA STREAM excessive retransmissions',                                         tags: ['suricata','stream','tcp'],                                 srcPool: OT_HOSTS, dstPool: SCADA, scoreRange: [0.42, 0.58] },
  { rule_id: 'DOS_UDP_FLOOD_001',        severity: 'critical', source: 'signature', proto: 'UDP', description: 'Sehr hohe UDP-Paketrate (>10000 pps) von einer Quelle – DoS-Verdacht',              tags: ['dos','udp','flood'],                      dst_port: 1900, srcPool: ['10.0.1.80'], dstPool: ['239.255.255.250','10.0.2.5'], scoreRange: [0.90, 0.99] },
  { rule_id: 'DNS_AMP_001',              severity: 'medium',   source: 'signature', proto: 'UDP', description: 'Viele kleine DNS-UDP-Anfragen – mögliche Reflection-Amplification-Quelle',          tags: ['dns','amplification','dos'],              dst_port: 53,    srcPool: OFFICE, dstPool: ['8.8.8.8'],       scoreRange: [0.40, 0.55] },
  { rule_id: 'ANOMALY_FRAGMENT_001',     severity: 'low',      source: 'signature', proto: 'TCP', description: 'Hoher Anteil fragmentierter IP-Pakete – mögliche Evasion-Technik',                  tags: ['anomaly','evasion','fragment'],                            srcPool: OFFICE, dstPool: ['192.168.100.10'], scoreRange: [0.18, 0.30] },
  { rule_id: 'UNKNOWN_HOST_001',         severity: 'low',      source: 'signature', proto: 'TCP', description: 'Unbekannter interner Host – nicht in host_info als trusted',                        tags: ['inventory','unknown'],                                     srcPool: ['10.0.1.80'], dstPool: ['10.0.1.10'], scoreRange: [0.10, 0.22] },
  { rule_id: 'IRMA_BLOCKLIST_HIT',       severity: 'high',     source: 'external',  proto: 'TCP', description: 'IRMA-Bridge: Blocklist-Hit – bekannter C2-Indikator',                               tags: ['external','irma','blocklist','c2'],       dst_port: 443,   srcPool: OT_HOSTS, dstPool: EXTERN, scoreRange: [0.75, 0.92] },
  { rule_id: 'IRMA_POLICY_VIOLATION',    severity: 'medium',   source: 'external',  proto: 'TCP', description: 'IRMA: Protokoll-Policy verletzt (Modbus → Internet)',                               tags: ['external','irma','policy','ot'],          dst_port: 502,   srcPool: OT_HOSTS, dstPool: EXTERN, scoreRange: [0.55, 0.70] },
  { rule_id: 'ICMP_SWEEP_001',           severity: 'low',      source: 'signature', proto: 'ICMP',description: 'ICMP-Sweep erkannt – Host-Discovery im Subnetz',                                     tags: ['icmp','recon','sweep'],                                    srcPool: ['10.0.1.80'], dstPool: OT_HOSTS, scoreRange: [0.20, 0.35] },
];

function pick<T>(arr: T[]): T { return arr[Math.floor(Math.random() * arr.length)]; }

function metaFor(ip: string) {
  return DEMO_HOSTS_META.find(h => h.ip === ip);
}

let counter = 0;
function nextId(): string {
  counter++;
  const hex = counter.toString(16).padStart(8, '0');
  return `demo-${hex}-1234-5678-9abc-def012345678`;
}

function buildAlert(tpl: AlertTpl, atMs: number): Alert {
  const src = pick(tpl.srcPool);
  const dst = pick(tpl.dstPool);
  const score = tpl.scoreRange[0] + Math.random() * (tpl.scoreRange[1] - tpl.scoreRange[0]);
  const dstPort = tpl.dst_port ?? 1024 + Math.floor(Math.random() * 60000);
  const srcMeta = metaFor(src);
  const dstMeta = metaFor(dst);
  return {
    alert_id:    nextId(),
    ts:          new Date(atMs).toISOString(),
    source:      tpl.source,
    rule_id:     tpl.rule_id,
    severity:    tpl.severity,
    score,
    src_ip:      src,
    dst_ip:      dst,
    dst_port:    dstPort,
    proto:       tpl.proto,
    description: tpl.description,
    tags:        [...tpl.tags],
    pcap_available: Math.random() > 0.2,
    is_test:     false,
    enrichment: {
      src_display_name: srcMeta?.name,
      src_hostname:     srcMeta?.name,
      src_trusted:      srcMeta?.trusted,
      src_trust_source: srcMeta?.trusted ? 'manual' : undefined,
      src_network:      srcMeta?.network,
      src_ping_ms:      srcMeta?.kind === 'EXT' ? 28 : 0.3,
      dst_display_name: dstMeta?.name,
      dst_hostname:     dstMeta?.name,
      dst_trusted:      dstMeta?.trusted,
      dst_trust_source: dstMeta?.trusted ? 'manual' : undefined,
      dst_network:      dstMeta?.network,
      dst_ping_ms:      dstMeta?.kind === 'EXT' ? 32 : 0.5,
    },
  };
}

// Weighted pool: critical 2, high 8, medium 20, low 20 per hour distribution
const WEIGHTED: AlertTpl[] = (() => {
  const out: AlertTpl[] = [];
  for (const t of TEMPLATES) {
    const weight = t.severity === 'critical' ? 1
                 : t.severity === 'high'     ? 3
                 : t.severity === 'medium'   ? 5
                 :                             6;
    for (let i = 0; i < weight; i++) out.push(t);
  }
  return out;
})();

export function generateInitialAlerts(): Alert[] {
  const now = Date.now();
  const alerts: Alert[] = [];
  // 90 alerts spread across last 3 hours, denser in last hour
  for (let i = 0; i < 90; i++) {
    const tpl = pick(WEIGHTED);
    // Bias toward recent: most in last hour
    const bias = Math.pow(Math.random(), 1.8);
    const ageMs = bias * 3 * 3600 * 1000;
    alerts.push(buildAlert(tpl, now - ageMs));
  }
  return alerts.sort((a, b) => Date.parse(b.ts) - Date.parse(a.ts));
}

export function generateLiveAlert(): Alert {
  // Slightly ML-biased so the ML filter shows activity
  const pool = Math.random() < 0.35 ? TEMPLATES.filter(t => t.source === 'ml') : WEIGHTED;
  return buildAlert(pick(pool), Date.now());
}

// ─── ThreatLevel ────────────────────────────────────────────────────────────

export function computeThreatLevel(alerts: Alert[]): ThreatLevel {
  const last15 = alerts.filter(a => Date.now() - Date.parse(a.ts) < 15 * 60 * 1000);
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const a of last15) counts[a.severity]++;
  const score = Math.min(100, counts.critical * 25 + counts.high * 12 + counts.medium * 3 + counts.low * 1);
  const label = score >= 75 ? 'red' : score >= 50 ? 'orange' : score >= 25 ? 'yellow' : 'green';
  return {
    level: score,
    label,
    alert_counts: counts,
    window_min: 15,
  };
}

// ─── Connection-Graph (für AlertFlowPopup) ─────────────────────────────────

export function generateConnectionGraph(srcIp: string, dstIp: string) {
  const now = new Date().toISOString();
  const base = new Date(Date.now() - 60_000).toISOString();
  const protoPool: ('TCP' | 'UDP' | 'ICMP')[] = ['TCP','TCP','TCP','UDP','ICMP'];
  const n = 4 + Math.floor(Math.random() * 4);
  const connections = [];
  for (let i = 0; i < n; i++) {
    const isForward = Math.random() > 0.3;
    const proto = protoPool[Math.floor(Math.random() * protoPool.length)];
    const port = [80, 443, 502, 4840, 20000, 22, 3389][Math.floor(Math.random() * 7)];
    connections.push({
      src_ip:     isForward ? srcIp : dstIp,
      dst_ip:     isForward ? dstIp : srcIp,
      dst_port:   proto === 'ICMP' ? null : port,
      proto,
      flow_count: 1 + Math.floor(Math.random() * 6),
      pkt_count:  10 + Math.floor(Math.random() * 400),
      byte_count: 512 + Math.floor(Math.random() * 80_000),
      first_seen: base,
      last_seen:  now,
    });
  }
  return {
    src_ip: srcIp,
    dst_ip: dstIp,
    window_min: 5,
    total_flows: connections.reduce((s, c) => s + c.flow_count, 0),
    connections,
  };
}
