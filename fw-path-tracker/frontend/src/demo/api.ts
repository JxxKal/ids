// Demo-Antworten: entsprechen der Phase-4-Testmatrix (Lab-Fixtures).
import type {
  InventorySummary, SearchHit, Session, SyncStatus,
  TraceHistoryEntry, TraceRequest, TraceResult,
} from '../types';

export function login(): Session {
  return { token: 'demo-token', username: 'demo', role: 'admin' };
}

const allowCandidate = {
  policyid: 100, name: 'allow-inside', action: 'accept',
  srcintf: ['inside-a'], dstintf: ['any'], srcaddr: ['all'], dstaddr: ['all'],
  service: ['ALL'], comments: '', hit: true,
};
const denyCandidate = {
  policyid: 110, name: 'deny-guest', action: 'deny',
  srcintf: ['any'], dstintf: ['any'], srcaddr: ['all'], dstaddr: ['all'],
  service: ['ALL'], comments: '', hit: false,
};

export function trace(req: TraceRequest): TraceResult {
  const deny = req.dst.includes('9.9') || req.dst_port === 23;
  return {
    verdict: deny ? 'DENY' : 'ALLOW',
    src: {
      ip: '10.1.1.10',
      names: [{ name: 'ws0042.corp.example', provenance: 'dns' }],
      provenance: 'ip',
    },
    dst: {
      ip: deny ? '10.2.9.9' : '10.2.1.30',
      names: deny ? [] : [{ name: 'srv-db', provenance: 'fmg' }],
      provenance: 'fmg',
    },
    protocol: req.protocol, dst_port: req.dst_port ?? null,
    src_port: null, icmp_type: null, icmp_code: null,
    hops: [
      {
        index: 0, device: 'fw-a', vdom: 'root', adom: 'corp',
        srcintf: 'lan1', src_zone: 'inside-a',
        egress: 'vpn-to-b', egress_zone: 'overlay', egress_class: 'OVERLAY',
        route: { interface: 'vpn-to-b', gateway: '0.0.0.0', source: 'live' },
        verdict: 'ALLOW', matched_policy: allowCandidate,
        candidates: [allowCandidate, denyCandidate],
        suggestion: null, warnings: [], degraded: false, after_deny: false,
      },
      {
        index: 1, device: 'fw-b', vdom: 'root', adom: 'corp',
        srcintf: 'vpn-to-a', src_zone: 'overlay',
        egress: 'lan1', egress_zone: 'lan1', egress_class: 'LOCAL',
        route: { interface: 'lan1', gateway: null, source: 'live' },
        verdict: deny ? 'DENY' : 'ALLOW',
        matched_policy: deny ? null : { ...allowCandidate, policyid: 200, name: 'allow-from-a' },
        candidates: [
          { ...allowCandidate, policyid: 200, name: 'allow-from-a', hit: !deny },
          { ...denyCandidate, policyid: 210, name: 'deny-legacy' },
        ],
        suggestion: deny ? {
          device: 'fw-b', vdom: 'root', adom: 'corp', package: 'pkg-b',
          src_zone: 'overlay', dst_zone: 'lan1',
          src_obj: { name: 'net-site-a', existing: true },
          dst_obj: { name: 'h-10.2.9.9', existing: false, subnet: '10.2.9.9/32' },
          service: { name: 'svc-tcp-23', existing: false, protocol: 'tcp', port: 23 },
          policy_name: 'allow-net-site-a-to-h-10.2.9.9-svc-tcp-23',
          cli: 'config firewall address\n    edit "h-10.2.9.9"\n        set subnet 10.2.9.9 255.255.255.255\n    next\nend\nconfig firewall policy\n    edit 0\n        set name "allow-net-site-a-to-h-10.2.9.9-svc-tcp-23"\n        set srcintf "overlay"\n        set dstintf "lan1"\n        set srcaddr "net-site-a"\n        set dstaddr "h-10.2.9.9"\n        set service "svc-tcp-23"\n        set action accept\n        set schedule always\n    next\nend',
          jsonrpc: ['{\n  "method": "add",\n  "params": [{"url": "/pm/config/adom/corp/pkg/pkg-b/firewall/policy", "data": {"name": "allow-…"}}]\n}'],
          note: 'Nur Vorschlag — Installation via FortiManager erforderlich. Der Tracker hat keinen Schreibzugriff.',
        } : null,
        warnings: [], degraded: false, after_deny: false,
      },
    ],
    warnings: [], vip: null, duration_ms: 412,
    inventory_synced_at: new Date().toISOString(),
  };
}

export function search(q: string): SearchHit[] {
  const hits: SearchHit[] = [
    { name: 'srv-db', ip: '10.2.1.30', provenance: 'fmg' },
    { name: 'srv-web01', ip: '10.2.1.31', provenance: 'itop' },
    { name: 'ws0042', ip: '10.1.1.10', provenance: 'itop' },
  ];
  return hits.filter((h) => h.name.includes(q.toLowerCase()));
}

export function traces(): TraceHistoryEntry[] {
  return [
    {
      id: 1, created_at: new Date(Date.now() - 3600e3).toISOString(),
      username: 'demo',
      request: { src: '10.1.1.10', dst: 'srv-db', protocol: 'tcp', dst_port: 443 },
      verdict: 'ALLOW', duration_ms: 380,
    },
    {
      id: 2, created_at: new Date(Date.now() - 7200e3).toISOString(),
      username: 'demo',
      request: { src: '10.1.1.10', dst: '10.2.9.9', protocol: 'tcp', dst_port: 23 },
      verdict: 'DENY', duration_ms: 401,
    },
  ];
}

export function syncStatus(): SyncStatus {
  return {
    phase: 'done',
    log: ['[08:00:01] ADOM \'corp\': Geräte laden ...', '[08:00:09] Sync abgeschlossen'],
    stats: { 'corp:devices': 2, 'corp:policies': 4 },
    started_at: null, finished_at: new Date().toISOString(),
  };
}

export function inventorySummary(): InventorySummary {
  return {
    synced_at: new Date().toISOString(),
    adoms: ['corp'],
    devices: {
      'fw-a': { adom: 'corp', vdoms: ['root', 'dmz'] },
      'fw-b': { adom: 'corp', vdoms: ['root'] },
    },
    counts: { policies: 4, addresses: 2, services: 1, vips: 1, zones: 3 },
  };
}
