import { useEffect, useState, useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { Alert, Enrichment, RemoteTap } from '../types';
import { alertsExportUrl, createEgressWhitelist, fetchTaps } from '../api';
import { countryFlag, geoTooltip } from '../lib/country';
import { AlertDetail } from './AlertDetail';
import { HelpTip } from './HelpTip';
import { SeverityBadge } from './SeverityBadge';
import { PcapPreview } from './PcapPreview';

// ── PCAP-Vorschau ─────────────────────────────────────────────────────────────

function PcapButton({ alertId, available }: { alertId: string; available: boolean }) {
  const { t } = useTranslation();
  const [show, setShow] = useState(false);

  return (
    <>
      <button
        onClick={e => { e.stopPropagation(); if (available) setShow(true); }}
        disabled={!available}
        title={available ? t('alertFeed.pcap.open') : t('alertFeed.pcap.unavailable')}
        className={`px-1.5 py-0.5 rounded text-[11px] border whitespace-nowrap transition-colors ${
          available
            ? 'border-blue-700/50 text-blue-400 bg-blue-950/30 hover:bg-blue-900/50 hover:text-blue-300'
            : 'border-slate-700/30 text-slate-600 bg-transparent cursor-default'
        } disabled:opacity-40`}
      >
        ⧉ pcap
      </button>
      {show && <PcapPreview alertId={alertId} onClose={() => setShow(false)} />}
    </>
  );
}

// ── IP-Zelle mit Hostname + Trust-Badge ────────────────────────────────────────

function IpCell({
  ip, port, enrichment, dir,
}: {
  ip?: string;
  port?: number;
  enrichment?: Enrichment;
  dir: 'src' | 'dst';
}) {
  const { t } = useTranslation();
  const hostname    = dir === 'src' ? enrichment?.src_hostname    : enrichment?.dst_hostname;
  const displayName = dir === 'src' ? enrichment?.src_display_name: enrichment?.dst_display_name;
  const trusted     = dir === 'src' ? enrichment?.src_trusted      : enrichment?.dst_trusted;
  const trustSrc    = dir === 'src' ? enrichment?.src_trust_source : enrichment?.dst_trust_source;
  const geo         = dir === 'src' ? enrichment?.src_geo           : enrichment?.dst_geo;

  const primary  = displayName ?? hostname ?? ip ?? '–';
  const showIp   = !!ip && primary !== ip;
  const portStr  = port ? `:${port}` : '';
  const srcLabel = trustSrc ? t(`trust.sources.${trustSrc}`, { defaultValue: trustSrc }) : null;

  // Flagge nur bei Public-IPs sichtbar — der Enrichment-Service liefert
  // für private/Multicast-IPs keinen country_code, deshalb reicht der
  // Truthy-Check. Tooltip: Land + (wenn vorhanden) Stadt.
  const flag = countryFlag(geo?.country_code);
  const geoTitle = geoTooltip(geo);

  return (
    <div className="leading-tight">
      <span className="text-slate-300">
        {flag && (
          <span
            className="mr-1 align-baseline cursor-help"
            title={geoTitle || geo?.country_code || ''}
          >
            {flag}
          </span>
        )}
        {primary}{!showIp ? portStr : ''}
      </span>
      {showIp && (
        <div className="text-slate-600 text-[10px]">{ip}{portStr}</div>
      )}
      {trusted && (
        <span
          className="inline-flex items-center gap-0.5 text-[10px] text-green-400 bg-green-950/50 border border-green-800/40 rounded px-1 mt-0.5"
          title={srcLabel ? t('trust.validatedVia', { source: srcLabel }) : t('trust.validated')}
        >
          ✓{srcLabel && <span className="text-green-600">{srcLabel}</span>}
        </span>
      )}
    </div>
  );
}


interface Props {
  alerts: Alert[];
  onUpdate: (a: Alert) => void;
  showTest: boolean;
  mlOnly: boolean;
  // Tap-Filter wird in App.tsx hochgehalten, damit der historic-Fetch
  // ihn als Server-Param mitgeben kann (sonst Limit-Cutoff-Problem).
  tapFilter: string;
  onTapFilterChange: (v: string) => void;
}

const SEVERITIES_ORDERED = ['critical', 'high', 'medium', 'low'] as const;

const ROW_SEVERITY: Record<string, string> = {
  critical: 'cyjan-row-critical',
  high:     'cyjan-row-high',
  medium:   'cyjan-row-medium',
  low:      'cyjan-row-low',
};

// ── Gruppierung ────────────────────────────────────────────────────────────────

interface AlertGroup {
  key:           string;
  severity:      Alert['severity'];
  rule_id?:      string;
  src_ip?:       string;
  dst_ip?:       string;
  proto?:        string;
  dst_port?:     number;
  description?:  string;
  tags:          string[];
  count:         number;
  first_ts:      string;
  last_ts:       string;
  latest:        Alert;
  enrichment?:   Enrichment;
  bidirectional: boolean;
}

const OT_TAGS = new Set(['scada', 'ics', 'modbus', 'dnp3', 'ethernet/ip', 'bacnet', 'ot']);

// ── Application-Protocol-Ableitung aus Port + L4 ──────────────────────────────

const PORT_MAP: Record<number, string> = {
  20: 'FTP-DATA', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP',
  53: 'DNS', 67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP',
  88: 'Kerberos', 110: 'POP3', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS',
  138: 'NetBIOS', 139: 'SMB', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP',
  179: 'BGP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS',
  500: 'IKE', 514: 'Syslog', 587: 'SMTP', 636: 'LDAPS',
  993: 'IMAPS', 995: 'POP3S', 1194: 'OpenVPN', 1433: 'MSSQL',
  1521: 'Oracle', 1812: 'RADIUS', 1813: 'RADIUS', 1883: 'MQTT',
  1900: 'SSDP', 3128: 'HTTP-Proxy', 3306: 'MySQL', 3389: 'RDP',
  5060: 'SIP', 5061: 'SIPS', 5353: 'mDNS', 5432: 'PostgreSQL',
  5683: 'CoAP', 5900: 'VNC', 6379: 'Redis', 8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt', 8883: 'MQTTS',
  // ── OT/SCADA ──────────────────────────────────────────────────────────────
  102: 'S7/ISO-TSAP',
  502: 'Modbus',
  789: 'Red-Lion',
  1089: 'FF-Annunciation', 1090: 'FF-FMS', 1091: 'FF-System',
  1962: 'PCWorX',
  2222: 'EtherNet/IP',
  4840: 'OPC-UA',
  9600: 'OMRON-FINS',
  18245: 'Siemens-GE-SRTP',
  18246: 'Siemens-GE-SRTP',
  20000: 'DNP3',
  34962: 'PROFINET', 34963: 'PROFINET', 34964: 'PROFINET',
  44818: 'EtherNet/IP',
  47808: 'BACnet',
};

function appProto(proto: string | undefined, dstPort: number | null | undefined, srcPort: number | null | undefined): string {
  // ICMP behält seinen Namen
  const p = (proto ?? '').toUpperCase();
  if (p === 'ICMP' || p === 'ICMPV6') return p;

  // Well-known port lookup (dst bevorzugt, dann src)
  if (dstPort && PORT_MAP[dstPort]) return PORT_MAP[dstPort];
  if (srcPort && PORT_MAP[srcPort]) return PORT_MAP[srcPort];

  return p || '–';
}

// ── Egress-Boundary-Badges ────────────────────────────────────────────────────

const PRIORITY_COLOR: Record<string, string> = {
  P0: 'bg-red-900/50 text-red-300 border-red-700/50',
  P1: 'bg-orange-900/50 text-orange-300 border-orange-700/50',
  P2: 'bg-amber-900/40 text-amber-300 border-amber-700/40',
  P3: 'bg-slate-700/50 text-slate-400 border-slate-600/40',
};

function BoundaryCell({ alert }: { alert: Alert }) {
  const { t } = useTranslation();
  if (!alert.boundary_priority) return <span className="text-slate-700">–</span>;

  const Pill = ({ ok, label }: { ok: boolean | null | undefined; label: string }) => (
    <span
      className={`inline-block px-1 text-[9px] font-mono rounded border ${
        ok ? 'bg-green-950/40 text-green-400 border-green-800/40' : 'bg-red-950/40 text-red-400 border-red-800/40'
      }`}
      title={`${label}: ${ok ? t('alertFeed.boundary.known') : t('alertFeed.boundary.unknown')}`}
    >
      {label}{ok ? '✓' : '✗'}
    </span>
  );

  return (
    <HelpTip helpKey="boundaryCell">
      <div className="flex flex-col gap-0.5">
        <span className={`px-1.5 py-0.5 text-[10px] font-mono rounded border w-fit ${PRIORITY_COLOR[alert.boundary_priority] ?? ''}`}>
          {alert.boundary_priority}
          {alert.boundary_whitelisted && <span className="ml-1 opacity-70">·WL</span>}
        </span>
        <span className="flex gap-0.5">
          <Pill ok={alert.boundary_net_known} label="N" />
          <Pill ok={alert.boundary_src_known} label="S" />
          <Pill ok={alert.boundary_dst_known} label="D" />
        </span>
      </div>
    </HelpTip>
  );
}

// ── Whitelist-Modal ───────────────────────────────────────────────────────────

function WhitelistModal({
  alert, onClose, onCreated,
}: {
  alert:     Alert;
  onClose:   () => void;
  onCreated: () => void;
}) {
  const { t } = useTranslation();
  const [scope, setScope] = useState<'src' | 'src+dst' | 'src+net' | 'src+port' | 'src+dst+port'>('src+dst');
  const [reason, setReason] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError]   = useState('');

  const buildBody = () => {
    const body: { src_ip: string; reason: string; dst_ip?: string; dst_net?: string; dst_port?: number; proto?: 'TCP' | 'UDP' | 'ICMP' } = {
      src_ip: alert.src_ip ?? '',
      reason: reason.trim(),
    };
    if (scope === 'src+dst' || scope === 'src+dst+port') body.dst_ip = alert.dst_ip ?? undefined;
    if (scope === 'src+net' && alert.dst_ip) {
      // Triviale /24 ableiten (kein vollständiger CIDR-Picker im v1).
      const parts = alert.dst_ip.split('.');
      if (parts.length === 4) body.dst_net = `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    }
    if (scope === 'src+port' || scope === 'src+dst+port') body.dst_port = alert.dst_port ?? undefined;
    if (alert.proto && (alert.proto === 'TCP' || alert.proto === 'UDP' || alert.proto === 'ICMP')) {
      body.proto = alert.proto;
    }
    return body;
  };

  const handleSave = async () => {
    setError('');
    if (!alert.src_ip) {
      setError(t('alertFeed.whitelistModal.noSrcIp'));
      return;
    }
    if (reason.trim().length < 3) {
      setError(t('alertFeed.whitelistModal.reasonRequired'));
      return;
    }
    setSaving(true);
    try {
      await createEgressWhitelist(buildBody());
      onCreated();
      onClose();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  return (
    <div
      className="fixed inset-0 bg-black/70 flex items-center justify-center z-[55] p-4"
      onClick={onClose}
    >
      <div className="cyjan-card w-full max-w-md p-5 rounded-xl space-y-4" onClick={e => e.stopPropagation()}>
        <h3 className="text-sm font-semibold text-slate-200">{t('alertFeed.whitelistModal.title')}</h3>

        <div className="text-xs text-slate-400 space-y-1 font-mono">
          <div>{t('alertFeed.whitelistModal.srcLabel')}: <span className="text-slate-200">{alert.src_ip ?? '–'}</span></div>
          <div>{t('alertFeed.whitelistModal.dstLabel')}: <span className="text-slate-200">{alert.dst_ip ?? '–'}{alert.dst_port ? `:${alert.dst_port}` : ''}</span></div>
          <div>{t('alertFeed.whitelistModal.protoLabel')}: <span className="text-slate-200">{alert.proto ?? '–'}</span></div>
        </div>

        <div>
          <label className="text-xs font-medium text-slate-300 block mb-1">{t('alertFeed.whitelistModal.scopeLabel')}</label>
          <select
            className="cyjan-input w-full text-xs"
            value={scope}
            onChange={e => setScope(e.target.value as typeof scope)}
          >
            <option value="src">{t('alertFeed.whitelistModal.scopeSrc')}</option>
            <option value="src+dst">{t('alertFeed.whitelistModal.scopeSrcDst')}</option>
            <option value="src+net">{t('alertFeed.whitelistModal.scopeSrcNet')}</option>
            <option value="src+port">{t('alertFeed.whitelistModal.scopeSrcPort')}</option>
            <option value="src+dst+port">{t('alertFeed.whitelistModal.scopeSrcDstPort')}</option>
          </select>
        </div>

        <div>
          <label className="text-xs font-medium text-slate-300 block mb-1">{t('alertFeed.whitelistModal.reasonLabel')}</label>
          <textarea
            className="cyjan-input w-full text-xs"
            rows={3}
            placeholder={t('alertFeed.whitelistModal.reasonPlaceholder')}
            value={reason}
            onChange={e => setReason(e.target.value)}
          />
        </div>

        {error && <p className="text-xs text-red-400">{error}</p>}

        <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
          <button onClick={onClose} className="btn-ghost text-xs" disabled={saving}>{t('common.cancel')}</button>
          <button
            onClick={handleSave}
            disabled={saving || reason.trim().length < 3}
            className="btn-primary text-xs disabled:opacity-50"
          >
            {saving ? '…' : t('alertFeed.whitelistModal.save')}
          </button>
        </div>
      </div>
    </div>
  );
}

function FeedbackBadge({ feedback }: { feedback: 'fp' | 'tp' }) {
  const { t } = useTranslation();
  return feedback === 'fp'
    ? <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border text-[10px] leading-none bg-green-950/50 text-green-300 border-green-700/40" title={t('alertFeed.feedback.fpTitle')}>✓ FP</span>
    : <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border text-[10px] leading-none bg-red-950/50 text-red-300 border-red-700/40"   title={t('alertFeed.feedback.tpTitle')}>⚠ TP</span>;
}

function TagList({ tags }: { tags: string[] }) {
  if (!tags.length) return <span className="text-slate-700">–</span>;
  return (
    <div className="flex flex-wrap gap-1">
      {tags.map(t => {
        const isOt = OT_TAGS.has(t.toLowerCase());
        return (
          <span key={t} className={`px-1.5 py-0.5 text-[10px] rounded border leading-none ${
            isOt
              ? 'bg-orange-900/40 text-orange-300 border-orange-700/40'
              : 'bg-slate-700/50 text-slate-400 border-slate-600/30'
          }`}>{t}</span>
        );
      })}
    </div>
  );
}

/** Wandelt ts (ISO-String oder Unix-Float) in Millisekunden um. */
function tsMs(ts: string | number): number {
  if (typeof ts === 'number') return ts * 1000;
  return new Date(ts).getTime();
}

function fmtTime(ts: string | number): string {
  return new Date(tsMs(ts)).toLocaleTimeString();
}

/** Normalisierter Session-Key: gleiche Session in beide Richtungen → gleicher Key. */
function sessionKey(ipA?: string, ipB?: string): string {
  const a = ipA ?? '–';
  const b = ipB ?? '–';
  return a <= b ? `${a}|${b}` : `${b}|${a}`;
}

const SEV_RANK: Record<Alert['severity'], number> = {
  critical: 4, high: 3, medium: 2, low: 1,
};

function maxSeverity(a: Alert['severity'], b: Alert['severity']): Alert['severity'] {
  return (SEV_RANK[b] ?? 0) > (SEV_RANK[a] ?? 0) ? b : a;
}

function groupAlerts(alerts: Alert[]): AlertGroup[] {
  const map = new Map<string, AlertGroup>();

  for (const a of alerts) {
    const k = `${a.rule_id ?? '–'}::${sessionKey(a.src_ip, a.dst_ip)}`;
    const g = map.get(k);
    if (g) {
      g.count++;
      // Gruppen-Severity = höchste Severity aller enthaltenen Alerts.
      // Sonst würde eine Gruppe mit 1 critical + 4 low als 'low' angezeigt
      // (weil neuester low) und der Filter 'critical' würde sie nicht finden.
      g.severity = maxSeverity(g.severity, a.severity);
      // Richtungswechsel erkennen: wenn diese Quelle vorher das Ziel war
      if (a.src_ip && a.src_ip === g.dst_ip) g.bidirectional = true;
      if (tsMs(a.ts) > tsMs(g.last_ts)) {
        g.last_ts = a.ts;
        g.latest = a;
        g.description = a.description;
        // neueste Richtung für Anzeige übernehmen
        g.src_ip = a.src_ip; g.dst_ip = a.dst_ip;
        g.dst_port = a.dst_port;
      }
      if (tsMs(a.ts) < tsMs(g.first_ts)) g.first_ts = a.ts;
      if (!g.enrichment && a.enrichment) g.enrichment = a.enrichment;
      if (a.tags?.length) g.tags = [...new Set([...g.tags, ...a.tags])];
    } else {
      map.set(k, {
        key: k, severity: a.severity,
        rule_id: a.rule_id, src_ip: a.src_ip, dst_ip: a.dst_ip,
        proto: a.proto, dst_port: a.dst_port, description: a.description,
        tags: [...(a.tags ?? [])],
        count: 1, first_ts: a.ts, last_ts: a.ts, latest: a,
        enrichment: a.enrichment ?? undefined,
        bidirectional: false,
      });
    }
  }

  return [...map.values()].sort((a, b) => tsMs(b.last_ts) - tsMs(a.last_ts));
}

// ── Komponente ─────────────────────────────────────────────────────────────────

export function AlertFeed({ alerts, onUpdate, showTest, mlOnly, tapFilter, onTapFilterChange }: Props) {
  const { t } = useTranslation();
  const [selected,          setSelected]          = useState<Alert | null>(null);
  const [severityFilters,   setSeverityFilters]   = useState<string[]>([]);
  const [sourceF,           setSourceF]           = useState('');
  const [feedbackF,         setFeedbackF]         = useState('');
  const [search,            setSearch]            = useState('');
  const [grouped,           setGrouped]           = useState(true);
  const [suppressIrmaAsset, setSuppressIrmaAsset] = useState(false);
  // Egress-Boundary: 'off' (Default), 'on' (nur Egress, ohne Whitelisted),
  // 'on+wl' (Egress inklusive Whitelisted für Audit-View).
  const [egressMode,        setEgressMode]        = useState<'off' | 'on' | 'on+wl'>('off');
  const [sortByPriority,    setSortByPriority]    = useState(false);
  const [whitelistFor,      setWhitelistFor]      = useState<Alert | null>(null);
  const [whitelistedNotice, setWhitelistedNotice] = useState<string>('');
  // Tap-Filter: '' = alle, 'master' = nur lokal erzeugte Alerts (tap_id null),
  // sonst Tap-UUID. Hochgehalten in App.tsx, damit der historic-Fetch ihn
  // server-side anwenden kann. Lokale Filter-Logik unten greift zusätzlich
  // für Live-Mode (WebSocket broadcastet alle Alerts).
  const [taps,              setTaps]              = useState<RemoteTap[]>([]);

  useEffect(() => {
    let cancelled = false;
    fetchTaps()
      .then(rows => { if (!cancelled) setTaps(rows); })
      .catch(() => { /* Tap-Listing schlägt für non-Admin fehl – einfach
                        ohne Tap-Spalte/Filter weiterfahren. */ });
    return () => { cancelled = true; };
  }, []);
  const showTapColumn = taps.length > 0;
  const tapsById = useMemo(
    () => Object.fromEntries(taps.map(tap => [tap.id, tap])) as Record<string, RemoteTap>,
    [taps],
  );

  // Spalten-Sichtbarkeit (persistiert in localStorage). Time + Actions
  // bleiben immer sichtbar — sonst wird die Tabelle unleserlich.
  type ColKey = 'severity' | 'boundary' | 'tap' | 'rule' | 'proto' | 'description' | 'tags' | 'source' | 'destination' | 'hits';
  const ALL_COLS: { key: ColKey; label: string }[] = [
    { key: 'severity',    label: t('alertFeed.columns.severity') },
    { key: 'boundary',    label: t('alertFeed.columns.boundary') },
    { key: 'tap',         label: t('alertFeed.columns.tap') },
    { key: 'rule',        label: t('alertFeed.columns.rule') },
    { key: 'proto',       label: t('alertFeed.columns.proto') },
    { key: 'description', label: t('alertFeed.columns.description') },
    { key: 'tags',        label: t('alertFeed.columns.tags') },
    { key: 'source',      label: t('alertFeed.columns.source') },
    { key: 'destination', label: t('alertFeed.columns.destination') },
    { key: 'hits',        label: t('alertFeed.columns.hits') },
  ];
  const [hiddenCols, setHiddenCols] = useState<Set<ColKey>>(() => {
    try {
      const raw = localStorage.getItem('cyjan-alert-hidden-cols');
      if (raw) return new Set(JSON.parse(raw) as ColKey[]);
    } catch { /* corrupted — Default leer */ }
    return new Set();
  });
  useEffect(() => {
    try { localStorage.setItem('cyjan-alert-hidden-cols', JSON.stringify([...hiddenCols])); } catch { /* quota */ }
  }, [hiddenCols]);
  const showCol = (k: ColKey): boolean => !hiddenCols.has(k);
  const toggleCol = (k: ColKey) => setHiddenCols(prev => {
    const next = new Set(prev);
    if (next.has(k)) next.delete(k); else next.add(k);
    return next;
  });

  // Spalten-Breiten (persistiert in localStorage). 'time' ist nicht
  // ausblendbar, aber resizable. Werte in Pixeln; ohne Eintrag nutzt der
  // Browser sein Auto-Layout. Min-Breite 40px, sonst lassen sich Spalten
  // versehentlich auf 0 ziehen.
  type ResizeKey = 'time' | ColKey;
  const [colWidths, setColWidths] = useState<Partial<Record<ResizeKey, number>>>(() => {
    try {
      const raw = localStorage.getItem('cyjan-alert-col-widths');
      if (raw) return JSON.parse(raw) as Partial<Record<ResizeKey, number>>;
    } catch { /* corrupted — Default leer */ }
    return {};
  });
  useEffect(() => {
    try { localStorage.setItem('cyjan-alert-col-widths', JSON.stringify(colWidths)); } catch { /* quota */ }
  }, [colWidths]);
  const colStyle = (k: ResizeKey): React.CSSProperties => {
    const w = colWidths[k];
    return w ? { width: `${w}px`, minWidth: `${w}px`, maxWidth: `${w}px` } : {};
  };
  const startResize = (k: ResizeKey, e: React.MouseEvent<HTMLSpanElement>) => {
    e.preventDefault();
    e.stopPropagation();
    const startX = e.clientX;
    const th = (e.currentTarget.parentElement as HTMLElement | null);
    const startW = colWidths[k] ?? (th?.getBoundingClientRect().width ?? 120);
    const onMove = (ev: MouseEvent) => {
      const newW = Math.max(40, Math.round(startW + (ev.clientX - startX)));
      setColWidths(prev => ({ ...prev, [k]: newW }));
    };
    const onUp = () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
      document.body.style.cursor = '';
      document.body.style.userSelect = '';
    };
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    document.body.style.cursor = 'col-resize';
    document.body.style.userSelect = 'none';
  };
  // Helper: rendert ein <th> mit Drag-Handle. ckey identifiziert die
  // Spalte für Width-Persistierung. Inhalt als children. extraClass
  // erweitert die Standard-Klassen (z.B. text-right für hits).
  const ResizableTh = ({ ckey, children, extraClass = '' }: {
    ckey: ResizeKey; children: React.ReactNode; extraClass?: string;
  }) => (
    <th className={`px-3 py-2 relative ${extraClass}`} style={colStyle(ckey)}>
      {children}
      <span
        className="absolute right-0 top-1 bottom-1 w-1 cursor-col-resize bg-transparent hover:bg-cyan-500/40 active:bg-cyan-500/60"
        onMouseDown={e => startResize(ckey, e)}
        title={t('alertFeed.columnPicker.resizeHandleTitle')}
      />
    </th>
  );
  // td-Style spiegelt den th-Wert, sonst rendert table-auto u.U. anders
  // breit als der Header.
  const tdStyle = colStyle;

  const filtered = useMemo(() => {
    const q = search.toLowerCase();
    const PRIORITY_ORDER: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };
    const filteredArr = alerts.filter(a => {
      if (!showTest && a.is_test) return false;
      if (mlOnly && a.source !== 'ml') return false;
      if (suppressIrmaAsset && a.source === 'external' && a.rule_id?.startsWith('ASSET::')) return false;
      if (severityFilters.length && !severityFilters.includes(a.severity)) return false;
      if (sourceF   && a.source   !== sourceF)   return false;
      if (feedbackF === 'none' && a.feedback)     return false;
      if (feedbackF === 'fp'   && a.feedback !== 'fp') return false;
      if (feedbackF === 'tp'   && a.feedback !== 'tp') return false;
      // Egress-Filter: nur Alerts mit gesetzter Boundary-Priority. Whitelisted
      // werden je nach Modus ein- oder ausgeblendet (Audit-Pfad).
      if (egressMode !== 'off') {
        if (!a.boundary_priority) return false;
        if (egressMode === 'on' && a.boundary_whitelisted) return false;
      }
      if (tapFilter) {
        if (tapFilter === 'master') {
          if (a.tap_id) return false;
        } else if (a.tap_id !== tapFilter) {
          return false;
        }
      }
      if (q) {
        // Auch Hostnamen + Display-Names durchsuchen — die IpCell rendert
        // `displayName ?? hostname ?? ip`, also sollen User auch genau das
        // suchen können was sie sehen (manuell vergebene Namen, iTop-CMDB-
        // Assignments, rDNS-Hostnames).
        const e = a.enrichment;
        return (
          a.src_ip?.includes(q) ||
          a.dst_ip?.includes(q) ||
          a.rule_id?.toLowerCase().includes(q) ||
          a.description?.toLowerCase().includes(q) ||
          a.tags.some(t => t.toLowerCase().includes(q)) ||
          e?.src_display_name?.toLowerCase().includes(q) ||
          e?.dst_display_name?.toLowerCase().includes(q) ||
          e?.src_hostname?.toLowerCase().includes(q) ||
          e?.dst_hostname?.toLowerCase().includes(q)
        );
      }
      return true;
    });
    if (sortByPriority) {
      filteredArr.sort((a, b) => {
        const pa = PRIORITY_ORDER[a.boundary_priority ?? ''] ?? 99;
        const pb = PRIORITY_ORDER[b.boundary_priority ?? ''] ?? 99;
        if (pa !== pb) return pa - pb;
        return new Date(b.ts).getTime() - new Date(a.ts).getTime();
      });
    }
    return filteredArr;
  }, [alerts, showTest, mlOnly, suppressIrmaAsset, severityFilters, sourceF, feedbackF, search, egressMode, sortByPriority, tapFilter]);

  // Export-URL passend zu aktiven Filtern aufbauen
  const exportUrl = alertsExportUrl({
    severity: severityFilters.length ? severityFilters.join(',') : undefined,
    source:   sourceF    || undefined,
    feedback: feedbackF  || undefined,
    is_test:  showTest ? null : false,
  });

  const groups  = useMemo(() => {
    if (!grouped) return null;
    const gs = groupAlerts(filtered);
    if (sortByPriority) {
      // groupAlerts sortiert intern nach last_ts desc – beim Priority-Sort
      // brauchen wir die Boundary-Priority der jeweils neuesten Mitgliedschaft
      // (g.latest) als primären Schlüssel und last_ts als Tie-Breaker.
      const order: Record<string, number> = { P0: 0, P1: 1, P2: 2, P3: 3 };
      gs.sort((a, b) => {
        const pa = order[a.latest.boundary_priority ?? ''] ?? 99;
        const pb = order[b.latest.boundary_priority ?? ''] ?? 99;
        if (pa !== pb) return pa - pb;
        return tsMs(b.last_ts) - tsMs(a.last_ts);
      });
    }
    return gs;
  }, [grouped, filtered, sortByPriority]);
  const rowCount = grouped ? groups!.length : filtered.length;

  const handleUpdate = (updated: Alert) => {
    onUpdate(updated);
    setSelected(updated);
  };

  return (
    <div className="card flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-slate-800">
        <HelpTip helpKey="alertSearch" className="flex-1 min-w-32">
          <input
            id="alert-search"
            name="alert-search"
            className="input w-full"
            placeholder={t('alertFeed.search')}
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
        </HelpTip>
        <HelpTip helpKey="severityPills">
          <div className="flex gap-1 items-center" title={t('alertFeed.filters.severity')}>
            {SEVERITIES_ORDERED.map(s => {
              const active = severityFilters.includes(s);
              return (
                <button
                  key={s}
                  type="button"
                  onClick={() => setSeverityFilters(prev =>
                    prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s]
                  )}
                  className={`cyjan-sev-badge cyjan-sev-${s} cursor-pointer transition-opacity ${
                    active ? '' : 'opacity-30 hover:opacity-60'
                  }`}
                  aria-pressed={active}
                >
                  {s}
                </button>
              );
            })}
          </div>
        </HelpTip>
        <HelpTip helpKey="filterSource">
          <select className="input w-28" value={sourceF} onChange={e => setSourceF(e.target.value)}
            title={t('alertFeed.filters.source')}>
            <option value="">{t('alertFeed.filters.allSources')}</option>
            <option value="signature">{t('alertFeed.filters.sources.signature')}</option>
            <option value="ml">{t('alertFeed.filters.sources.ml')}</option>
            <option value="suricata">{t('alertFeed.filters.sources.suricata')}</option>
            <option value="external">{t('alertFeed.filters.sources.external')}</option>
          </select>
        </HelpTip>
        <HelpTip helpKey="filterFeedback">
          <select className="input w-28" value={feedbackF} onChange={e => setFeedbackF(e.target.value)}
            title={t('alertFeed.filters.feedback')}>
            <option value="">{t('common.all')}</option>
            <option value="none">{t('alertFeed.filters.noFeedback')}</option>
            <option value="fp">False Positive</option>
            <option value="tp">True Positive</option>
          </select>
        </HelpTip>

        {/* Tap-Filter (nur sichtbar wenn überhaupt ein Tap registriert ist) */}
        {showTapColumn && (
          <HelpTip helpKey="filterTap">
            <select className="input w-32" value={tapFilter} onChange={e => onTapFilterChange(e.target.value)}
              title={t('alertFeed.filters.tap')}>
              <option value="">{t('alertFeed.filters.allTaps')}</option>
              <option value="master">{t('alertFeed.filters.tapMaster')}</option>
              {taps.map(tap => (
                <option key={tap.id} value={tap.id}>{tap.name}</option>
              ))}
            </select>
          </HelpTip>
        )}

        {/* Gruppierungs-Toggle */}
        <HelpTip helpKey="alertGroup">
        <button
          onClick={() => setGrouped(g => !g)}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border font-mono ${
            grouped
              ? 'bg-cyan-500/15 text-cyan-200 border-cyan-500/50'
              : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
          }`}
          title={t('alertFeed.groupedToggle.title')}
        >
          {grouped ? t('alertFeed.groupedToggle.grouped') : t('alertFeed.groupedToggle.single')}
        </button>
        </HelpTip>

        {/* Egress-Boundary 3-State-Toggle */}
        <HelpTip helpKey="alertEgress">
        <button
          onClick={() => setEgressMode(m => m === 'off' ? 'on' : m === 'on' ? 'on+wl' : 'off')}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border font-mono ${
            egressMode === 'off'
              ? 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
              : egressMode === 'on'
                ? 'bg-rose-500/15 text-rose-200 border-rose-500/50'
                : 'bg-amber-500/15 text-amber-200 border-amber-500/50'
          }`}
          title={t('alertFeed.egressToggle.title')}
        >
          {egressMode === 'off' ? t('alertFeed.egressToggle.off')
            : egressMode === 'on' ? t('alertFeed.egressToggle.on')
            : t('alertFeed.egressToggle.onWl')}
        </button>
        </HelpTip>

        {/* Sort by Boundary-Priority */}
        <HelpTip helpKey="alertSortPriority">
        <button
          onClick={() => setSortByPriority(p => !p)}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border font-mono ${
            sortByPriority
              ? 'bg-cyan-500/15 text-cyan-200 border-cyan-500/50'
              : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
          }`}
          title={t('alertFeed.priorityToggle.title')}
        >
          {sortByPriority ? t('alertFeed.priorityToggle.on') : t('alertFeed.priorityToggle.off')}
        </button>
        </HelpTip>

        {whitelistedNotice && (
          <span className="text-[11px] text-green-400 font-mono">{whitelistedNotice}</span>
        )}

        {/* IRMA Asset-Warnungen unterdrücken */}
        <HelpTip helpKey="irmaFilterToggle">
          <button
            onClick={() => setSuppressIrmaAsset(s => !s)}
            className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border ${
              suppressIrmaAsset
                ? 'bg-violet-500/15 text-violet-200 border-violet-500/50'
                : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
            }`}
            title={t('alertFeed.irmaAssetToggle.title')}
          >
            {suppressIrmaAsset ? '∅ IRMA filter Warnings' : 'IRMA filter Warnings'}
          </button>
        </HelpTip>

        {/* CSV-Export */}
        <a
          href={exportUrl}
          download="alerts_export.csv"
          className="px-2.5 py-1 rounded text-xs font-medium border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors"
          title={t('alertFeed.csvExport.title')}
        >
          ↓ CSV
        </a>

        {/* Spalten-Auswahl: details/summary statt React-Dropdown spart UI-State.
            User toggelt Checkboxen, hiddenCols schreibt sich automatisch in
            localStorage und persistiert über Reloads. */}
        <details className="relative">
          <summary
            className="cursor-pointer list-none px-2.5 py-1 rounded text-xs font-medium border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors select-none"
            title={t('alertFeed.columnPicker.buttonTitle')}
          >
            {t('alertFeed.columnPicker.buttonLabel')} {hiddenCols.size > 0 && <span className="text-amber-400">({hiddenCols.size})</span>}
          </summary>
          <div className="absolute right-0 mt-1 z-20 bg-slate-900 border border-slate-700 rounded shadow-lg p-2 min-w-48">
            <div className="text-[10px] uppercase tracking-wider text-slate-500 mb-1.5 px-1">
              {t('alertFeed.columnPicker.headerShow')}
            </div>
            {ALL_COLS.map(c => {
              // Bedingungs-abhängige Spalten greyen wir aus, wenn der Auslöser
              // (egressMode/showTapColumn) gerade nicht aktiv ist — dann ist
              // der Toggle wirkungslos.
              const dimmed = (c.key === 'boundary' && egressMode === 'off')
                          || (c.key === 'tap' && !showTapColumn);
              return (
                <label key={c.key}
                  className={`flex items-center gap-2 px-1 py-0.5 text-xs cursor-pointer hover:bg-slate-800/60 rounded ${dimmed ? 'text-slate-600' : 'text-slate-300'}`}
                >
                  <input
                    type="checkbox"
                    className="accent-cyan-500"
                    checked={showCol(c.key)}
                    onChange={() => toggleCol(c.key)}
                  />
                  <span>{c.label}</span>
                  {dimmed && <span className="ml-auto text-[9px] text-slate-600">{t('alertFeed.columnPicker.inactiveHint')}</span>}
                </label>
              );
            })}
            <div className="mt-1.5 border-t border-slate-800 pt-1.5 space-y-0.5">
              {hiddenCols.size > 0 && (
                <button
                  className="w-full text-[10px] text-slate-500 hover:text-slate-300 px-1 py-0.5 text-left"
                  onClick={() => setHiddenCols(new Set())}
                >
                  {t('alertFeed.columnPicker.resetHidden')}
                </button>
              )}
              {Object.keys(colWidths).length > 0 && (
                <button
                  className="w-full text-[10px] text-slate-500 hover:text-slate-300 px-1 py-0.5 text-left"
                  onClick={() => setColWidths({})}
                  title={t('alertFeed.columnPicker.resetWidthsTitle')}
                >
                  {t('alertFeed.columnPicker.resetWidths')}
                </button>
              )}
              <p className="text-[9px] text-slate-600 px-1 leading-relaxed">
                {t('alertFeed.columnPicker.resizeTip')}
              </p>
            </div>
          </div>
        </details>

        <span className="text-sm font-medium text-slate-300 shrink-0">
          {rowCount} <span className="text-xs font-normal text-slate-500">{grouped && groups!.some(g => g.count > 1) ? t('alertFeed.counts.groups') : t('alertFeed.counts.alerts')}</span>
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto flex-1">
        {grouped ? (
          /* ── Gruppierte Ansicht ─────────────────────────────── */
          <table className="w-full text-xs">
            <thead className="cyjan-table-head sticky top-0 z-10">
              <tr className="text-left">
                <ResizableTh ckey="time">{t('alertFeed.columns.lastSeen')}</ResizableTh>
                {showCol('severity')    && <ResizableTh ckey="severity">{t('alertFeed.columns.severity')}</ResizableTh>}
                {egressMode !== 'off' && showCol('boundary') && <ResizableTh ckey="boundary">{t('alertFeed.columns.boundary')}</ResizableTh>}
                {showTapColumn && showCol('tap') && <ResizableTh ckey="tap">{t('alertFeed.columns.tap')}</ResizableTh>}
                {showCol('rule')        && <ResizableTh ckey="rule">{t('alertFeed.columns.rule')}</ResizableTh>}
                {showCol('proto')       && <ResizableTh ckey="proto">{t('alertFeed.columns.proto')}</ResizableTh>}
                {showCol('description') && <ResizableTh ckey="description">{t('alertFeed.columns.description')}</ResizableTh>}
                {showCol('tags')        && <ResizableTh ckey="tags">{t('alertFeed.columns.tags')}</ResizableTh>}
                {showCol('source')      && <ResizableTh ckey="source">{t('alertFeed.columns.source')}</ResizableTh>}
                {showCol('destination') && <ResizableTh ckey="destination">{t('alertFeed.columns.destination')}</ResizableTh>}
                {showCol('hits')        && <ResizableTh ckey="hits" extraClass="text-right">{t('alertFeed.columns.hits')}</ResizableTh>}
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {groups!.length === 0 && (
                <tr><td colSpan={11} className="text-center text-slate-600 py-12">{t('alertFeed.noAlerts')}</td></tr>
              )}
              {groups!.map(g => (
                <tr
                  key={g.key}
                  className={`border-b border-slate-800/50 hover:brightness-125 cursor-pointer transition-all ${ROW_SEVERITY[g.severity] ?? ''}`}
                  onClick={() => setSelected(g.latest)}
                >
                  <td className="px-3 py-2 text-slate-500 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('time')}>
                    {fmtTime(g.last_ts)}
                    {g.count > 1 && (
                      <div className="text-slate-600 text-xs">
                        {fmtTime(g.first_ts)} –
                      </div>
                    )}
                  </td>
                  {showCol('severity') && (
                    <td className="px-3 py-2" style={tdStyle('severity')}>
                      <SeverityBadge severity={g.severity} />
                    </td>
                  )}
                  {egressMode !== 'off' && showCol('boundary') && (
                    <td className="px-3 py-2" style={tdStyle('boundary')}><BoundaryCell alert={g.latest} /></td>
                  )}
                  {showTapColumn && showCol('tap') && (
                    <td className="px-3 py-2 text-[11px] font-mono text-slate-400 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('tap')}>
                      {g.latest.tap_id
                        ? (tapsById[g.latest.tap_id]?.name ?? g.latest.tap_id.slice(0, 8))
                        : <span className="text-slate-600">–</span>}
                    </td>
                  )}
                  {showCol('rule') && (
                    <td className="px-3 py-2 font-medium text-slate-200 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('rule')}>
                      {g.rule_id ?? '–'}
                      {g.latest.is_test && <span className="ml-1 text-blue-400">[TEST]</span>}
                      {g.latest.source === 'external' && <span className="ml-1 px-1 py-0.5 text-[10px] rounded bg-violet-900/50 text-violet-300 border border-violet-700/40">IRMA</span>}
                    </td>
                  )}
                  {showCol('proto') && (
                    <td className="px-3 py-2 font-mono text-[11px] text-cyan-300 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('proto')}>
                      {appProto(g.proto, g.dst_port, g.latest.src_port)}
                    </td>
                  )}
                  {showCol('description') && (
                    <td className="px-3 py-2 text-slate-400 overflow-hidden" style={tdStyle('description')}>
                      <span className="line-clamp-2" title={g.description ?? undefined}>
                        {g.description ?? '–'}
                      </span>
                    </td>
                  )}
                  {showCol('tags') && (
                    <td className="px-3 py-2 overflow-hidden" style={tdStyle('tags')}>
                      <TagList tags={g.tags} />
                    </td>
                  )}
                  {showCol('source') && (
                    <td className="px-3 py-2 overflow-hidden" style={tdStyle('source')}>
                      <div className="flex items-center gap-1.5">
                        <IpCell ip={g.src_ip} enrichment={g.enrichment ?? g.latest.enrichment} dir="src" />
                        {g.bidirectional && (
                          <span title={t('alertFeed.bidirectional')} className="text-cyan-500 text-sm shrink-0">↔</span>
                        )}
                      </div>
                    </td>
                  )}
                  {showCol('destination') && (
                    <td className="px-3 py-2 overflow-hidden" style={tdStyle('destination')}>
                      <IpCell ip={g.dst_ip} port={g.latest.dst_port} enrichment={g.enrichment ?? g.latest.enrichment} dir="dst" />
                    </td>
                  )}
                  {showCol('hits') && (
                    <td className="px-3 py-2 text-right" style={tdStyle('hits')}>
                      <div className="flex items-center justify-end gap-1.5">
                        {g.latest.feedback && <FeedbackBadge feedback={g.latest.feedback} />}
                        {g.count > 1
                          ? <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 font-mono">×{g.count}</span>
                          : <span className="text-slate-600">1</span>
                        }
                      </div>
                    </td>
                  )}
                  <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1.5">
                      <PcapButton alertId={g.latest.alert_id} available={g.latest.pcap_available} />
                      {egressMode !== 'off' && g.latest.boundary_priority && (
                        <button
                          onClick={() => setWhitelistFor(g.latest)}
                          title={t('alertFeed.whitelistRowAction')}
                          className="px-1.5 py-0.5 rounded text-[11px] border whitespace-nowrap transition-colors border-amber-700/50 text-amber-400 bg-amber-950/30 hover:bg-amber-900/50 hover:text-amber-300"
                        >
                          + WL
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          /* ── Einzelansicht ──────────────────────────────────── */
          <table className="w-full text-xs">
            <thead className="cyjan-table-head sticky top-0 z-10">
              <tr className="text-left">
                <ResizableTh ckey="time">{t('alertFeed.columns.time')}</ResizableTh>
                {showCol('severity')    && <ResizableTh ckey="severity">{t('alertFeed.columns.severity')}</ResizableTh>}
                {egressMode !== 'off' && showCol('boundary') && <ResizableTh ckey="boundary">{t('alertFeed.columns.boundary')}</ResizableTh>}
                {showTapColumn && showCol('tap') && <ResizableTh ckey="tap">{t('alertFeed.columns.tap')}</ResizableTh>}
                {showCol('rule')        && <ResizableTh ckey="rule">{t('alertFeed.columns.rule')}</ResizableTh>}
                {showCol('proto')       && <ResizableTh ckey="proto">{t('alertFeed.columns.proto')}</ResizableTh>}
                {showCol('description') && <ResizableTh ckey="description">{t('alertFeed.columns.description')}</ResizableTh>}
                {showCol('tags')        && <ResizableTh ckey="tags">{t('alertFeed.columns.tags')}</ResizableTh>}
                {showCol('source')      && <ResizableTh ckey="source">{t('alertFeed.columns.source')}</ResizableTh>}
                {showCol('destination') && <ResizableTh ckey="destination">{t('alertFeed.columns.destination')}</ResizableTh>}
                {showCol('hits')        && <ResizableTh ckey="hits">{t('alertFeed.columns.score')}</ResizableTh>}
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={11} className="text-center text-slate-600 py-12">{t('alertFeed.noAlerts')}</td></tr>
              )}
              {filtered.map(a => (
                <tr
                  key={a.alert_id}
                  className={`border-b border-slate-800/50 hover:brightness-125 cursor-pointer transition-all ${ROW_SEVERITY[a.severity] ?? ''}`}
                  onClick={() => setSelected(a)}
                >
                  <td className="px-3 py-2 text-slate-500 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('time')}>
                    {fmtTime(a.ts)}
                  </td>
                  {showCol('severity') && (
                    <td className="px-3 py-2" style={tdStyle('severity')}><SeverityBadge severity={a.severity} /></td>
                  )}
                  {egressMode !== 'off' && showCol('boundary') && (
                    <td className="px-3 py-2" style={tdStyle('boundary')}><BoundaryCell alert={a} /></td>
                  )}
                  {showTapColumn && showCol('tap') && (
                    <td className="px-3 py-2 text-[11px] font-mono text-slate-400 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('tap')}>
                      {a.tap_id
                        ? (tapsById[a.tap_id]?.name ?? a.tap_id.slice(0, 8))
                        : <span className="text-slate-600">–</span>}
                    </td>
                  )}
                  {showCol('rule') && (
                    <td className="px-3 py-2 font-medium text-slate-200 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('rule')}>
                      {a.rule_id}
                      {a.is_test && <span className="ml-1 text-blue-400 text-xs">[TEST]</span>}
                      {a.source === 'external' && <span className="ml-1 px-1 py-0.5 text-[10px] rounded bg-violet-900/50 text-violet-300 border border-violet-700/40">IRMA</span>}
                    </td>
                  )}
                  {showCol('proto') && (
                    <td className="px-3 py-2 font-mono text-[11px] text-cyan-300 whitespace-nowrap overflow-hidden text-ellipsis" style={tdStyle('proto')}>
                      {appProto(a.proto, a.dst_port, a.src_port)}
                    </td>
                  )}
                  {showCol('description') && (
                    <td className="px-3 py-2 text-slate-400 overflow-hidden" style={tdStyle('description')}>
                      <span className="line-clamp-2" title={a.description ?? undefined}>
                        {a.description ?? '–'}
                      </span>
                    </td>
                  )}
                  {showCol('tags') && (
                    <td className="px-3 py-2 overflow-hidden" style={tdStyle('tags')}>
                      <TagList tags={a.tags ?? []} />
                    </td>
                  )}
                  {showCol('source') && (
                    <td className="px-3 py-2 overflow-hidden" style={tdStyle('source')}>
                      <IpCell ip={a.src_ip} enrichment={a.enrichment} dir="src" />
                    </td>
                  )}
                  {showCol('destination') && (
                    <td className="px-3 py-2 overflow-hidden" style={tdStyle('destination')}>
                      <IpCell ip={a.dst_ip} port={a.dst_port} enrichment={a.enrichment} dir="dst" />
                    </td>
                  )}
                  {showCol('hits') && (
                    <td className="px-3 py-2 tabular-nums text-slate-400 overflow-hidden text-ellipsis" style={tdStyle('hits')}>{(a.score ?? 0).toFixed(2)}</td>
                  )}
                  <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1.5">
                      {a.feedback && <FeedbackBadge feedback={a.feedback} />}
                      <PcapButton alertId={a.alert_id} available={a.pcap_available} />
                      {egressMode !== 'off' && a.boundary_priority && (
                        <button
                          onClick={() => setWhitelistFor(a)}
                          title={t('alertFeed.whitelistRowAction')}
                          className="px-1.5 py-0.5 rounded text-[11px] border whitespace-nowrap transition-colors border-amber-700/50 text-amber-400 bg-amber-950/30 hover:bg-amber-900/50 hover:text-amber-300"
                        >
                          + WL
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {selected && (
        <AlertDetail alert={selected} onClose={() => setSelected(null)} onUpdate={handleUpdate} />
      )}

      {whitelistFor && (
        <WhitelistModal
          alert={whitelistFor}
          onClose={() => setWhitelistFor(null)}
          onCreated={() => {
            setWhitelistedNotice(t('alertFeed.whitelistModal.created'));
            window.setTimeout(() => setWhitelistedNotice(''), 4000);
          }}
        />
      )}
    </div>
  );
}
