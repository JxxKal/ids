import { useState } from 'react';
import type { Alert, Enrichment } from '../types';
import { AlertDetail } from './AlertDetail';
import { SeverityBadge } from './SeverityBadge';

// ── IP-Zelle mit Hostname + Trust-Badge ────────────────────────────────────────

const TRUST_SOURCE_LABEL: Record<string, string> = {
  manual: 'manuell',
  csv:    'Import',
  dns:    'DNS',
};

function IpCell({
  ip, port, enrichment, dir,
}: {
  ip?: string;
  port?: number;
  enrichment?: Enrichment;
  dir: 'src' | 'dst';
}) {
  const hostname    = dir === 'src' ? enrichment?.src_hostname    : enrichment?.dst_hostname;
  const displayName = dir === 'src' ? enrichment?.src_display_name: enrichment?.dst_display_name;
  const trusted     = dir === 'src' ? enrichment?.src_trusted      : enrichment?.dst_trusted;
  const trustSrc    = dir === 'src' ? enrichment?.src_trust_source : enrichment?.dst_trust_source;

  const primary  = displayName ?? hostname ?? ip ?? '–';
  const showIp   = !!ip && primary !== ip;
  const portStr  = port ? `:${port}` : '';
  const srcLabel = trustSrc ? TRUST_SOURCE_LABEL[trustSrc] ?? trustSrc : null;

  return (
    <div className="leading-tight">
      <span className="text-slate-300">{primary}{!showIp ? portStr : ''}</span>
      {showIp && (
        <div className="text-slate-600 text-[10px]">{ip}{portStr}</div>
      )}
      {trusted && (
        <span
          className="inline-flex items-center gap-0.5 text-[10px] text-green-400 bg-green-950/50 border border-green-800/40 rounded px-1 mt-0.5"
          title={srcLabel ? `Validiert via ${srcLabel}` : 'Validiert'}
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
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];

const ROW_SEVERITY: Record<string, string> = {
  critical: 'border-l-2 border-l-red-500    bg-red-950/40',
  high:     'border-l-2 border-l-red-600    bg-red-950/20',
  medium:   'border-l-2 border-l-orange-500 bg-orange-950/20',
  low:      'border-l-2 border-l-green-600  bg-green-950/20',
};

// ── Gruppierung ────────────────────────────────────────────────────────────────

interface AlertGroup {
  key:          string;
  severity:     Alert['severity'];
  rule_id?:     string;
  src_ip?:      string;
  dst_ip?:      string;
  proto?:       string;
  description?: string;
  count:        number;
  first_ts:     string;
  last_ts:      string;
  latest:       Alert;
  enrichment?:  Enrichment;
}

/** Wandelt ts (ISO-String oder Unix-Float) in Millisekunden um. */
function tsMs(ts: string | number): number {
  if (typeof ts === 'number') return ts * 1000;
  return new Date(ts).getTime();
}

function fmtTime(ts: string | number): string {
  return new Date(tsMs(ts)).toLocaleTimeString();
}

function groupAlerts(alerts: Alert[]): AlertGroup[] {
  const map = new Map<string, AlertGroup>();

  for (const a of alerts) {
    const k = `${a.rule_id ?? '–'}::${a.src_ip ?? '–'}`;
    const g = map.get(k);
    if (g) {
      g.count++;
      if (tsMs(a.ts) > tsMs(g.last_ts)) { g.last_ts = a.ts; g.latest = a; g.description = a.description; }
      if (tsMs(a.ts) < tsMs(g.first_ts)) g.first_ts = a.ts;
      if (!g.enrichment && a.enrichment) g.enrichment = a.enrichment;
    } else {
      map.set(k, {
        key: k, severity: a.severity,
        rule_id: a.rule_id, src_ip: a.src_ip, dst_ip: a.dst_ip,
        proto: a.proto, description: a.description,
        count: 1, first_ts: a.ts, last_ts: a.ts, latest: a,
        enrichment: a.enrichment ?? undefined,
      });
    }
  }

  return [...map.values()].sort((a, b) => tsMs(b.last_ts) - tsMs(a.last_ts));
}

// ── Komponente ─────────────────────────────────────────────────────────────────

export function AlertFeed({ alerts, onUpdate, showTest }: Props) {
  const [selected,  setSelected]  = useState<Alert | null>(null);
  const [severityF, setSeverityF] = useState('');
  const [search,    setSearch]    = useState('');
  const [grouped,   setGrouped]   = useState(true);

  const filtered = alerts.filter(a => {
    if (!showTest && a.is_test) return false;
    if (severityF && a.severity !== severityF) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        a.src_ip?.includes(q) ||
        a.dst_ip?.includes(q) ||
        a.rule_id?.toLowerCase().includes(q) ||
        a.description?.toLowerCase().includes(q)
      );
    }
    return true;
  });

  const groups  = grouped ? groupAlerts(filtered) : null;
  const rowCount = grouped ? groups!.length : filtered.length;

  const handleUpdate = (updated: Alert) => {
    onUpdate(updated);
    setSelected(updated);
  };

  return (
    <div className="card flex flex-col h-full">
      {/* Toolbar */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800">
        <input
          id="alert-search"
          name="alert-search"
          className="input flex-1"
          placeholder="Suche (IP, Regel, …)"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select
          id="alert-severity"
          name="alert-severity"
          className="input w-32"
          value={severityF}
          onChange={e => setSeverityF(e.target.value)}
        >
          {SEVERITIES.map(s => (
            <option key={s} value={s}>{s || 'Alle Schweregrade'}</option>
          ))}
        </select>

        {/* Gruppierungs-Toggle */}
        <button
          onClick={() => setGrouped(g => !g)}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border ${
            grouped
              ? 'bg-blue-900/60 text-blue-200 border-blue-700'
              : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
          }`}
          title="Gleiche Regel + Quell-IP zusammenfassen (zeigt Treffer-Anzahl)"
        >
          {grouped ? '⊞ Gruppiert' : '≡ Einzeln'}
        </button>

        <span className="text-sm font-medium text-slate-300 shrink-0">
          {rowCount} <span className="text-xs font-normal text-slate-500">{grouped && groups!.some(g => g.count > 1) ? 'Gruppen' : 'Alerts'}</span>
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto flex-1">
        {grouped ? (
          /* ── Gruppierte Ansicht ─────────────────────────────── */
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 z-10">
              <tr className="text-left text-slate-500">
                <th className="px-3 py-2">Letzte</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Regel</th>
                <th className="px-3 py-2">Beschreibung</th>
                <th className="px-3 py-2">Quelle</th>
                <th className="px-3 py-2">Ziel</th>
                <th className="px-3 py-2 text-right">Treffer</th>
              </tr>
            </thead>
            <tbody>
              {groups!.length === 0 && (
                <tr><td colSpan={7} className="text-center text-slate-600 py-12">Keine Alerts</td></tr>
              )}
              {groups!.map(g => (
                <tr
                  key={g.key}
                  className={`border-b border-slate-800/50 hover:brightness-125 cursor-pointer transition-all ${ROW_SEVERITY[g.severity] ?? ''}`}
                  onClick={() => setSelected(g.latest)}
                >
                  <td className="px-3 py-2 text-slate-500 whitespace-nowrap">
                    {fmtTime(g.last_ts)}
                    {g.count > 1 && (
                      <div className="text-slate-600 text-xs">
                        {fmtTime(g.first_ts)} –
                      </div>
                    )}
                  </td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={g.severity} />
                  </td>
                  <td className="px-3 py-2 font-medium text-slate-200 whitespace-nowrap">
                    {g.rule_id ?? '–'}
                    {g.latest.is_test && <span className="ml-1 text-blue-400">[TEST]</span>}
                  </td>
                  <td className="px-3 py-2 text-slate-400 max-w-sm">
                    <span className="line-clamp-2" title={g.description ?? undefined}>
                      {g.description ?? '–'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={g.src_ip} enrichment={g.enrichment ?? g.latest.enrichment} dir="src" />
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={g.dst_ip} port={g.latest.dst_port} enrichment={g.enrichment ?? g.latest.enrichment} dir="dst" />
                  </td>
                  <td className="px-3 py-2 text-right">
                    {g.count > 1
                      ? <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 font-mono">×{g.count}</span>
                      : <span className="text-slate-600">1</span>
                    }
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : (
          /* ── Einzelansicht ──────────────────────────────────── */
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-slate-900 border-b border-slate-800 z-10">
              <tr className="text-left text-slate-500">
                <th className="px-3 py-2">Zeit</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Regel</th>
                <th className="px-3 py-2">Beschreibung</th>
                <th className="px-3 py-2">Quelle</th>
                <th className="px-3 py-2">Ziel</th>
                <th className="px-3 py-2">Score</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={8} className="text-center text-slate-600 py-12">Keine Alerts</td></tr>
              )}
              {filtered.map(a => (
                <tr
                  key={a.alert_id}
                  className={`border-b border-slate-800/50 hover:brightness-125 cursor-pointer transition-all ${ROW_SEVERITY[a.severity] ?? ''}`}
                  onClick={() => setSelected(a)}
                >
                  <td className="px-3 py-2 text-slate-500 whitespace-nowrap">
                    {fmtTime(a.ts)}
                  </td>
                  <td className="px-3 py-2"><SeverityBadge severity={a.severity} /></td>
                  <td className="px-3 py-2 font-medium text-slate-200 whitespace-nowrap">
                    {a.rule_id}
                    {a.is_test && <span className="ml-1 text-blue-400 text-xs">[TEST]</span>}
                  </td>
                  <td className="px-3 py-2 text-slate-400 max-w-sm">
                    <span className="line-clamp-2" title={a.description ?? undefined}>
                      {a.description ?? '–'}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={a.src_ip} enrichment={a.enrichment} dir="src" />
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={a.dst_ip} port={a.dst_port} enrichment={a.enrichment} dir="dst" />
                  </td>
                  <td className="px-3 py-2 tabular-nums text-slate-400">{(a.score ?? 0).toFixed(2)}</td>
                  <td className="px-3 py-2 text-slate-600">
                    {a.feedback && (
                      <span className={a.feedback === 'fp' ? 'text-green-500' : 'text-red-400'}>
                        {a.feedback.toUpperCase()}
                      </span>
                    )}
                    {a.pcap_available && !a.feedback && <span className="text-blue-500">▶</span>}
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
    </div>
  );
}
