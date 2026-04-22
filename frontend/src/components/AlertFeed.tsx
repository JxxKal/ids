import { useState } from 'react';
import type { Alert, Enrichment } from '../types';
import { alertsExportUrl, getToken, pcapUrl } from '../api';
import { AlertDetail } from './AlertDetail';
import { SeverityBadge } from './SeverityBadge';

// ── PCAP-Download ─────────────────────────────────────────────────────────────

function PcapButton({ alertId, available, filename }: { alertId: string; available: boolean; filename?: string }) {
  const [loading, setLoading] = useState(false);

  async function handleDownload(e: React.MouseEvent) {
    e.stopPropagation();
    if (loading || !available) return;
    setLoading(true);
    try {
      const token = getToken();
      const res = await fetch(pcapUrl(alertId), {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      if (!res.ok) throw new Error(`${res.status}`);
      const blob = await res.blob();
      const url  = URL.createObjectURL(blob);
      const a    = document.createElement('a');
      a.href     = url;
      a.download = filename ?? `alert-${alertId.slice(0, 8)}.pcap`;
      a.click();
      URL.revokeObjectURL(url);
    } catch {
      /* ignore */
    } finally {
      setLoading(false);
    }
  }

  return (
    <button
      onClick={handleDownload}
      disabled={loading || !available}
      title={available ? 'PCAP herunterladen' : 'Kein PCAP – Sniffer läuft nicht oder kein Paketpuffer für diesen Alert'}
      className={`px-1.5 py-0.5 rounded text-[11px] border whitespace-nowrap transition-colors ${
        available
          ? 'border-blue-700/50 text-blue-400 bg-blue-950/30 hover:bg-blue-900/50 hover:text-blue-300'
          : 'border-slate-700/30 text-slate-600 bg-transparent cursor-default'
      } disabled:opacity-40`}
    >
      {loading ? '…' : '↓ pcap'}
    </button>
  );
}

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
  mlOnly: boolean;
}

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low'];

const ROW_SEVERITY: Record<string, string> = {
  critical: 'cyjan-row-critical',
  high:     'cyjan-row-high',
  medium:   'cyjan-row-medium',
  low:      'cyjan-row-low',
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
  tags:         string[];
  count:        number;
  first_ts:     string;
  last_ts:      string;
  latest:       Alert;
  enrichment?:  Enrichment;
}

const OT_TAGS = new Set(['scada', 'ics', 'modbus', 'dnp3', 'ethernet/ip', 'bacnet', 'ot']);

function FeedbackBadge({ feedback }: { feedback: 'fp' | 'tp' }) {
  return feedback === 'fp'
    ? <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border text-[10px] leading-none bg-green-950/50 text-green-300 border-green-700/40" title="False Positive – Falschalarm bestätigt, fließt in ML-Training ein">✓ FP</span>
    : <span className="inline-flex items-center gap-0.5 px-1.5 py-0.5 rounded border text-[10px] leading-none bg-red-950/50 text-red-300 border-red-700/40"   title="True Positive – Angriff bestätigt, fließt in ML-Training ein">⚠ TP</span>;
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
      if (a.tags?.length) g.tags = [...new Set([...g.tags, ...a.tags])];
    } else {
      map.set(k, {
        key: k, severity: a.severity,
        rule_id: a.rule_id, src_ip: a.src_ip, dst_ip: a.dst_ip,
        proto: a.proto, description: a.description,
        tags: [...(a.tags ?? [])],
        count: 1, first_ts: a.ts, last_ts: a.ts, latest: a,
        enrichment: a.enrichment ?? undefined,
      });
    }
  }

  return [...map.values()].sort((a, b) => tsMs(b.last_ts) - tsMs(a.last_ts));
}

// ── Komponente ─────────────────────────────────────────────────────────────────

export function AlertFeed({ alerts, onUpdate, showTest, mlOnly }: Props) {
  const [selected,  setSelected]  = useState<Alert | null>(null);
  const [severityF, setSeverityF] = useState('');
  const [sourceF,   setSourceF]   = useState('');
  const [feedbackF, setFeedbackF] = useState('');
  const [search,    setSearch]    = useState('');
  const [grouped,   setGrouped]   = useState(true);

  const filtered = alerts.filter(a => {
    if (!showTest && a.is_test) return false;
    if (mlOnly && a.source !== 'ml') return false;
    if (severityF && a.severity !== severityF) return false;
    if (sourceF   && a.source   !== sourceF)   return false;
    if (feedbackF === 'none' && a.feedback)     return false;
    if (feedbackF === 'fp'   && a.feedback !== 'fp') return false;
    if (feedbackF === 'tp'   && a.feedback !== 'tp') return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        a.src_ip?.includes(q) ||
        a.dst_ip?.includes(q) ||
        a.rule_id?.toLowerCase().includes(q) ||
        a.description?.toLowerCase().includes(q) ||
        a.tags.some(t => t.toLowerCase().includes(q))
      );
    }
    return true;
  });

  // Export-URL passend zu aktiven Filtern aufbauen
  const exportUrl = alertsExportUrl({
    severity: severityF  || undefined,
    source:   sourceF    || undefined,
    feedback: feedbackF  || undefined,
    is_test:  showTest ? null : false,
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
      <div className="flex flex-wrap items-center gap-2 px-3 py-2 border-b border-slate-800">
        <input
          id="alert-search"
          name="alert-search"
          className="input flex-1 min-w-32"
          placeholder="Suche: IP, Regel, Tag, …"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select className="input w-28" value={severityF} onChange={e => setSeverityF(e.target.value)}
          title="Schweregrad filtern">
          {SEVERITIES.map(s => (
            <option key={s} value={s}>{s || 'Alle'}</option>
          ))}
        </select>
        <select className="input w-28" value={sourceF} onChange={e => setSourceF(e.target.value)}
          title="Quelle filtern">
          <option value="">Alle Quellen</option>
          <option value="signature">Signatur</option>
          <option value="ml">ML / KI</option>
          <option value="suricata">Suricata</option>
          <option value="external">Extern (IRMA)</option>
        </select>
        <select className="input w-28" value={feedbackF} onChange={e => setFeedbackF(e.target.value)}
          title="Feedback-Status filtern">
          <option value="">Alle</option>
          <option value="none">Kein Feedback</option>
          <option value="fp">False Positive</option>
          <option value="tp">True Positive</option>
        </select>

        {/* Gruppierungs-Toggle */}
        <button
          onClick={() => setGrouped(g => !g)}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border font-mono ${
            grouped
              ? 'bg-cyan-500/15 text-cyan-200 border-cyan-500/50'
              : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
          }`}
          title="Gleiche Regel + Quell-IP zusammenfassen"
        >
          {grouped ? '⊞ Gruppiert' : '≡ Einzeln'}
        </button>

        {/* CSV-Export */}
        <a
          href={exportUrl}
          download="alerts_export.csv"
          className="px-2.5 py-1 rounded text-xs font-medium border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500 transition-colors"
          title="Gefilterte Alerts als CSV exportieren (max. 5000)"
        >
          ↓ CSV
        </a>

        <span className="text-sm font-medium text-slate-300 shrink-0">
          {rowCount} <span className="text-xs font-normal text-slate-500">{grouped && groups!.some(g => g.count > 1) ? 'Gruppen' : 'Alerts'}</span>
        </span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto flex-1">
        {grouped ? (
          /* ── Gruppierte Ansicht ─────────────────────────────── */
          <table className="w-full text-xs">
            <thead className="cyjan-table-head sticky top-0 z-10">
              <tr className="text-left">
                <th className="px-3 py-2">Letzte</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Regel</th>
                <th className="px-3 py-2">Beschreibung</th>
                <th className="px-3 py-2">Tags</th>
                <th className="px-3 py-2">Quelle</th>
                <th className="px-3 py-2">Ziel</th>
                <th className="px-3 py-2 text-right">Treffer</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {groups!.length === 0 && (
                <tr><td colSpan={9} className="text-center text-slate-600 py-12">Keine Alerts</td></tr>
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
                    {g.latest.source === 'external' && <span className="ml-1 px-1 py-0.5 text-[10px] rounded bg-violet-900/50 text-violet-300 border border-violet-700/40">IRMA</span>}
                  </td>
                  <td className="px-3 py-2 text-slate-400 max-w-sm">
                    <span className="line-clamp-2" title={g.description ?? undefined}>
                      {g.description ?? '–'}
                    </span>
                  </td>
                  <td className="px-3 py-2 max-w-[140px]">
                    <TagList tags={g.tags} />
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={g.src_ip} enrichment={g.enrichment ?? g.latest.enrichment} dir="src" />
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={g.dst_ip} port={g.latest.dst_port} enrichment={g.enrichment ?? g.latest.enrichment} dir="dst" />
                  </td>
                  <td className="px-3 py-2 text-right">
                    <div className="flex items-center justify-end gap-1.5">
                      {g.latest.feedback && <FeedbackBadge feedback={g.latest.feedback} />}
                      {g.count > 1
                        ? <span className="px-1.5 py-0.5 rounded bg-slate-700 text-slate-300 font-mono">×{g.count}</span>
                        : <span className="text-slate-600">1</span>
                      }
                    </div>
                  </td>
                  <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                    <PcapButton alertId={g.latest.alert_id} available={g.latest.pcap_available} />
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
                <th className="px-3 py-2">Zeit</th>
                <th className="px-3 py-2">Severity</th>
                <th className="px-3 py-2">Regel</th>
                <th className="px-3 py-2">Beschreibung</th>
                <th className="px-3 py-2">Tags</th>
                <th className="px-3 py-2">Quelle</th>
                <th className="px-3 py-2">Ziel</th>
                <th className="px-3 py-2">Score</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {filtered.length === 0 && (
                <tr><td colSpan={9} className="text-center text-slate-600 py-12">Keine Alerts</td></tr>
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
                    {a.source === 'external' && <span className="ml-1 px-1 py-0.5 text-[10px] rounded bg-violet-900/50 text-violet-300 border border-violet-700/40">IRMA</span>}
                  </td>
                  <td className="px-3 py-2 text-slate-400 max-w-sm">
                    <span className="line-clamp-2" title={a.description ?? undefined}>
                      {a.description ?? '–'}
                    </span>
                  </td>
                  <td className="px-3 py-2 max-w-[140px]">
                    <TagList tags={a.tags ?? []} />
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={a.src_ip} enrichment={a.enrichment} dir="src" />
                  </td>
                  <td className="px-3 py-2">
                    <IpCell ip={a.dst_ip} port={a.dst_port} enrichment={a.enrichment} dir="dst" />
                  </td>
                  <td className="px-3 py-2 tabular-nums text-slate-400">{(a.score ?? 0).toFixed(2)}</td>
                  <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                    <div className="flex items-center gap-1.5">
                      {a.feedback && <FeedbackBadge feedback={a.feedback} />}
                      <PcapButton alertId={a.alert_id} available={a.pcap_available} />
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
    </div>
  );
}
