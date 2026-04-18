import { useState } from 'react';
import type { Alert } from '../types';
import { AlertDetail } from './AlertDetail';
import { SeverityBadge } from './SeverityBadge';
import { TrustBadge } from './TrustBadge';

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
  key:         string;
  severity:    Alert['severity'];
  rule_id?:    string;
  src_ip?:     string;
  dst_ip?:     string;
  proto?:      string;
  description?: string;
  count:       number;
  first_ts:    string;
  last_ts:     string;
  latest:      Alert;
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
    } else {
      map.set(k, {
        key: k, severity: a.severity,
        rule_id: a.rule_id, src_ip: a.src_ip, dst_ip: a.dst_ip,
        proto: a.proto, description: a.description,
        count: 1, first_ts: a.ts, last_ts: a.ts, latest: a,
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
          className="input flex-1"
          placeholder="Suche (IP, Regel, …)"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select
          className="input w-32"
          value={severityF}
          onChange={e => setSeverityF(e.target.value)}
        >
          {SEVERITIES.map(s => (
            <option key={s} value={s}>{s || 'Alle'}</option>
          ))}
        </select>

        {/* Gruppierungs-Toggle */}
        <button
          onClick={() => setGrouped(g => !g)}
          className={`px-2.5 py-1 rounded text-xs font-medium transition-colors border ${
            grouped
              ? 'bg-slate-700 text-slate-100 border-slate-600'
              : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
          }`}
          title="Alerts mit gleicher Regel-ID und Quell-IP zu einer Zeile zusammenfassen und Treffer-Anzahl anzeigen"
        >
          {grouped ? 'Zusammengefasst' : 'Einzeln'}
        </button>

        <span className="text-xs text-slate-500 shrink-0">{rowCount} {grouped && groups!.some(g => g.count > 1) ? 'Gruppen' : 'Alerts'}</span>
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
                        ab {fmtTime(g.first_ts)}
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
                  <td className="px-3 py-2 text-slate-400 max-w-xs truncate">
                    {g.description ?? '–'}
                  </td>
                  <td className="px-3 py-2 text-slate-400">
                    {g.latest.enrichment?.src_hostname ?? g.src_ip ?? '–'}
                  </td>
                  <td className="px-3 py-2 text-slate-400">
                    {g.latest.enrichment?.dst_hostname ?? g.dst_ip ?? '–'}
                    {g.latest.dst_port ? `:${g.latest.dst_port}` : ''}
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
                  <td className="px-3 py-2 text-slate-400 max-w-xs truncate">
                    {a.description ?? '–'}
                  </td>
                  <td className="px-3 py-2 text-slate-400">
                    {a.enrichment?.src_hostname ?? a.src_ip ?? '–'}
                  </td>
                  <td className="px-3 py-2 text-slate-400">
                    {a.enrichment?.dst_hostname ?? a.dst_ip ?? '–'}
                    {a.dst_port ? `:${a.dst_port}` : ''}
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
