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

export function AlertFeed({ alerts, onUpdate, showTest }: Props) {
  const [selected,  setSelected]  = useState<Alert | null>(null);
  const [severityF, setSeverityF] = useState('');
  const [search,    setSearch]    = useState('');

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
        <span className="text-xs text-slate-500 shrink-0">{filtered.length} Alerts</span>
      </div>

      {/* Table */}
      <div className="overflow-y-auto flex-1">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-slate-900 border-b border-slate-800">
            <tr className="text-left text-slate-500">
              <th className="px-3 py-2">Zeit</th>
              <th className="px-3 py-2">Severity</th>
              <th className="px-3 py-2">Regel</th>
              <th className="px-3 py-2">Quelle</th>
              <th className="px-3 py-2">Ziel</th>
              <th className="px-3 py-2">Trust</th>
              <th className="px-3 py-2">Score</th>
              <th className="px-3 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center text-slate-600 py-12">
                  Keine Alerts
                </td>
              </tr>
            )}
            {filtered.map(a => (
              <tr
                key={a.alert_id}
                className="border-b border-slate-800/50 hover:bg-slate-800/40 cursor-pointer"
                onClick={() => setSelected(a)}
              >
                <td className="px-3 py-2 text-slate-500 whitespace-nowrap">
                  {new Date(a.ts).toLocaleTimeString()}
                </td>
                <td className="px-3 py-2">
                  <SeverityBadge severity={a.severity} />
                </td>
                <td className="px-3 py-2 font-medium text-slate-200">
                  {a.rule_id}
                  {a.is_test && <span className="ml-1 text-blue-400 text-xs">[TEST]</span>}
                </td>
                <td className="px-3 py-2 text-slate-400">
                  {a.enrichment?.src_hostname ?? a.src_ip ?? '–'}
                </td>
                <td className="px-3 py-2 text-slate-400">
                  {a.enrichment?.dst_hostname ?? a.dst_ip ?? '–'}
                  {a.dst_port ? `:${a.dst_port}` : ''}
                </td>
                <td className="px-3 py-2">
                  {a.enrichment && (
                    <div className="flex gap-1 flex-wrap">
                      {a.enrichment.src_trusted === false && (
                        <TrustBadge trusted={false} />
                      )}
                      {a.enrichment.dst_trusted === false && (
                        <TrustBadge trusted={false} />
                      )}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2 tabular-nums text-slate-400">
                  {a.score.toFixed(2)}
                </td>
                <td className="px-3 py-2 text-slate-600">
                  {a.feedback && (
                    <span className={a.feedback === 'fp' ? 'text-green-500' : 'text-red-400'}>
                      {a.feedback.toUpperCase()}
                    </span>
                  )}
                  {a.pcap_available && !a.feedback && (
                    <span className="text-blue-500">▶</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {selected && (
        <AlertDetail
          alert={selected}
          onClose={() => setSelected(null)}
          onUpdate={handleUpdate}
        />
      )}
    </div>
  );
}
