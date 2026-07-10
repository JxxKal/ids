import { RotateCcw } from 'lucide-react';
import { useEffect, useState } from 'react';
import { fetchTraces } from '../api';
import { de } from '../i18n/de';
import type { TraceHistoryEntry, TraceRequest } from '../types';

const verdictColor: Record<string, string> = {
  ALLOW: 'text-emerald-400',
  DENY: 'text-red-400',
  DEGRADED: 'text-amber-400',
};

export default function HistoryList({ onReplay }: { onReplay: (req: TraceRequest) => void }) {
  const [entries, setEntries] = useState<TraceHistoryEntry[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchTraces().then(setEntries).finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-sm text-slate-500">{de.common.loading}</p>;
  if (entries.length === 0) return <p className="text-sm text-slate-500">{de.history.empty}</p>;

  return (
    <div className="fwpt-card overflow-x-auto p-0">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-800 text-xs text-slate-500">
          <tr>
            <th className="px-3 py-2 font-medium">Zeit</th>
            <th className="px-3 py-2 font-medium">User</th>
            <th className="px-3 py-2 font-medium">Quelle</th>
            <th className="px-3 py-2 font-medium">Ziel</th>
            <th className="px-3 py-2 font-medium">Proto</th>
            <th className="px-3 py-2 font-medium">Verdict</th>
            <th className="px-3 py-2" />
          </tr>
        </thead>
        <tbody>
          {entries.map((e) => (
            <tr key={e.id} className="border-b border-slate-800/60 hover:bg-slate-800/40">
              <td className="px-3 py-2 text-slate-400">
                {new Date(e.created_at).toLocaleString('de-DE')}
              </td>
              <td className="px-3 py-2 text-slate-400">{e.username}</td>
              <td className="px-3 py-2 font-mono text-slate-200">{e.request.src}</td>
              <td className="px-3 py-2 font-mono text-slate-200">{e.request.dst}</td>
              <td className="px-3 py-2 uppercase text-slate-400">
                {e.request.protocol}{e.request.dst_port ? `/${e.request.dst_port}` : ''}
              </td>
              <td className={`px-3 py-2 font-medium ${verdictColor[e.verdict]}`}>
                {de.verdict[e.verdict]}
              </td>
              <td className="px-3 py-2">
                <button type="button" className="fwpt-btn-ghost !px-2 !py-1 text-xs"
                  onClick={() => onReplay(e.request)}>
                  <RotateCcw size={12} />
                  {de.history.replay}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
