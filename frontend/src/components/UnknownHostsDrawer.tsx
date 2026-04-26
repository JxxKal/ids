import { useState, useEffect, useMemo } from 'react';
import { createPortal } from 'react-dom';
import { fetchUnknownHosts, createHost } from '../api';
import type { UnknownHost } from '../api';

const SEV_CLS: Record<string, string> = {
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-green-400',
};

function fmt(iso: string | null): string {
  if (!iso) return '–';
  const d = new Date(iso);
  return d.toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

export function UnknownHostsDrawer({ onClose }: { onClose: () => void }) {
  const [hosts,   setHosts]   = useState<UnknownHost[]>([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');
  const [search,  setSearch]  = useState('');
  const [added,   setAdded]   = useState<Set<string>>(new Set());
  const [adding,  setAdding]  = useState<string | null>(null);

  // ESC schließt – konsistent mit AlertFlowPopup, HostConnectionDrawer
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  useEffect(() => {
    fetchUnknownHosts(30)
      .then(setHosts)
      .catch(() => setError('Daten konnten nicht geladen werden'))
      .finally(() => setLoading(false));
  }, []);

  const filtered = useMemo(() =>
    search.trim()
      ? hosts.filter(h => h.ip.includes(search.trim()))
      : hosts,
    [hosts, search],
  );

  async function handleAdd(ip: string) {
    setAdding(ip);
    try {
      await createHost({ ip, trusted: false });
      setAdded(prev => new Set([...prev, ip]));
    } catch {
      // ignore, user can retry
    } finally {
      setAdding(null);
    }
  }

  return createPortal(
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="relative bg-slate-900 border border-slate-700 rounded-lg shadow-2xl flex flex-col overflow-hidden"
        style={{ width: '92vw', maxWidth: '900px', height: '82dvh', maxHeight: 'calc(100dvh - 32px)' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-slate-700 shrink-0">
          <svg className="w-4 h-4 text-amber-400 shrink-0" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <circle cx="12" cy="12" r="9"/><path d="M12 8v4m0 4h.01"/>
          </svg>
          <span className="text-slate-200 font-mono text-sm">
            Unbekannte Hosts
            {!loading && !error && (
              <span className="ml-2 text-amber-400 font-semibold">{filtered.length}</span>
            )}
          </span>
          <span className="text-[11px] text-slate-600 font-mono">letzte 30 Tage</span>
          <div className="flex-1" />
          <button onClick={onClose} title="Schließen"
            className="text-[11px] px-3 py-1 rounded border border-slate-600/30 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors">
            ESC · ✕
          </button>
        </div>

        {/* Search */}
        {!loading && !error && (
          <div className="px-4 py-2 border-b border-slate-700/50 shrink-0">
            <input
              type="text"
              value={search}
              onChange={e => setSearch(e.target.value)}
              placeholder="IP filtern…"
              className="w-64 bg-slate-800 border border-slate-600 rounded px-2 py-1 text-xs font-mono text-slate-200 outline-none focus:border-cyan-600 placeholder:text-slate-600"
            />
          </div>
        )}

        {/* Body */}
        <div className="flex-1 overflow-y-auto min-h-0">
          {loading ? (
            <div className="flex items-center justify-center h-full text-slate-500 text-sm">Lade…</div>
          ) : error ? (
            <div className="flex items-center justify-center h-full text-red-400 text-sm">{error}</div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full gap-2">
              <span className="text-green-400 text-lg">✓</span>
              <span className="text-slate-500 text-sm">Alle Hosts sind bekannt</span>
            </div>
          ) : (
            <table className="w-full border-collapse text-xs font-mono">
              <thead className="sticky top-0 bg-slate-900/95 backdrop-blur-sm z-10">
                <tr className="text-left text-slate-500 border-b border-slate-700 text-[11px]">
                  <th className="px-3 py-2">IP-Adresse</th>
                  <th className="px-3 py-2 w-20 text-right">Alerts</th>
                  <th className="px-3 py-2 w-20">Severity</th>
                  <th className="px-3 py-2 w-36">Zuletzt gesehen</th>
                  <th className="px-3 py-2 w-36">Erstmals gesehen</th>
                  <th className="px-3 py-2 w-32"></th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(h => {
                  const isAdded  = added.has(h.ip);
                  const isAdding = adding === h.ip;
                  return (
                    <tr key={h.ip} className="border-b border-slate-800/50 hover:bg-slate-800/40">
                      <td className="px-3 py-1.5 text-cyan-300 tabular-nums">{h.ip}</td>
                      <td className="px-3 py-1.5 text-right tabular-nums text-slate-300">{h.alert_count}</td>
                      <td className={`px-3 py-1.5 font-semibold ${SEV_CLS[h.top_severity ?? ''] ?? 'text-slate-500'}`}>
                        {h.top_severity ?? '–'}
                      </td>
                      <td className="px-3 py-1.5 text-slate-400">{fmt(h.last_seen)}</td>
                      <td className="px-3 py-1.5 text-slate-500">{fmt(h.first_seen)}</td>
                      <td className="px-3 py-1.5">
                        {isAdded ? (
                          <span className="text-green-400 text-[11px]">✓ Hinzugefügt</span>
                        ) : (
                          <button
                            onClick={() => handleAdd(h.ip)}
                            disabled={isAdding}
                            className="px-2 py-0.5 rounded border border-slate-600 text-slate-400 hover:border-cyan-600 hover:text-cyan-300 transition-colors disabled:opacity-40 text-[11px]"
                          >
                            {isAdding ? '…' : '+ Inventar'}
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>

        {/* Footer */}
        {!loading && !error && filtered.length > 0 && (
          <div className="shrink-0 px-4 py-2 border-t border-slate-700/50 text-[11px] text-slate-600 font-mono">
            Hosts ohne hostname oder display_name in host_info · Klick auf "+ Inventar" legt den Host an
          </div>
        )}
      </div>
    </div>,
    document.body,
  );
}
