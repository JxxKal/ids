/**
 * HostConnectionDrawer
 *
 * Slide-In von rechts mit grafischer Übersicht aller Verbindungen eines
 * Hosts in einem Zeitfenster. Wird über ein globales CustomEvent geöffnet:
 *
 *     window.dispatchEvent(new CustomEvent('ids:show-host-connections', {
 *       detail: { ip: '192.168.1.42' }
 *     }));
 *
 * Komponenten:
 *   • Time-Range-Preset-Buttons (15m / 1h / 6h / 24h) – snap zum Bucket
 *   • Histogramm-Sparkline darunter (Flow-Counts pro Bucket)
 *   • Radial-SVG-Plot: Host in der Mitte, Peers auf einem Kreis. Edge-
 *     Stärke aus log(Bytes), Edge-Farbe aus max_severity.
 *   • Peer-Liste mit Direction, Bytes, Top-Ports und Alert-Count.
 */
import { useEffect, useMemo, useState } from 'react';
import { X, ArrowRight, ArrowLeft, ArrowLeftRight, AlertTriangle } from 'lucide-react';
import { fetchHostConnections } from '../api';
import type {
  HostConnectionsResponse,
  HostConnectionPeer,
  HostConnectionWindow,
} from '../api';

const WINDOWS: { id: HostConnectionWindow; label: string }[] = [
  { id: '15m', label: '15 min' },
  { id: '1h',  label: '1 h'   },
  { id: '6h',  label: '6 h'   },
  { id: '24h', label: '24 h'  },
];

const SEV_COLOR: Record<NonNullable<HostConnectionPeer['max_severity']>, string> = {
  low:      '#22c55e',
  medium:   '#eab308',
  high:     '#f97316',
  critical: '#ef4444',
};
const NEUTRAL_EDGE = '#475569';

const fmtBytes = (b: number): string => {
  if (b < 1024) return `${b} B`;
  if (b < 1024 * 1024) return `${(b / 1024).toFixed(1)} KB`;
  if (b < 1024 * 1024 * 1024) return `${(b / 1024 / 1024).toFixed(1)} MB`;
  return `${(b / 1024 / 1024 / 1024).toFixed(2)} GB`;
};

export function HostConnectionDrawer() {
  const [ip,     setIp]     = useState<string | null>(null);
  const [windowSel, setWindowSel] = useState<HostConnectionWindow>('1h');
  const [data,   setData]   = useState<HostConnectionsResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error,  setError]  = useState<string | null>(null);

  // ── Globaler Event-Listener für Open/Close ─────────────────────────────────
  useEffect(() => {
    function open(e: Event) {
      const ce = e as CustomEvent<{ ip?: string }>;
      const newIp = ce.detail?.ip;
      if (typeof newIp === 'string' && newIp) {
        setIp(newIp);
        setError(null);
      }
    }
    function onEsc(e: KeyboardEvent) {
      if (e.key === 'Escape') setIp(null);
    }
    window.addEventListener('ids:show-host-connections', open);
    window.addEventListener('keydown', onEsc);
    return () => {
      window.removeEventListener('ids:show-host-connections', open);
      window.removeEventListener('keydown', onEsc);
    };
  }, []);

  // ── Daten laden bei IP- oder Window-Change ────────────────────────────────
  useEffect(() => {
    if (!ip) return;
    let alive = true;
    setLoading(true);
    setError(null);
    fetchHostConnections(ip, windowSel)
      .then(d => { if (alive) { setData(d); setLoading(false); } })
      .catch(e => { if (alive) { setError(e instanceof Error ? e.message : String(e)); setLoading(false); } });
    return () => { alive = false; };
  }, [ip, windowSel]);

  if (!ip) return null;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 z-40 backdrop-blur-sm"
        onClick={() => setIp(null)}
      />

      {/* Drawer */}
      <aside
        className="fixed top-0 right-0 h-full w-full md:w-[720px] z-50
                   bg-slate-950 border-l border-slate-700/60
                   shadow-2xl overflow-y-auto"
      >
        <header className="sticky top-0 z-10 bg-slate-950/95 backdrop-blur
                           border-b border-slate-800 px-5 py-3 flex items-center gap-3">
          <div className="flex-1 min-w-0">
            <p className="text-[10px] uppercase tracking-widest text-slate-500">Host-Verbindungen</p>
            <h2 className="font-mono text-base text-slate-100 truncate">{ip}</h2>
          </div>
          <button
            type="button"
            onClick={() => setIp(null)}
            className="p-1.5 rounded hover:bg-slate-800 text-slate-400 hover:text-slate-200 transition"
            title="Schließen (Esc)"
          >
            <X size={18} />
          </button>
        </header>

        <div className="px-5 py-4 space-y-5">
          {/* Time-Range-Buttons */}
          <div className="flex items-center gap-1 bg-slate-900/60 border border-slate-700/50 rounded-lg p-1 w-fit">
            {WINDOWS.map(w => (
              <button
                key={w.id}
                type="button"
                onClick={() => setWindowSel(w.id)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  windowSel === w.id
                    ? 'bg-cyan-700 text-white'
                    : 'text-slate-400 hover:text-slate-100 hover:bg-slate-800'
                }`}
              >
                {w.label}
              </button>
            ))}
            {data && (
              <span className="ml-2 text-[10px] text-slate-500 font-mono pl-2 border-l border-slate-700/50">
                {new Date(data.window_start * 1000).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
                {' → '}
                {new Date(data.window_end   * 1000).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit' })}
              </span>
            )}
          </div>

          {/* Sparkline */}
          {data && data.histogram.length > 0 && <Sparkline data={data} />}

          {error && (
            <p className="text-xs text-red-400 bg-red-950/40 border border-red-700/50 rounded px-3 py-2">
              {error}
            </p>
          )}

          {/* Radial-Graph */}
          {loading && !data && (
            <p className="text-xs text-slate-500 text-center py-8">Lade Verbindungen …</p>
          )}
          {data && data.peers.length === 0 && !loading && (
            <p className="text-xs text-slate-500 text-center py-8 italic">
              Keine Flows zu diesem Host im gewählten Zeitfenster.
            </p>
          )}
          {data && data.peers.length > 0 && (
            <RadialGraph host={ip} peers={data.peers} />
          )}

          {/* Peer-Liste */}
          {data && data.peers.length > 0 && (
            <PeerList peers={data.peers} truncated={data.peers.length >= 100} />
          )}
        </div>
      </aside>
    </>
  );
}

// ── Sparkline (Flow-Histogramm über das Fenster) ─────────────────────────────
function Sparkline({ data }: { data: HostConnectionsResponse }) {
  const W = 680;
  const H = 56;
  const pad = 2;

  const max = Math.max(1, ...data.histogram.map(b => b.flows));
  const buckets = data.histogram;
  const expectedBuckets = 60;
  // Volle 60 Buckets darstellen, auch wenn die DB für manche keine Zeile lieferte.
  const filled = useMemo(() => {
    const start = data.window_start;
    const step  = data.bucket_sec;
    const arr: { ts: number; flows: number }[] = [];
    const lookup = new Map(buckets.map(b => [Math.floor(b.ts / step) * step, b.flows]));
    for (let i = 0; i < expectedBuckets; i++) {
      const ts = start + i * step;
      arr.push({ ts, flows: lookup.get(Math.floor(ts / step) * step) ?? 0 });
    }
    return arr;
  }, [buckets, data.window_start, data.bucket_sec]);

  const barW = (W - pad * 2) / expectedBuckets;

  return (
    <div className="rounded border border-slate-800 bg-slate-900/40 p-2">
      <div className="flex items-baseline justify-between mb-1">
        <span className="text-[10px] uppercase tracking-widest text-slate-500">Flows pro {fmtBucket(data.bucket_sec)}</span>
        <span className="text-[10px] text-slate-500 font-mono">max {max}</span>
      </div>
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none" style={{ display: 'block' }}>
        {filled.map((b, i) => {
          const h = b.flows === 0 ? 0 : Math.max(1.5, (b.flows / max) * (H - pad * 2));
          return (
            <rect
              key={i}
              x={pad + i * barW}
              y={H - pad - h}
              width={Math.max(1, barW - 1)}
              height={h}
              fill={b.flows > 0 ? '#0ea5e9' : '#1e293b'}
              opacity={b.flows > 0 ? 0.85 : 1}
            />
          );
        })}
      </svg>
    </div>
  );
}

function fmtBucket(sec: number): string {
  if (sec < 60)    return `${sec} s`;
  if (sec < 3600)  return `${Math.round(sec / 60)} min`;
  return `${(sec / 3600).toFixed(1)} h`;
}

// ── Radial-SVG-Plot ──────────────────────────────────────────────────────────
function RadialGraph({ host, peers }: { host: string; peers: HostConnectionPeer[] }) {
  const W = 680;
  const H = 380;
  const cx = W / 2;
  const cy = H / 2;
  const radius = Math.min(W, H) * 0.36;

  // Auf 30 Peers begrenzen – sonst wird der Kreis unleserlich. Nach Bytes
  // sortieren, der Server liefert sie ohnehin so.
  const top = peers.slice(0, 30);
  const truncated = peers.length > 30;

  const maxBytes = Math.max(1, ...top.map(p => p.total_bytes));

  return (
    <div className="rounded border border-slate-800 bg-slate-900/40 p-2">
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} role="img" aria-label={`Verbindungen von ${host}`}>
        {/* Edges first (under the nodes) */}
        {top.map((p, i) => {
          const angle = (i / top.length) * 2 * Math.PI - Math.PI / 2;
          const px = cx + Math.cos(angle) * radius;
          const py = cy + Math.sin(angle) * radius;
          // Stärke aus log(bytes), 1–6 px
          const t = Math.max(0, Math.log10(p.total_bytes + 1)) /
                    Math.max(1, Math.log10(maxBytes + 1));
          const stroke = p.max_severity ? SEV_COLOR[p.max_severity] : NEUTRAL_EDGE;
          return (
            <line
              key={`e-${p.ip}`}
              x1={cx} y1={cy} x2={px} y2={py}
              stroke={stroke}
              strokeWidth={1 + t * 5}
              strokeOpacity={0.55 + t * 0.45}
              strokeLinecap="round"
            />
          );
        })}

        {/* Direction arrowheads, kleine Spitze nahe dem Peer-Node */}
        {top.map((p, i) => {
          const angle = (i / top.length) * 2 * Math.PI - Math.PI / 2;
          const px = cx + Math.cos(angle) * (radius - 22);
          const py = cy + Math.sin(angle) * (radius - 22);
          const sym = p.direction === 'both' ? '↔' : p.direction === 'out' ? '→' : '←';
          return (
            <text
              key={`a-${p.ip}`}
              x={px} y={py}
              fontSize="11"
              fill="#94a3b8"
              textAnchor="middle"
              dominantBaseline="middle"
              transform={`rotate(${(angle * 180) / Math.PI + 90} ${px} ${py})`}
            >
              {sym}
            </text>
          );
        })}

        {/* Center node = host */}
        <circle cx={cx} cy={cy} r={26} fill="#0ea5e9" stroke="#7dd3fc" strokeWidth="2" />
        <text x={cx} y={cy + 4} fontSize="11" fill="#0b1220" textAnchor="middle" fontWeight="700">HOST</text>
        <text x={cx} y={cy + 46} fontSize="10" fill="#cbd5e1" textAnchor="middle" fontFamily="monospace">{host}</text>

        {/* Peer nodes + labels */}
        {top.map((p, i) => {
          const angle = (i / top.length) * 2 * Math.PI - Math.PI / 2;
          const px = cx + Math.cos(angle) * radius;
          const py = cy + Math.sin(angle) * radius;
          const fill   = p.max_severity ? SEV_COLOR[p.max_severity] : '#1e293b';
          const stroke = p.max_severity ? SEV_COLOR[p.max_severity] : '#64748b';

          // Label-Position außen
          const lx = cx + Math.cos(angle) * (radius + 14);
          const ly = cy + Math.sin(angle) * (radius + 14);
          // Auf der linken Seite Anker rechts, sonst links
          const anchor = Math.cos(angle) < -0.2 ? 'end' : Math.cos(angle) > 0.2 ? 'start' : 'middle';

          return (
            <g key={`n-${p.ip}`}>
              <circle cx={px} cy={py} r={7} fill={fill} stroke={stroke} strokeWidth="1.5" opacity={0.95} />
              <text
                x={lx} y={ly + 3}
                fontSize="10"
                fill="#cbd5e1"
                textAnchor={anchor}
                fontFamily="monospace"
              >
                {p.ip}
              </text>
            </g>
          );
        })}
      </svg>
      {truncated && (
        <p className="text-[10px] text-amber-400 italic mt-1 px-2">
          Top 30 von {peers.length} Peers (nach Bytes). Rest in der Liste unten.
        </p>
      )}
    </div>
  );
}

// ── Peer-Liste mit Details ───────────────────────────────────────────────────
function PeerList({ peers, truncated }: { peers: HostConnectionPeer[]; truncated: boolean }) {
  return (
    <div className="space-y-1">
      <p className="text-[10px] uppercase tracking-widest text-slate-500 mb-1">Peers ({peers.length})</p>
      {peers.map(p => {
        const dirIcon = p.direction === 'both' ? <ArrowLeftRight size={11} /> :
                        p.direction === 'out'  ? <ArrowRight     size={11} /> :
                                                 <ArrowLeft      size={11} />;
        const sevColor = p.max_severity ? SEV_COLOR[p.max_severity] : undefined;
        return (
          <div
            key={p.ip}
            className="grid grid-cols-[auto_1fr_auto] gap-3 items-center
                       px-3 py-1.5 rounded border border-slate-800
                       bg-slate-900/40 text-xs"
          >
            <span className="text-slate-500 flex items-center gap-1.5">
              {dirIcon}
              <span className="uppercase text-[9px] tracking-widest">{p.direction}</span>
            </span>

            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-slate-100 truncate">{p.ip}</span>
                {p.alert_count > 0 && sevColor && (
                  <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded
                                   text-[10px] font-medium border"
                        style={{
                          color:  sevColor,
                          borderColor: sevColor + '66',
                          backgroundColor: sevColor + '14',
                        }}>
                    <AlertTriangle size={10} />
                    {p.alert_count} {p.max_severity}
                  </span>
                )}
              </div>
              <div className="text-slate-500 text-[10px] flex items-center gap-3 mt-0.5 flex-wrap">
                <span>{p.flow_count} flows</span>
                <span className="font-mono">{fmtBytes(p.total_bytes)}</span>
                {p.top_ports.length > 0 && (
                  <span className="font-mono text-slate-400">
                    {p.top_ports.slice(0, 3).map(tp => `${tp.proto.toLowerCase()}/${tp.port}`).join(' · ')}
                  </span>
                )}
              </div>
            </div>

            <div className="text-right text-[10px] font-mono text-slate-500">
              <div>↑ {fmtBytes(p.bytes_out)}</div>
              <div>↓ {fmtBytes(p.bytes_in)}</div>
            </div>
          </div>
        );
      })}
      {truncated && (
        <p className="text-[10px] italic text-slate-500 mt-2">
          Nur 100 Peers angezeigt – API-Limit. Bei dichtem Traffic Zeitfenster verkleinern.
        </p>
      )}
    </div>
  );
}

// ── Convenience-Helper für Trigger-Sites ─────────────────────────────────────

export function showHostConnections(ip: string): void {
  window.dispatchEvent(new CustomEvent('ids:show-host-connections', { detail: { ip } }));
}
