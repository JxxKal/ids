import { useEffect, useState } from 'react';
import { fetchConnectionGraph } from '../api';
import type { ConnectionGraphData, ConnectionSummary } from '../api';
import type { Alert } from '../types';

// ── Layout constants ──────────────────────────────────────────────────────────
const W         = 700;   // viewBox width
const NODE_W    = 148;   // width of host box
const NODE_X_R  = W - NODE_W;
const ARW_X1    = NODE_W + 10;   // arrow start x (right edge of left node + gap)
const ARW_X2    = NODE_X_R - 10; // arrow end x
const ARW_MID   = (ARW_X1 + ARW_X2) / 2;
const ROW_H     = 54;
const TOP_PAD   = 16;
const BOT_PAD   = 16;

// ── Protocol colour palette ───────────────────────────────────────────────────
const PROTO_COLORS: Record<string, string> = {
  TCP:  '#38bdf8',
  UDP:  '#fb923c',
  ICMP: '#a78bfa',
  ICMP6:'#c084fc',
};
function protoColor(p: string) {
  return PROTO_COLORS[p.toUpperCase()] ?? '#94a3b8';
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtBytes(b: number): string {
  if (b < 1024) return `${b} B`;
  if (b < 1024 ** 2) return `${(b / 1024).toFixed(1)} KB`;
  return `${(b / 1024 ** 2).toFixed(1)} MB`;
}

// ── Arrowhead marker definitions (right + left per colour) ───────────────────
function Markers() {
  const entries = [...Object.entries(PROTO_COLORS), ['OTHER', '#94a3b8']] as [string, string][];
  return (
    <defs>
      {entries.map(([key, fill]) => (
        <g key={key}>
          <marker id={`arR-${key}`} markerWidth="7" markerHeight="6"
            refX="6" refY="3" orient="auto">
            <polygon points="0 0, 7 3, 0 6" fill={fill} />
          </marker>
          <marker id={`arL-${key}`} markerWidth="7" markerHeight="6"
            refX="1" refY="3" orient="auto-start-reverse">
            <polygon points="7 0, 0 3, 7 6" fill={fill} />
          </marker>
        </g>
      ))}
    </defs>
  );
}

// ── One connection row ────────────────────────────────────────────────────────
function ConnectionRow({
  conn, alertSrcIp, rowIdx, y,
}: {
  conn:       ConnectionSummary;
  alertSrcIp: string;
  rowIdx:     number;
  y:          number;  // center y of this row
}) {
  const leftToRight = conn.src_ip === alertSrcIp;
  const color       = protoColor(conn.proto);
  const colorKey    = PROTO_COLORS[conn.proto.toUpperCase()] ? conn.proto.toUpperCase() : 'OTHER';
  const markerId    = leftToRight ? `arR-${colorKey}` : `arL-${colorKey}`;
  const x1          = leftToRight ? ARW_X1 : ARW_X2;
  const x2          = leftToRight ? ARW_X2 : ARW_X1;
  const label       = conn.dst_port ? `${conn.proto}:${conn.dst_port}` : conn.proto;
  const sub         = `${conn.flow_count} Flow${conn.flow_count !== 1 ? 's' : ''} · ${fmtBytes(conn.byte_count)}`;

  return (
    <g>
      {/* Alternating row bg */}
      <rect x={ARW_X1 - 4} y={y - ROW_H / 2} width={ARW_X2 - ARW_X1 + 8} height={ROW_H}
        fill={rowIdx % 2 === 0 ? '#0f172a' : '#0c1422'} opacity="0.5" />

      {/* Arrow shaft */}
      <line x1={x1} y1={y} x2={x2} y2={y}
        stroke={color} strokeWidth="1.5"
        markerEnd={`url(#${markerId})`} />

      {/* Protocol + port */}
      <text x={ARW_MID} y={y - 7} textAnchor="middle"
        fill={color} fontSize="12" fontWeight="700" fontFamily="monospace">
        {label}
      </text>

      {/* Flow count + bytes */}
      <text x={ARW_MID} y={y + 10} textAnchor="middle"
        fill="#64748b" fontSize="10.5" fontFamily="sans-serif">
        {sub}
      </text>
    </g>
  );
}

// ── Host box ──────────────────────────────────────────────────────────────────
function HostBox({
  x, ip, hostname, label, boxY, boxH,
}: {
  x: number; ip: string; hostname?: string; label: string; boxY: number; boxH: number;
}) {
  const cy = boxY + boxH / 2;
  return (
    <g>
      <rect x={x} y={boxY} width={NODE_W} height={boxH}
        rx="6" fill="#1e293b" stroke="#334155" strokeWidth="1" />
      <text x={x + NODE_W / 2} y={cy - 14} textAnchor="middle"
        fill="#64748b" fontSize="9" fontFamily="sans-serif"
        style={{ textTransform: 'uppercase' }}>
        {label}
      </text>
      <text x={x + NODE_W / 2} y={cy + 2} textAnchor="middle"
        fill="#e2e8f0" fontSize="12.5" fontWeight="700" fontFamily="monospace">
        {ip}
      </text>
      {hostname && (
        <text x={x + NODE_W / 2} y={cy + 18} textAnchor="middle"
          fill="#475569" fontSize="9.5" fontFamily="sans-serif">
          {hostname.length > 20 ? hostname.slice(0, 18) + '…' : hostname}
        </text>
      )}
    </g>
  );
}

// ── Main component ────────────────────────────────────────────────────────────
export function ConnectionGraph({ alert, onClose }: { alert: Alert; onClose: () => void }) {
  const [data, setData]       = useState<ConnectionGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);

  useEffect(() => {
    if (!alert.src_ip || !alert.dst_ip) {
      setError('Alert hat keine Quell- oder Ziel-IP.');
      setLoading(false);
      return;
    }
    const ts = new Date(alert.ts).getTime() / 1000;
    fetchConnectionGraph(alert.src_ip, alert.dst_ip, ts)
      .then(setData)
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }, [alert]);

  // SVG dimensions
  const rowCount = Math.max(1, data?.connections.length ?? 3);
  const contentH = rowCount * ROW_H;
  const svgH     = TOP_PAD + contentH + BOT_PAD;
  const boxY     = TOP_PAD;

  const alertTs    = new Date(alert.ts);
  const windowMin  = data?.window_min ?? 5;
  const tsFrom     = new Date(alertTs.getTime() - windowMin * 60_000);
  const tsTo       = new Date(alertTs.getTime() + windowMin * 60_000);
  const fmtTime    = (d: Date) => d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  return (
    <div
      className="fixed inset-0 bg-black/80 flex items-center justify-center z-[60] p-4"
      onClick={onClose}
    >
      <div
        className="card w-full max-w-3xl max-h-[90vh] overflow-y-auto"
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800">
          <div>
            <span className="font-semibold text-slate-100 text-sm">Verbindungsgraph</span>
            <span className="text-slate-500 text-xs ml-2">
              {fmtTime(tsFrom)} – {fmtTime(tsTo)}
              {' '}(±{windowMin} min um Alert-Zeitpunkt)
            </span>
          </div>
          <button onClick={onClose} className="text-slate-500 hover:text-slate-200 text-lg leading-none">×</button>
        </div>

        <div className="px-4 pt-3 pb-4">
          {loading && (
            <div className="text-slate-400 text-sm py-10 text-center">
              Lade Verbindungen…
            </div>
          )}
          {error && (
            <div className="text-red-400 text-sm py-10 text-center">{error}</div>
          )}
          {data && (
            <>
              {/* Stats row */}
              <div className="flex gap-4 mb-3 text-xs text-slate-500">
                <span>{data.total_flows} Flows gesamt</span>
                <span>·</span>
                <span>{data.connections.length} Verbindungsgruppen</span>
                <span>·</span>
                <span className="text-slate-600">
                  {alert.src_ip} ↔ {alert.dst_ip}
                </span>
              </div>

              {/* SVG graph */}
              <svg
                viewBox={`0 0 ${W} ${svgH}`}
                className="w-full rounded border border-slate-800 bg-slate-950"
                style={{ minHeight: 140 }}
              >
                <Markers />

                {/* Host boxes */}
                <HostBox
                  x={0} ip={alert.src_ip!}
                  hostname={alert.enrichment?.src_hostname}
                  label="Quelle"
                  boxY={boxY} boxH={contentH}
                />
                <HostBox
                  x={NODE_X_R} ip={alert.dst_ip!}
                  hostname={alert.enrichment?.dst_hostname}
                  label="Ziel"
                  boxY={boxY} boxH={contentH}
                />

                {/* Connection arrows */}
                {data.connections.length === 0 ? (
                  <text x={W / 2} y={svgH / 2} textAnchor="middle"
                    fill="#475569" fontSize="13" fontFamily="sans-serif">
                    Keine Flows im Zeitfenster gefunden
                  </text>
                ) : (
                  data.connections.map((conn, i) => (
                    <ConnectionRow
                      key={i}
                      conn={conn}
                      alertSrcIp={alert.src_ip!}
                      rowIdx={i}
                      y={boxY + i * ROW_H + ROW_H / 2}
                    />
                  ))
                )}
              </svg>

              {/* Legend */}
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2.5 px-0.5">
                {[['TCP','#38bdf8'],['UDP','#fb923c'],['ICMP','#a78bfa'],['Sonstige','#94a3b8']].map(([p, c]) => (
                  <div key={p} className="flex items-center gap-1.5">
                    <div className="w-4 h-px" style={{ backgroundColor: c, borderTop: `2px solid ${c}` }} />
                    <span className="text-xs text-slate-500">{p}</span>
                  </div>
                ))}
                <span className="text-xs text-slate-600 ml-auto">
                  → Quelle initiiert &nbsp;·&nbsp; ← Ziel initiiert
                </span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
