import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
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
  conn, alertSrcIp, rowIdx, y, t,
}: {
  conn:       ConnectionSummary;
  alertSrcIp: string;
  rowIdx:     number;
  y:          number;  // center y of this row
  t:          TFunction;
}) {
  const leftToRight = conn.src_ip === alertSrcIp;
  const color       = protoColor(conn.proto);
  const colorKey    = PROTO_COLORS[conn.proto.toUpperCase()] ? conn.proto.toUpperCase() : 'OTHER';
  const markerId    = leftToRight ? `arR-${colorKey}` : `arL-${colorKey}`;
  const x1          = leftToRight ? ARW_X1 : ARW_X2;
  const x2          = leftToRight ? ARW_X2 : ARW_X1;
  const label       = conn.dst_port ? `${conn.proto}:${conn.dst_port}` : conn.proto;
  const flowWord    = conn.flow_count !== 1 ? t('connectionGraph.flowPlural') : t('connectionGraph.flowSingular');
  const sub         = `${conn.flow_count} ${flowWord} · ${fmtBytes(conn.byte_count)}`;

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
  const { t } = useTranslation();
  const [data, setData]       = useState<ConnectionGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError]     = useState<string | null>(null);

  useEffect(() => {
    if (!alert.src_ip || !alert.dst_ip) {
      setError(t('connectionGraph.noIp'));
      setLoading(false);
      return;
    }
    const ts = new Date(alert.ts).getTime() / 1000;
    fetchConnectionGraph(alert.src_ip, alert.dst_ip, ts)
      .then(setData)
      .catch(e => setError(String(e)))
      .finally(() => setLoading(false));
  }, [alert, t]);

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
      className="fixed inset-0 bg-black/80 flex items-end md:items-center justify-center z-[60] p-0 md:p-4"
      onClick={onClose}
    >
      <div
        className="card w-full max-w-3xl h-[92vh] rounded-t-2xl flex flex-col md:h-auto md:max-h-[90vh] md:rounded-xl"
        onClick={e => e.stopPropagation()}
      >
        {/* Mobile-Drag-Handle */}
        <div className="md:hidden flex-none flex justify-center pt-2 pb-1">
          <div className="w-10 h-1 rounded-full bg-slate-600/50" />
        </div>

        {/* Header */}
        <div className="flex-none flex items-center justify-between px-3 md:px-4 py-3 border-b border-slate-800 gap-2">
          <div className="min-w-0">
            <span className="font-semibold text-slate-100 text-sm">{t('connectionGraph.title')}</span>
            <span className="text-slate-500 text-xs ml-2">
              {fmtTime(tsFrom)} – {fmtTime(tsTo)}
              {' '}{t('connectionGraph.windowLabel', { minutes: windowMin })}
            </span>
          </div>
          <button
            onClick={onClose}
            title={t('common.close')}
            className="text-[11px] px-3 py-2 md:py-1 rounded border border-slate-600/30 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors min-w-[44px] flex items-center justify-center shrink-0"
          >
            ✕
          </button>
        </div>

        <div className="flex-1 min-h-0 overflow-y-auto px-3 md:px-4 pt-3 pb-4">
          {loading && (
            <div className="text-slate-400 text-sm py-10 text-center">
              {t('connectionGraph.loading')}
            </div>
          )}
          {error && (
            <div className="text-red-400 text-sm py-10 text-center">{error}</div>
          )}
          {data && (
            <>
              {/* Stats row */}
              <div className="flex flex-wrap gap-x-3 gap-y-1 mb-3 text-xs text-slate-500">
                <span>{t('connectionGraph.totalFlows', { count: data.total_flows })}</span>
                <span className="hidden md:inline">·</span>
                <span>{t('connectionGraph.connectionGroups', { count: data.connections.length })}</span>
                <span className="hidden md:inline">·</span>
                <span className="text-slate-600 basis-full md:basis-auto break-all">
                  {alert.src_ip} ↔ {alert.dst_ip}
                </span>
              </div>

              {/* SVG graph (Desktop) — auf Mobile (<768px) ist der 700px-
                  viewBox so stark verkleinert, dass Ports/Bytes-Labels nicht
                  mehr lesbar sind. Stattdessen rendern wir auf Mobile eine
                  Connection-Liste mit denselben Daten. */}
              <svg
                viewBox={`0 0 ${W} ${svgH}`}
                className="hidden md:block w-full rounded border border-slate-800 bg-slate-950"
                style={{ minHeight: 140 }}
              >
                <Markers />
                <HostBox
                  x={0} ip={alert.src_ip!}
                  hostname={alert.enrichment?.src_hostname}
                  label={t('connectionGraph.source')}
                  boxY={boxY} boxH={contentH}
                />
                <HostBox
                  x={NODE_X_R} ip={alert.dst_ip!}
                  hostname={alert.enrichment?.dst_hostname}
                  label={t('connectionGraph.destination')}
                  boxY={boxY} boxH={contentH}
                />
                {data.connections.length === 0 ? (
                  <text x={W / 2} y={svgH / 2} textAnchor="middle"
                    fill="#475569" fontSize="13" fontFamily="sans-serif">
                    {t('connectionGraph.noFlows')}
                  </text>
                ) : (
                  data.connections.map((conn, i) => (
                    <ConnectionRow
                      key={i}
                      conn={conn}
                      alertSrcIp={alert.src_ip!}
                      rowIdx={i}
                      y={boxY + i * ROW_H + ROW_H / 2}
                      t={t}
                    />
                  ))
                )}
              </svg>

              {/* Connection-Liste (Mobile) — vertikal gestapelt, kompakt
                  lesbar, Pfeil-Direction farblich pro Protokoll. */}
              <div className="md:hidden">
                {data.connections.length === 0 ? (
                  <div className="text-slate-600 text-sm text-center py-10">{t('connectionGraph.noFlows')}</div>
                ) : (
                  <div className="flex flex-col gap-1.5">
                    {data.connections.map((conn, i) => {
                      const color = protoColor(conn.proto);
                      const initFromSrc = conn.src_ip === alert.src_ip;
                      return (
                        <div
                          key={i}
                          className="rounded border border-slate-800 bg-slate-950/40 p-2.5 flex items-center gap-2"
                          style={{ borderLeft: `3px solid ${color}` }}
                        >
                          <div className="flex-1 min-w-0">
                            <div className="font-mono text-[11px] text-slate-300">
                              <span style={{ color }}>{conn.proto}</span>
                              {conn.dst_port != null && (
                                <span className="text-slate-400">:{conn.dst_port}</span>
                              )}
                              <span className="text-slate-600 mx-1.5">{initFromSrc ? '→' : '←'}</span>
                              <span className="text-slate-500">
                                {t('connectionGraph.flowsCount', { count: conn.flow_count, defaultValue: '{{count}} Flows' })}
                              </span>
                            </div>
                            <div className="text-[10px] text-slate-600 font-mono mt-0.5">
                              {fmtBytes(conn.byte_count)} · {conn.pkt_count} Pkts
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                )}
              </div>

              {/* Legend */}
              <div className="flex flex-wrap items-center gap-x-4 gap-y-1 mt-2.5 px-0.5">
                {[['TCP','#38bdf8'],['UDP','#fb923c'],['ICMP','#a78bfa'],[t('connectionGraph.legendOther'),'#94a3b8']].map(([p, c]) => (
                  <div key={p} className="flex items-center gap-1.5">
                    <div className="w-4 h-px" style={{ backgroundColor: c, borderTop: `2px solid ${c}` }} />
                    <span className="text-xs text-slate-500">{p}</span>
                  </div>
                ))}
                <span className="text-xs text-slate-600 ml-auto hidden md:inline">
                  → {t('connectionGraph.legendSourceInit')} &nbsp;·&nbsp; ← {t('connectionGraph.legendDestInit')}
                </span>
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
