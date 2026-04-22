import { useEffect, useMemo, useRef, useState } from 'react';
import { fetchConnectionGraph, type ConnectionGraphData, type ConnectionSummary } from '../api';
import type { Alert } from '../types';

interface Props {
  alert: Alert;
  onClose: () => void;
}

type Proto = 'TCP' | 'UDP' | 'ICMP' | 'OTHER';

interface Conn {
  id:      string;
  from:    'a' | 'b';
  proto:   Proto;
  port:    number | null;
  packets: number;
  bytes:   number;
  flows:   number;
  threat:  boolean;
}

interface ConnState extends Conn {
  born:  number;
  dying: number | null;
}

const PROTO_COLOR: Record<Proto, string> = {
  TCP:   '#38bdf8',
  UDP:   '#fb923c',
  ICMP:  '#a78bfa',
  OTHER: '#94a3b8',
};

const VB_W = 1000;
const VB_H = 380;
const A_X  = 222, A_Y = VB_H / 2;
const B_X  = 778, B_Y = VB_H / 2;

function normProto(p: string): Proto {
  const up = p.toUpperCase();
  if (up === 'TCP' || up === 'UDP' || up === 'ICMP') return up;
  return 'OTHER';
}

function mapConnections(data: ConnectionGraphData, alertSrc: string): Conn[] {
  return data.connections.map((c: ConnectionSummary): Conn => ({
    id:      `${c.src_ip}-${c.dst_ip}-${c.proto}-${c.dst_port ?? 'x'}`,
    from:    c.src_ip === alertSrc ? 'a' : 'b',
    proto:   normProto(c.proto),
    port:    c.dst_port,
    packets: c.pkt_count,
    bytes:   c.byte_count,
    flows:   c.flow_count,
    threat:  false,
  }));
}

function hostMeta(alert: Alert, which: 'a' | 'b') {
  const e = alert.enrichment;
  if (which === 'a') {
    const ip   = alert.src_ip ?? '—';
    const name = e?.src_display_name ?? e?.src_hostname ?? ip;
    const net  = e?.src_network?.name;
    return { ip, name, kind: e?.src_trusted ? 'HOST' : '?', role: net };
  }
  const ip   = alert.dst_ip ?? '—';
  const name = e?.dst_display_name ?? e?.dst_hostname ?? ip;
  const net  = e?.dst_network?.name;
  const port = alert.dst_port ? `:${alert.dst_port}` : '';
  return { ip: `${ip}${port}`, name, kind: e?.dst_trusted ? 'HOST' : '?', role: net };
}

export function AlertFlowPopup({ alert, onClose }: Props) {
  const [data, setData] = useState<ConnectionGraphData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string>('');
  const stateRef = useRef<Map<string, ConnState>>(new Map());
  const [, force] = useState(0);
  const frameRef = useRef<number | null>(null);

  // Fetch graph data
  useEffect(() => {
    if (!alert.src_ip || !alert.dst_ip) {
      setError('Alert hat keine src/dst IP – kein Flow-Graph verfügbar.');
      setLoading(false);
      return;
    }
    const centerTs = Math.floor(new Date(alert.ts).getTime() / 1000);
    setLoading(true);
    fetchConnectionGraph(alert.src_ip, alert.dst_ip, centerTs, 5)
      .then(d => {
        setData(d);
        setError('');
      })
      .catch(e => setError(e instanceof Error ? e.message : 'Fetch-Fehler'))
      .finally(() => setLoading(false));
  }, [alert.alert_id, alert.src_ip, alert.dst_ip, alert.ts]);

  // Mark alert-matching connection as threat
  const connections = useMemo(() => {
    if (!data || !alert.src_ip) return [];
    const list = mapConnections(data, alert.src_ip);
    // highlight the connection that matches the alert (dst_port + proto)
    return list.map(c => {
      const matches = alert.proto
        ? normProto(alert.proto) === c.proto
          && (alert.dst_port == null || c.port === alert.dst_port)
        : false;
      return matches ? { ...c, threat: true } : c;
    });
  }, [data, alert]);

  // Diff connections into state for entry/exit animation
  useEffect(() => {
    const now = performance.now();
    const incoming = new Map(connections.map(c => [c.id, c]));
    for (const [id, c] of stateRef.current) {
      if (!incoming.has(id) && !c.dying) c.dying = now;
    }
    for (const c of connections) {
      const existing = stateRef.current.get(c.id);
      if (existing) {
        Object.assign(existing, c);
        existing.dying = null;
      } else {
        stateRef.current.set(c.id, { ...c, born: now, dying: null });
      }
    }
  }, [connections]);

  // Animation tick
  useEffect(() => {
    const tick = () => {
      const now = performance.now();
      for (const [id, c] of stateRef.current) {
        if (c.dying && now - c.dying > 500) stateRef.current.delete(id);
      }
      force(f => (f + 1) % 1e9);
      frameRef.current = requestAnimationFrame(tick);
    };
    frameRef.current = requestAnimationFrame(tick);
    return () => {
      if (frameRef.current != null) cancelAnimationFrame(frameRef.current);
      stateRef.current.clear();
    };
  }, []);

  // ESC to close
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose();
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  const active = [...stateRef.current.values()];
  const anyThreat = active.some(c => c.threat && !c.dying);
  const hostA = hostMeta(alert, 'a');
  const hostB = hostMeta(alert, 'b');

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{
        background: 'rgba(2,6,23,0.82)',
        backdropFilter: 'blur(4px)',
      }}
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div
        role="dialog"
        aria-modal="true"
        className="flex flex-col overflow-hidden"
        style={{
          width: 'min(960px, 96vw)',
          maxHeight: '90vh',
          background: 'linear-gradient(180deg, #0b1220 0%, #020617 100%)',
          border: '1px solid rgba(34,211,238,0.28)',
          borderRadius: 10,
          boxShadow:
            '0 0 0 1px rgba(34,211,238,0.08), 0 20px 60px rgba(2,6,23,0.7), 0 0 80px rgba(34,211,238,0.08)',
          fontFamily: 'JetBrains Mono, ui-monospace, monospace',
          color: '#e2e8f0',
        }}
      >
        {/* Header */}
        <div
          className="flex items-center justify-between px-5 py-3"
          style={{ borderBottom: '1px solid rgba(34,211,238,0.15)', background: 'rgba(15,26,45,0.6)' }}
        >
          <div className="flex items-center gap-3">
            <span
              className="text-[10px] font-bold uppercase tracking-[0.12em] px-2 py-0.5 rounded"
              style={{
                background:
                  alert.severity === 'critical' ? 'rgba(239,68,68,0.15)' :
                  alert.severity === 'high'     ? 'rgba(249,115,22,0.15)' :
                  alert.severity === 'medium'   ? 'rgba(234,179,8,0.15)' :
                                                  'rgba(34,197,94,0.15)',
                color:
                  alert.severity === 'critical' ? '#ef4444' :
                  alert.severity === 'high'     ? '#f97316' :
                  alert.severity === 'medium'   ? '#eab308' :
                                                  '#22c55e',
              }}
            >
              {alert.severity}
            </span>
            <h2 className="text-[13px] font-semibold m-0" style={{ letterSpacing: 0.5 }}>
              <span className="mr-2 text-cyan-300">{alert.rule_id}</span>
              <span className="text-slate-300">{alert.description}</span>
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-[11px] px-3 py-1 rounded border border-slate-600/30 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors"
          >
            ESC · ✕
          </button>
        </div>

        {/* Meta */}
        <div
          className="grid grid-cols-4 px-5 py-2.5 text-[10px]"
          style={{ borderBottom: '1px solid rgba(148,163,184,0.08)', background: 'rgba(2,6,23,0.4)' }}
        >
          <MetaCell label="Alert ID"   value={alert.alert_id.slice(0, 12) + '…'} cyan />
          <MetaCell label="First seen" value={new Date(alert.ts).toLocaleString()} />
          <MetaCell label="Source"     value={alert.source} />
          <MetaCell label="Window"     value={data ? `±${data.window_min} min · ${data.total_flows} flows` : '—'} />
        </div>

        {/* Stage */}
        <div
          className="relative"
          style={{
            height: VB_H,
            minHeight: VB_H,
            flexShrink: 0,
            background:
              'radial-gradient(ellipse at center, rgba(14,165,233,0.07), transparent 70%), linear-gradient(180deg, rgba(11,18,32,0.5), rgba(2,6,23,0.7))',
            overflow: 'hidden',
          }}
        >
          <div
            className="absolute top-3 right-4 z-10 flex items-center gap-1.5 text-[9px] uppercase tracking-[1.5px] px-2 py-1 rounded"
            style={{
              color: anyThreat ? '#fca5a5' : '#67e8f9',
              border: `1px solid ${anyThreat ? 'rgba(239,68,68,0.40)' : 'rgba(34,211,238,0.30)'}`,
              background: 'rgba(11,18,32,0.7)',
            }}
          >
            <span
              style={{
                width: 6, height: 6, borderRadius: '50%',
                background: anyThreat ? '#ef4444' : '#22d3ee',
                boxShadow: `0 0 8px ${anyThreat ? '#ef4444' : '#22d3ee'}`,
                animation: 'cyjan-flow-pulse 1.4s ease-in-out infinite',
              }}
            />
            {loading ? 'lade…' : `${active.filter(c => !c.dying).length} conns`}
          </div>

          <HostCard side="left"  host={hostA} isAlert={true} />
          <HostCard side="right" host={hostB} isAlert={false} />

          <svg viewBox={`0 0 ${VB_W} ${VB_H}`} preserveAspectRatio="none" className="absolute inset-0 w-full h-full">
            <defs>
              {active.map(c => {
                const color = c.threat ? '#ef4444' : PROTO_COLOR[c.proto];
                const opacity = c.dying ? 1 - Math.min(1, (performance.now() - c.dying) / 500) : 1;
                return (
                  <marker key={`m-${c.id}`} id={`arr-${c.id}`}
                    viewBox="0 0 10 10" refX="9" refY="5"
                    markerWidth="7" markerHeight="7" orient="auto-start-reverse">
                    <path d="M 0 0 L 10 5 L 0 10 z" fill={color} opacity={opacity} />
                  </marker>
                );
              })}
            </defs>
            {active.map((c, i) => (
              <FlowArc key={c.id} conn={c} index={i} total={active.length} />
            ))}
          </svg>

          {!loading && connections.length === 0 && !error && (
            <div className="absolute inset-0 flex items-center justify-center text-slate-500 text-xs">
              Keine Flows im ±5-min-Fenster zwischen diesen Hosts.
            </div>
          )}
          {error && (
            <div className="absolute inset-0 flex items-center justify-center text-red-400 text-xs px-6 text-center">
              {error}
            </div>
          )}
        </div>

        {/* Footer */}
        <div
          className="flex items-center justify-between px-5 py-2.5 text-[10px] text-slate-400"
          style={{ borderTop: '1px solid rgba(148,163,184,0.08)', background: 'rgba(2,6,23,0.5)' }}
        >
          <div className="flex gap-3.5 flex-wrap items-center">
            <LegendDot color="#38bdf8" label="TCP"  />
            <LegendDot color="#fb923c" label="UDP"  />
            <LegendDot color="#a78bfa" label="ICMP" />
            <LegendDot color="#ef4444" label="Alert" />
            <span className="text-slate-600">→ Richtung = src → dst</span>
          </div>
          <button
            onClick={onClose}
            className="px-2.5 py-1 rounded border border-slate-600/30 text-slate-300 hover:border-cyan-500/50 hover:text-cyan-300 transition-colors text-[10px]"
          >
            Schließen
          </button>
        </div>
      </div>
    </div>
  );
}

function FlowArc({ conn, index, total }: { conn: ConnState; index: number; total: number }) {
  const now = performance.now();
  const age = (now - conn.born) / 500;
  const draw = Math.min(1, Math.max(0, age));
  const exit = conn.dying ? Math.max(0, 1 - Math.min(1, (now - conn.dying) / 500)) : 1;

  const slot = total === 1 ? 0 : index - (total - 1) / 2;
  const spread = Math.min(70, 260 / Math.max(1, total));
  const yOff = slot * spread;

  const fromLeft = conn.from === 'a';
  const sx = fromLeft ? A_X : B_X;
  const tx = fromLeft ? B_X : A_X;
  const sy = A_Y + yOff;
  const ty = B_Y + yOff;
  const lift = 26 * (Math.abs(slot) + 0.2) * (slot === 0 ? 0.6 : 1);
  const mx = (sx + tx) / 2;
  const my = sy - lift;

  const color = conn.threat ? '#ef4444' : PROTO_COLOR[conn.proto];
  const strokeW = conn.threat ? 2.0 : 1.3;
  const d = `M ${sx} ${sy} Q ${mx} ${my} ${tx} ${ty}`;

  let dasharray: string | undefined = conn.threat ? '6 4' : undefined;
  let dashoffset: number | undefined;
  if (draw < 1) {
    const approxLen = Math.hypot(tx - sx, ty - sy) + Math.abs(lift);
    dasharray = conn.threat ? '6 4' : `${approxLen}`;
    dashoffset = approxLen * (1 - draw);
  }

  const travel = ((now - conn.born) / (conn.proto === 'ICMP' ? 1600 : 1100)) % 1;
  const dotPositions = draw >= 1 && !conn.dying
    ? [travel, (travel + 0.5) % 1].map(t => ({
        x: (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * mx + t * t * tx,
        y: (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * my + t * t * ty,
      }))
    : [];

  const arrow = fromLeft ? '→' : '←';
  const portLabel = conn.port ? `:${conn.port}` : '';
  const labelText = `${conn.proto}${portLabel}`;
  const labelPkts = `${conn.packets.toLocaleString()} pkts · ${conn.flows} flow${conn.flows !== 1 ? 's' : ''}`;
  const lw = Math.max(90, labelText.length * 6.4 + 40);

  return (
    <g opacity={exit}>
      <path
        d={d}
        fill="none" stroke={color} strokeWidth={strokeW}
        strokeLinecap="round"
        strokeOpacity={conn.threat ? 0.95 : 0.75}
        markerEnd={`url(#arr-${conn.id})`}
        strokeDasharray={dasharray}
        strokeDashoffset={dashoffset}
      />

      {dotPositions.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r={conn.threat ? 3 : 2.2}
          fill={color} style={{ filter: `drop-shadow(0 0 5px ${color})` }} />
      ))}

      <g transform={`translate(${mx}, ${my + 4})`} opacity={draw}>
        <rect x={-lw / 2} y={-20} width={lw} height={36} rx={4}
          fill="rgba(11,18,32,0.92)" stroke={color}
          strokeOpacity={conn.threat ? 0.9 : 0.45}
          strokeWidth={conn.threat ? 1.2 : 0.8} />
        <text x={0} y={-6} textAnchor="middle"
          fontFamily="JetBrains Mono, monospace" fontSize="10" fontWeight="600" fill={color}>
          {arrow}  {labelText}
        </text>
        <text x={0} y={9} textAnchor="middle"
          fontFamily="JetBrains Mono, monospace" fontSize="9"
          fill={conn.threat ? '#fca5a5' : '#94a3b8'}>
          {labelPkts}
        </text>
      </g>
    </g>
  );
}

function HostCard({ side, host, isAlert }: { side: 'left' | 'right'; host: { ip: string; name: string; kind: string; role?: string }; isAlert: boolean }) {
  return (
    <div
      className="absolute top-1/2 w-[190px] p-3.5 rounded-lg z-10"
      style={{
        transform: 'translateY(-50%)',
        background: 'rgba(11,18,32,0.92)',
        border: `1px solid ${isAlert ? 'rgba(239,68,68,0.45)' : 'rgba(34,211,238,0.25)'}`,
        boxShadow: isAlert
          ? '0 0 30px rgba(239,68,68,0.22)'
          : '0 0 30px rgba(34,211,238,0.12)',
        fontFamily: 'JetBrains Mono, monospace',
        ...(side === 'left' ? { left: 22 } : { right: 22, textAlign: 'right' as const }),
      }}
    >
      <div>
        <span
          className="inline-block text-[9px] font-bold tracking-[1.5px] px-1.5 py-0.5 rounded-sm"
          style={{
            background: isAlert ? 'rgba(239,68,68,0.15)' : 'rgba(34,211,238,0.12)',
            color:      isAlert ? '#ef4444' : '#67e8f9',
          }}
        >
          {host.kind}
        </span>
      </div>
      <div className="mt-2 text-[13px] font-semibold text-slate-100 break-all">{host.ip}</div>
      <div className="mt-0.5 text-[10px] text-slate-400 break-all">{host.name}</div>
      {host.role && (
        <div
          className="mt-2.5 pt-2.5 text-[9px] uppercase tracking-[1px] text-slate-500"
          style={{ borderTop: '1px solid rgba(148,163,184,0.1)' }}
        >
          NET: <b className="font-semibold text-cyan-300">{host.role}</b>
        </div>
      )}
    </div>
  );
}

function MetaCell({ label, value, cyan }: { label: string; value: string; cyan?: boolean }) {
  return (
    <div className="pr-3.5" style={{ borderRight: '1px solid rgba(148,163,184,0.06)' }}>
      <div className="text-slate-500 text-[9px] uppercase tracking-[1.5px] mb-0.5">{label}</div>
      <div className="tabular-nums truncate" style={{ color: cyan ? '#67e8f9' : '#e2e8f0' }}>
        {value}
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span className="inline-flex items-center gap-1.5">
      <span className="w-2 h-2 rounded-full inline-block" style={{ background: color }} />
      {label}
    </span>
  );
}
