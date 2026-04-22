// AlertFlowPopup.tsx — React + TypeScript
// Drop into frontend/src/components/ and use from the alert list:
//
//   import { AlertFlowPopup, Connection, Host } from './AlertFlowPopup';
//
//   <AlertFlowPopup
//     open={selectedAlert !== null}
//     onClose={() => setSelectedAlert(null)}
//     alert={selectedAlert}
//     hostA={{ ip: '10.10.20.14', name: 'PLC·S7-1500', kind: 'PLC', role: 'Control' }}
//     hostB={{ ip: '10.10.20.41', name: 'HMI·WinCC',   kind: 'HMI', role: 'Operator' }}
//     alertHost="a"
//     connections={connections}   // live list from your store / WebSocket
//   />
//
// The component is declarative: feed it the full list of currently-active
// connections; it diff-renders entrance (0.5 s stroke-draw), travelling packet
// dots, exit fade. For imperative feeds, use a small reducer in the parent.

import React, { useEffect, useMemo, useRef, useState } from 'react';

// ---- Public types ----------------------------------------------------------

export type Proto = 'TCP' | 'UDP' | 'ICMP';

export interface Host {
  ip: string;
  name: string;
  /** Short role pill: PLC / HMI / SCADA / RTU / ENG / GW / WAN / ??? */
  kind: string;
  /** Long-form role shown under the divider */
  role?: string;
}

export interface Connection {
  id: string;
  from: 'a' | 'b';
  to:   'a' | 'b';
  proto: Proto;
  port: number;
  packets: number;
  threat?: boolean;
  /** Optional free-text tag shown next to packet count, e.g. 'Modbus' */
  label?: string;
}

export interface AlertMeta {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  ruleId: string;
  ruleName: string;
  firstSeen: string;
  session?: string;
  sensor?: string;
}

export interface AlertFlowPopupProps {
  open: boolean;
  onClose: () => void;
  alert: AlertMeta | null;
  hostA: Host;
  hostB: Host;
  alertHost?: 'a' | 'b' | null;
  connections: Connection[];
  /** Optional: called when user clicks "Mark as threat" */
  onMarkThreat?: () => void;
}

// ---- Internals --------------------------------------------------------------

const PROTO_COLOR: Record<Proto, string> = {
  TCP:  '#38bdf8',
  UDP:  '#fb923c',
  ICMP: '#a78bfa',
};

interface ConnState extends Connection {
  born: number;
  dying: number | null;
}

const VB_W = 1000;
const VB_H = 380;
const A_X = 222, A_Y = VB_H / 2;
const B_X = 778, B_Y = VB_H / 2;

// ---- Component --------------------------------------------------------------

export function AlertFlowPopup(props: AlertFlowPopupProps) {
  const { open, onClose, alert, hostA, hostB, alertHost, connections, onMarkThreat } = props;

  // track incoming connections as a stateful map so we can animate entry/exit
  const stateRef = useRef<Map<string, ConnState>>(new Map());
  const [, force] = useState(0);
  const frameRef = useRef<number | null>(null);

  // diff props.connections against our internal state
  useEffect(() => {
    if (!open) return;
    const now = performance.now();
    const incoming = new Map(connections.map(c => [c.id, c]));
    // mark removed as dying
    for (const [id, c] of stateRef.current) {
      if (!incoming.has(id) && !c.dying) c.dying = now;
    }
    // add / update
    for (const c of connections) {
      const existing = stateRef.current.get(c.id);
      if (existing) {
        Object.assign(existing, c);
        existing.dying = null;
      } else {
        stateRef.current.set(c.id, { ...c, born: now, dying: null });
      }
    }
  }, [connections, open]);

  // animation loop — drives packet dots + fade timing
  useEffect(() => {
    if (!open) return;
    const tick = () => {
      const now = performance.now();
      // cull fully-faded
      for (const [id, c] of stateRef.current) {
        if (c.dying && now - c.dying > 500) stateRef.current.delete(id);
      }
      force(f => (f + 1) % 1e9);
      frameRef.current = requestAnimationFrame(tick);
    };
    frameRef.current = requestAnimationFrame(tick);
    return () => {
      if (frameRef.current != null) cancelAnimationFrame(frameRef.current);
    };
  }, [open]);

  // reset on close
  useEffect(() => {
    if (!open) stateRef.current.clear();
  }, [open]);

  // escape to close
  useEffect(() => {
    if (!open) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === 'Escape') onClose(); };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  const active = useMemo(() => {
    const now = performance.now();
    return [...stateRef.current.values()]
      .filter(c => !c.dying || now - c.dying < 500);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stateRef.current.size, connections]);

  if (!open || !alert) return null;

  const anyThreat = active.some(c => c.threat && !c.dying);

  return (
    <div
      style={styles.backdrop}
      onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div style={styles.modal} role="dialog" aria-modal="true">

        {/* Header */}
        <div style={styles.head}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <SeverityPill severity={alert.severity} />
            <h2 style={styles.title}>
              <span style={{ color: '#22d3ee', marginRight: 8 }}>{alert.ruleId}</span>
              {alert.ruleName}
            </h2>
          </div>
          <button style={styles.closeBtn} onClick={onClose}>ESC · ✕</button>
        </div>

        {/* Meta grid */}
        <div style={styles.meta}>
          <MetaCell label="Alert ID"   value={alert.id}        cyan />
          <MetaCell label="First seen" value={alert.firstSeen} />
          <MetaCell label="Session"    value={alert.session ?? '—'} />
          <MetaCell label="IDS sensor" value={alert.sensor ?? '—'} />
        </div>

        {/* Stage */}
        <div style={styles.stage}>
          <div style={{ ...styles.liveChip, ...(anyThreat ? styles.liveChipAlert : null) }}>
            <span style={{
              ...styles.liveDot,
              background: anyThreat ? '#ef4444' : '#22d3ee',
              boxShadow: `0 0 8px ${anyThreat ? '#ef4444' : '#22d3ee'}`,
            }} />
            LIVE · {active.filter(c => !c.dying).length} CONNS
          </div>

          <HostCard side="left"  host={hostA} alert={alertHost === 'a'} />
          <HostCard side="right" host={hostB} alert={alertHost === 'b'} />

          <svg viewBox={`0 0 ${VB_W} ${VB_H}`} preserveAspectRatio="none" style={styles.svg}>
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
        </div>

        {/* Footer */}
        <div style={styles.foot}>
          <div style={styles.legend}>
            <LegendDot color="#38bdf8" label="TCP" />
            <LegendDot color="#fb923c" label="UDP" />
            <LegendDot color="#a78bfa" label="ICMP" />
            <LegendDot color="#ef4444" label="Alert" />
            <span style={{ color: '#64748b' }}>→ Richtung = Aufbau (SYN)</span>
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            <button style={styles.footBtn} onClick={onClose}>Close</button>
            {onMarkThreat && (
              <button style={{ ...styles.footBtn, ...styles.footBtnPrimary }} onClick={onMarkThreat}>
                Mark as threat
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// ---- Subcomponents ----------------------------------------------------------

function FlowArc({ conn, index, total }: { conn: ConnState; index: number; total: number }) {
  const now = performance.now();
  const age = (now - conn.born) / 500;
  const draw = Math.min(1, age);
  const exit = conn.dying ? 1 - Math.min(1, (now - conn.dying) / 500) : 1;

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

  // entrance dash-draw
  let dasharray: string | undefined = conn.threat ? '6 4' : undefined;
  let dashoffset: number | undefined;
  if (draw < 1) {
    const approxLen = Math.hypot(tx - sx, ty - sy) + Math.abs(lift);
    dasharray = conn.threat ? '6 4' : `${approxLen}`;
    dashoffset = approxLen * (1 - draw);
  }

  // travelling packet dots
  const travel = ((now - conn.born) / (conn.proto === 'ICMP' ? 1600 : 1100)) % 1;
  const dotPositions = draw >= 1 && !conn.dying
    ? [travel, (travel + 0.5) % 1].map(t => ({
        x: (1 - t) * (1 - t) * sx + 2 * (1 - t) * t * mx + t * t * tx,
        y: (1 - t) * (1 - t) * sy + 2 * (1 - t) * t * my + t * t * ty,
      }))
    : [];

  const arrow = fromLeft ? '→' : '←';
  const labelText = `${conn.proto} :${conn.port}`;
  const labelPkts = `${conn.packets.toLocaleString()} pkts`;
  const lw = Math.max(70, labelText.length * 6.4 + 40);

  return (
    <g opacity={exit}>
      <path d={d}
            fill="none" stroke={color} strokeWidth={strokeW}
            strokeLinecap="round"
            strokeOpacity={conn.threat ? 0.95 : 0.75}
            markerEnd={`url(#arr-${conn.id})`}
            strokeDasharray={dasharray}
            strokeDashoffset={dashoffset} />

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
          {labelPkts}{conn.label ? ` · ${conn.label}` : ''}
        </text>
      </g>
    </g>
  );
}

function HostCard({ side, host, alert }: { side: 'left' | 'right'; host: Host; alert?: boolean }) {
  const base: React.CSSProperties = {
    position: 'absolute', top: '50%', transform: 'translateY(-50%)',
    width: 190, padding: 14, borderRadius: 8,
    background: 'rgba(11,18,32,0.92)',
    border: `1px solid ${alert ? 'rgba(239,68,68,0.45)' : 'rgba(34,211,238,0.25)'}`,
    boxShadow: alert
      ? '0 0 30px rgba(239,68,68,0.22)'
      : '0 0 30px rgba(34,211,238,0.12)',
    fontFamily: 'JetBrains Mono, monospace',
    zIndex: 3,
    ...(side === 'left' ? { left: 22 } : { right: 22, textAlign: 'right' as const }),
  };
  const kindStyle: React.CSSProperties = {
    display: 'inline-block', fontSize: 9, fontWeight: 700, letterSpacing: 1.5,
    padding: '2px 6px', borderRadius: 3,
    background: alert ? 'rgba(239,68,68,0.15)' : 'rgba(34,211,238,0.12)',
    color: alert ? '#ef4444' : '#67e8f9',
  };
  return (
    <div style={base}>
      <div><span style={kindStyle}>{host.kind}</span></div>
      <div style={{ marginTop: 8, fontSize: 13, fontWeight: 600, color: '#f1f5f9' }}>{host.ip}</div>
      <div style={{ marginTop: 2, fontSize: 10, color: '#94a3b8' }}>{host.name}</div>
      {host.role && (
        <div style={{
          marginTop: 10, paddingTop: 10,
          borderTop: '1px solid rgba(148,163,184,0.1)',
          fontSize: 9, letterSpacing: 1, textTransform: 'uppercase', color: '#64748b',
        }}>
          ROLE: <b style={{ color: '#22d3ee', fontWeight: 600 }}>{host.role}</b>
        </div>
      )}
    </div>
  );
}

function HostIcon({ kind }: { kind: string }) {
  const k = kind.toUpperCase();
  const common = {
    width: 20, height: 20, viewBox: '0 0 24 24', fill: 'none',
    stroke: 'currentColor', strokeWidth: 1.6,
    strokeLinecap: 'round' as const, strokeLinejoin: 'round' as const,
  };
  if (k === 'HMI') return (
    <svg {...common}><rect x="3" y="3" width="18" height="13" rx="1"/><path d="M8 21h8M12 16v5"/></svg>
  );
  if (k === 'PLC' || k === 'RTU') return (
    <svg {...common}><rect x="3" y="4" width="18" height="16" rx="1"/><path d="M7 8h10M7 12h6M7 16h10"/></svg>
  );
  if (k === 'SCADA') return (
    <svg {...common}><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a15 15 0 0 1 0 18M12 3a15 15 0 0 0 0 18"/></svg>
  );
  if (k === 'GW' || k === 'WAN' || k === 'NET') return (
    <svg {...common}><path d="M4 7h16M4 12h16M4 17h16"/><circle cx="7" cy="7" r="0.8" fill="currentColor"/><circle cx="17" cy="12" r="0.8" fill="currentColor"/></svg>
  );
  return <svg {...common}><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>;
}

function SeverityPill({ severity }: { severity: AlertMeta['severity'] }) {
  const colors: Record<AlertMeta['severity'], { bg: string; fg: string }> = {
    critical: { bg: 'rgba(239,68,68,0.15)',  fg: '#ef4444' },
    high:     { bg: 'rgba(249,115,22,0.15)', fg: '#f97316' },
    medium:   { bg: 'rgba(234,179,8,0.15)',  fg: '#eab308' },
    low:      { bg: 'rgba(34,197,94,0.15)',  fg: '#22c55e' },
    info:     { bg: 'rgba(56,189,248,0.15)', fg: '#38bdf8' },
  };
  const c = colors[severity];
  return (
    <span style={{
      fontSize: 9, fontWeight: 700, padding: '3px 7px',
      borderRadius: 3, letterSpacing: 1.5,
      background: c.bg, color: c.fg,
    }}>
      {severity.toUpperCase()}
    </span>
  );
}

function MetaCell({ label, value, cyan }: { label: string; value: string; cyan?: boolean }) {
  return (
    <div style={{ borderRight: '1px solid rgba(148,163,184,0.06)', padding: '0 14px 0 0' }}>
      <div style={{ color: '#94a3b8', fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase', marginBottom: 2 }}>
        {label}
      </div>
      <div style={{ color: cyan ? '#67e8f9' : '#e2e8f0', fontVariantNumeric: 'tabular-nums' }}>
        {value}
      </div>
    </div>
  );
}

function LegendDot({ color, label }: { color: string; label: string }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
      <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
      {label}
    </span>
  );
}

// ---- Styles -----------------------------------------------------------------

const styles: Record<string, React.CSSProperties> = {
  backdrop: {
    position: 'fixed', inset: 0,
    background: 'rgba(2,6,23,0.82)', backdropFilter: 'blur(4px)',
    zIndex: 20,
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  },
  modal: {
    width: 'min(960px, 96vw)', maxHeight: '90vh',
    background: 'linear-gradient(180deg, #0b1220 0%, #020617 100%)',
    border: '1px solid rgba(34,211,238,0.28)', borderRadius: 10,
    boxShadow: '0 0 0 1px rgba(34,211,238,0.08), 0 20px 60px rgba(2,6,23,0.7), 0 0 80px rgba(34,211,238,0.08)',
    overflow: 'hidden',
    display: 'flex', flexDirection: 'column',
    fontFamily: 'JetBrains Mono, ui-monospace, monospace',
    color: '#e2e8f0',
  },
  head: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '14px 18px',
    borderBottom: '1px solid rgba(34,211,238,0.15)',
    background: 'rgba(15,26,45,0.6)',
  },
  title: {
    margin: 0, fontFamily: 'JetBrains Mono, monospace',
    fontWeight: 600, fontSize: 13, color: '#e2e8f0', letterSpacing: 0.5,
  },
  closeBtn: {
    background: 'transparent', border: '1px solid rgba(148,163,184,0.2)',
    color: '#cbd5e1', fontFamily: 'JetBrains Mono, monospace',
    fontSize: 11, padding: '4px 10px', borderRadius: 4, cursor: 'pointer',
  },
  meta: {
    display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)',
    padding: '10px 18px',
    borderBottom: '1px solid rgba(148,163,184,0.08)',
    background: 'rgba(2,6,23,0.4)', fontSize: 10,
  },
  stage: {
    position: 'relative', height: 380,
    background: 'radial-gradient(ellipse at center, rgba(14,165,233,0.07), transparent 70%), linear-gradient(180deg, rgba(11,18,32,0.5), rgba(2,6,23,0.7))',
    overflow: 'hidden',
  },
  svg: { position: 'absolute', inset: 0, width: '100%', height: '100%' },
  liveChip: {
    position: 'absolute', top: 14, right: 18, zIndex: 4,
    fontSize: 9, letterSpacing: 1.5, textTransform: 'uppercase',
    color: '#67e8f9',
    display: 'flex', alignItems: 'center', gap: 6,
    padding: '4px 8px',
    border: '1px solid rgba(34,211,238,0.3)', borderRadius: 3,
    background: 'rgba(11,18,32,0.7)',
  },
  liveChipAlert: { borderColor: 'rgba(239,68,68,0.4)', color: '#fca5a5' },
  liveDot: {
    width: 6, height: 6, borderRadius: '50%',
    animation: 'cyjan-pulse 1.4s ease-in-out infinite',
  },
  foot: {
    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
    padding: '10px 18px',
    borderTop: '1px solid rgba(148,163,184,0.08)',
    background: 'rgba(2,6,23,0.5)',
    fontSize: 10, color: '#94a3b8',
  },
  legend: { display: 'flex', gap: 14, flexWrap: 'wrap', alignItems: 'center' },
  footBtn: {
    background: 'transparent', border: '1px solid rgba(148,163,184,0.22)',
    color: '#cbd5e1', fontFamily: 'JetBrains Mono, monospace',
    fontSize: 10, padding: '5px 10px', borderRadius: 4, cursor: 'pointer',
    letterSpacing: 0.5,
  },
  footBtnPrimary: {
    borderColor: '#0891b2', background: 'rgba(14,165,233,0.1)', color: '#67e8f9',
  },
};

// Inject the pulse keyframes once
if (typeof document !== 'undefined' && !document.getElementById('cyjan-flow-keyframes')) {
  const s = document.createElement('style');
  s.id = 'cyjan-flow-keyframes';
  s.textContent = `@keyframes cyjan-pulse { 0%,100%{opacity:1;transform:scale(1)} 50%{opacity:0.4;transform:scale(1.3)} }`;
  document.head.appendChild(s);
}
