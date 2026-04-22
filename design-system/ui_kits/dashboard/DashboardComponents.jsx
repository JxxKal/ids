/* global React */
const { useState, useEffect } = React;

// ─── Sidebar ──────────────────────────────────────────────
window.DashSidebar = function DashSidebar({ active, onNav }) {
  const items = [
    ['dashboard','Dashboard', <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/></svg>],
    ['network','Netzwerk',    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="9"/><path d="M3 12h18M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18"/></svg>],
    ['hosts','Hosts',         <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/><circle cx="7" cy="7" r="0.9" fill="currentColor"/><circle cx="7" cy="17" r="0.9" fill="currentColor"/></svg>],
    ['scenarios','Szenarien', <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10 2v6l-4 8a4 4 0 0 0 4 6h4a4 4 0 0 0 4-6l-4-8V2M8 2h8"/></svg>],
    ['settings','Einstellungen', <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="3"/><path d="M19 12l2 1-2 3-3-1-2 2-1-3 2-3 3 1zM5 12l-2 1 2 3 3-1 2 2 1-3-2-3-3 1z"/></svg>],
  ];
  return (
    <aside style={{ width:210, background:'#0f172a', borderRight:'1px solid #172033', padding:'16px 10px', display:'flex', flexDirection:'column', gap:2 }}>
      <div style={{ display:'flex', alignItems:'center', gap:10, padding:'6px 10px 16px', borderBottom:'1px solid #172033', marginBottom:10 }}>
        <img src="../../assets/logos/cyjan_logo_compact.svg" style={{ width:24, height:24, filter:'drop-shadow(0 0 10px rgba(14,165,233,0.4))' }}/>
        <div style={{ fontFamily:'Inter', fontWeight:700, letterSpacing:'0.24em', fontSize:13, color:'#e0f2fe' }}>
          CY<span style={{ color:'#38bdf8' }}>JAN</span>
        </div>
      </div>
      {items.map(([k, l, ic]) => (
        <div key={k} onClick={() => onNav(k)} style={{
          display:'flex', alignItems:'center', gap:10, padding:'8px 10px',
          fontFamily:'Inter', fontSize:13, cursor:'pointer', borderRadius:4,
          color: active===k ? '#7dd3fc' : '#94a3b8',
          background: active===k ? 'rgba(14,165,233,0.12)' : 'transparent',
          borderLeft: active===k ? '2px solid #0ea5e9' : '2px solid transparent',
        }}>
          <span style={{ width:16, height:16, display:'grid', placeItems:'center' }}>{ic}</span>{l}
        </div>
      ))}
      <div style={{ flex:1 }}/>
      <div style={{ padding:'8px 10px', fontFamily:'JetBrains Mono', fontSize:10, color:'#475569', borderTop:'1px solid #172033', marginTop:12 }}>
        admin@cyjan-01 · v1.0
      </div>
    </aside>
  );
};

// ─── Top bar with live KPIs ──────────────────────────────
window.DashTopBar = function DashTopBar({ title, kpis }) {
  return (
    <div style={{ padding:'12px 20px', borderBottom:'1px solid #172033', background:'#0b1120', display:'flex', alignItems:'center', justifyContent:'space-between' }}>
      <div style={{ display:'flex', alignItems:'center', gap:20 }}>
        <h1 style={{ fontFamily:'Inter', fontWeight:600, fontSize:16, color:'#e0f2fe' }}>{title}</h1>
        <span style={{ display:'inline-flex', alignItems:'center', gap:6, fontFamily:'JetBrains Mono', fontSize:11, color:'#7dd3fc', padding:'2px 10px', borderRadius:999, border:'1px solid rgba(14,165,233,0.4)', background:'rgba(14,165,233,0.08)' }}>
          <span style={{ width:6, height:6, background:'#22c55e', borderRadius:999, animation:'pulse 2s ease-in-out infinite', boxShadow:'0 0 6px #22c55e' }}/>Live
        </span>
      </div>
      <div style={{ display:'flex', gap:20 }}>
        {kpis.map((k,i) => (
          <div key={i} style={{ textAlign:'right', fontFamily:'JetBrains Mono' }}>
            <div style={{ fontSize:10, color:'#64748b', letterSpacing:'0.12em', textTransform:'uppercase' }}>{k.label}</div>
            <div style={{ fontSize:14, fontWeight:600, color:k.color || '#e0f2fe' }}>{k.value}</div>
          </div>
        ))}
      </div>
    </div>
  );
};

// ─── Severity badge ──────────────────────────────────────
window.SevBadge = function SevBadge({ level }) {
  const m = {
    critical: { bg:'rgba(127,29,29,0.70)', fg:'#fecaca', br:'rgba(220,38,38,0.60)' },
    high:     { bg:'rgba(127,29,29,0.50)', fg:'#fca5a5', br:'rgba(185,28,28,0.50)' },
    medium:   { bg:'rgba(124,45,18,0.60)', fg:'#fdba74', br:'rgba(194,65,12,0.50)' },
    low:      { bg:'rgba(22,101,52,0.50)', fg:'#86efac', br:'rgba(21,128,61,0.50)' },
  }[level] || { bg:'#1e293b', fg:'#94a3b8', br:'#334155' };
  return (
    <span style={{ padding:'2px 8px', borderRadius:4, background:m.bg, color:m.fg, border:`1px solid ${m.br}`, fontFamily:'JetBrains Mono', fontSize:10, letterSpacing:'0.06em', textTransform:'uppercase', fontWeight:500 }}>{level}</span>
  );
};

// ─── Alert Table ─────────────────────────────────────────
window.AlertTable = function AlertTable({ rows }) {
  const levelFor = s => s >= 75 ? 'critical' : s >= 50 ? 'high' : s >= 25 ? 'medium' : 'low';
  const colorFor = s => s >= 75 ? '#ef4444' : s >= 50 ? '#dc2626' : s >= 25 ? '#f97316' : '#22c55e';
  const scoreColor = s => s >= 75 ? '#f87171' : s >= 50 ? '#fca5a5' : s >= 25 ? '#fdba74' : '#86efac';
  return (
    <div style={{ border:'1px solid #172033', borderRadius:6, background:'#0f172a', overflow:'hidden' }}>
      <div style={{ display:'grid', gridTemplateColumns:'90px 60px 90px 1fr 160px 90px 80px', gap:10, padding:'8px 14px', background:'#0b1120', borderBottom:'1px solid #172033', fontFamily:'JetBrains Mono', fontSize:9, color:'#475569', letterSpacing:'0.12em', textTransform:'uppercase' }}>
        <span>time</span><span>score</span><span>severity</span><span>rule · src → dst</span><span>tags</span><span>source</span><span>actions</span>
      </div>
      {rows.map((r, i) => (
        <div key={i} style={{
          display:'grid', gridTemplateColumns:'90px 60px 90px 1fr 160px 90px 80px', gap:10,
          padding:'10px 14px', alignItems:'center',
          fontFamily:'JetBrains Mono', fontSize:11, color:'#e2e8f0',
          borderBottom:'1px solid #172033',
          borderLeft:`3px solid ${colorFor(r.score)}`,
          background: r.score >= 75 ? 'rgba(127,29,29,0.15)' : r.score >= 50 ? 'rgba(127,29,29,0.08)' : 'transparent',
        }}>
          <span style={{ color:'#64748b' }}>{r.time}</span>
          <span style={{ color:scoreColor(r.score), fontWeight:700 }}>{r.score}</span>
          <span><SevBadge level={levelFor(r.score)}/></span>
          <span><span style={{ color:'#e2e8f0' }}>{r.rule}</span> · <span style={{ color:'#7dd3fc' }}>{r.src}</span> → <span style={{ color:'#7dd3fc' }}>{r.dst}</span></span>
          <span style={{ display:'flex', gap:4, flexWrap:'wrap' }}>
            {r.tags.map(t => (
              <span key={t} style={{ padding:'1px 7px', borderRadius:999, background:'rgba(249,115,22,0.15)', color:'#fb923c', fontSize:10, border:'1px solid rgba(249,115,22,0.4)' }}>{t}</span>
            ))}
          </span>
          <span style={{ color: r.source === 'IRMA' ? '#c4b5fd' : '#94a3b8' }}>{r.source}</span>
          <span style={{ display:'flex', gap:8, color:'#64748b', fontSize:11 }}>
            <span style={{ cursor:'pointer' }}>↓</span>
            <span style={{ cursor:'pointer', color:'#86efac' }}>✓</span>
            <span style={{ cursor:'pointer', color:'#fca5a5' }}>⚠</span>
          </span>
        </div>
      ))}
    </div>
  );
};

// ─── Threat Gauge ────────────────────────────────────────
window.ThreatGauge = function ThreatGauge({ value = 74 }) {
  const c = 2 * Math.PI * 54;
  const off = c - (value / 100) * c;
  const color = value >= 75 ? '#ef4444' : value >= 50 ? '#f97316' : value >= 25 ? '#eab308' : '#22c55e';
  return (
    <div style={{ background:'#0f172a', border:'1px solid #172033', borderRadius:8, padding:16, display:'flex', gap:16, alignItems:'center' }}>
      <svg width="120" height="120" viewBox="0 0 120 120">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#172033" strokeWidth="8"/>
        <circle cx="60" cy="60" r="54" fill="none" stroke={color} strokeWidth="8"
                strokeDasharray={c} strokeDashoffset={off} strokeLinecap="round"
                transform="rotate(-90 60 60)"
                style={{ transition:'stroke-dashoffset 0.6s ease', filter:`drop-shadow(0 0 6px ${color})` }}/>
        <text x="60" y="58" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="26" fontWeight="700" fill={color}>{value}</text>
        <text x="60" y="76" textAnchor="middle" fontFamily="JetBrains Mono" fontSize="9" fill="#64748b" letterSpacing="0.16em">THREAT</text>
      </svg>
      <div>
        <div style={{ fontFamily:'Inter', fontSize:11, color:'#64748b', letterSpacing:'0.14em', textTransform:'uppercase', marginBottom:4 }}>Overall threat level</div>
        <div style={{ fontFamily:'Inter', fontSize:14, fontWeight:600, color:'#e0f2fe', marginBottom:6 }}>{value >= 75 ? 'Kritisch' : value >= 50 ? 'Erhöht' : value >= 25 ? 'Moderat' : 'Normal'}</div>
        <div style={{ fontFamily:'JetBrains Mono', fontSize:10, color:'#86efac' }}>▲ +18 vs last hour</div>
        <div style={{ fontFamily:'JetBrains Mono', fontSize:10, color:'#64748b', marginTop:2 }}>top: ET·SCADA·2018927</div>
      </div>
    </div>
  );
};

// ─── Host row ───────────────────────────────────────────
window.HostRow = function HostRow({ host }) {
  return (
    <div style={{
      display:'grid', gridTemplateColumns:'140px 120px 1fr 120px 90px', gap:12,
      padding:'10px 14px', fontFamily:'JetBrains Mono', fontSize:11,
      borderBottom:'1px solid #172033', alignItems:'center',
    }}>
      <span style={{ color:'#7dd3fc' }}>{host.ip}</span>
      <span style={{ color:'#e0f2fe' }}>{host.name}</span>
      <span style={{ display:'flex', gap:4 }}>
        {host.protocols.map(p => (
          <span key={p} style={{ padding:'1px 7px', borderRadius:999, background:'rgba(249,115,22,0.12)', color:'#fb923c', fontSize:10, border:'1px solid rgba(249,115,22,0.3)' }}>{p}</span>
        ))}
      </span>
      <span style={{ color:'#94a3b8' }}>
        <span style={{ display:'inline-block', width:6, height:6, borderRadius:999, background: host.online ? '#22c55e' : '#ef4444', marginRight:6, boxShadow: host.online ? '0 0 6px #22c55e' : 'none' }}/>
        {host.online ? 'online' : 'offline'}
      </span>
      <span style={{ color: host.score >= 50 ? '#fca5a5' : '#94a3b8', fontWeight: host.score >= 50 ? 700 : 400 }}>{host.score}</span>
    </div>
  );
};

Object.assign(window, {
  DashSidebar: window.DashSidebar, DashTopBar: window.DashTopBar,
  SevBadge: window.SevBadge, AlertTable: window.AlertTable,
  ThreatGauge: window.ThreatGauge, HostRow: window.HostRow,
});
