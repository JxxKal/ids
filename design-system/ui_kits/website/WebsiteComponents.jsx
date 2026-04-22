/* global React */
const { useState, useEffect, useRef } = React;

// ─── Logo wordmark ─────────────────────────────────────────
window.CyjanMark = function CyjanMark({ size = 28, showText = true }) {
  return (
    <div style={{ display:'flex', alignItems:'center', gap:10 }}>
      <img src="../../assets/logos/cyjan_logo_compact.svg"
           style={{ width:size, height:size, filter:'drop-shadow(0 0 12px rgba(14,165,233,0.4))' }} />
      {showText && (
        <div style={{ fontFamily:'Inter', fontWeight:700, letterSpacing:'0.24em',
                      color:'#e0f2fe', fontSize:14, textTransform:'uppercase' }}>
          CY<span style={{ color:'#38bdf8' }}>JAN</span>
        </div>
      )}
    </div>
  );
};

// ─── Top Nav ──────────────────────────────────────────────
window.TopNav = function TopNav({ onNav, active='home' }) {
  const items = [
    ['home','Home'], ['features','Capabilities'], ['architecture','Architecture'],
    ['quickstart','Quick Start'], ['opensource','Open Source'],
  ];
  return (
    <nav style={{
      position:'sticky', top:0, zIndex:50,
      background:'rgba(2,6,23,0.85)', backdropFilter:'blur(16px)',
      borderBottom:'1px solid rgba(14,165,233,0.15)',
      padding:'14px 40px', display:'flex', alignItems:'center', justifyContent:'space-between',
    }}>
      <window.CyjanMark />
      <div style={{ display:'flex', gap:32, alignItems:'center' }}>
        {items.map(([k,label]) => (
          <a key={k} onClick={() => onNav?.(k)} style={{
            cursor:'pointer', fontFamily:'Inter', fontSize:14, fontWeight:500,
            color: active===k ? '#38bdf8' : '#94a3b8',
            transition:'color 0.2s',
          }}>{label}</a>
        ))}
        <button style={{
          padding:'8px 18px', borderRadius:8,
          background:'linear-gradient(135deg,#0ea5e9,#0284c7)', color:'#fff',
          border:'none', fontFamily:'Inter', fontWeight:600, fontSize:13,
          boxShadow:'0 0 20px rgba(14,165,233,0.3)', cursor:'pointer',
        }}>View on GitHub →</button>
      </div>
    </nav>
  );
};

// ─── Alert Ticker ─────────────────────────────────────────
window.AlertTicker = function AlertTicker() {
  return (
    <div style={{
      position:'sticky', top:65, zIndex:40,
      background:'rgba(2,6,23,0.9)', backdropFilter:'blur(12px)',
      borderBottom:'1px solid rgba(14,165,233,0.08)',
      height:26, overflow:'hidden', display:'flex', alignItems:'center',
      fontFamily:'JetBrains Mono', fontSize:11, color:'#64748b',
    }}>
      <div style={{
        display:'flex', gap:40, whiteSpace:'nowrap',
        animation:'ticker 35s linear infinite', paddingLeft:'100%',
      }}>
        <span><span style={{ color:'#f87171' }}>● CRIT</span> ET·SCADA·2018927 · 10.42.0.118 → 10.42.7.3:502 · Modbus TCP</span>
        <span><span style={{ color:'#fdba74' }}>● MED </span> ML·Anomaly · host 10.42.0.12 · score 58</span>
        <span><span style={{ color:'#86efac' }}>● LOW </span> ET·Info·scan · 10.42.0.200 → broadcast</span>
        <span><span style={{ color:'#7dd3fc' }}>● LIVE</span> 312 alerts / last 1h · 87 hosts online</span>
      </div>
    </div>
  );
};

// ─── Feature card ─────────────────────────────────────────
window.FeatureCard = function FeatureCard({ icon, title, body }) {
  const [hover, setHover] = useState(false);
  return (
    <div onMouseEnter={()=>setHover(true)} onMouseLeave={()=>setHover(false)}
      style={{
        background:'rgba(15,23,42,0.80)', backdropFilter:'blur(8px)',
        border:`1px solid rgba(14,165,233,${hover?0.5:0.15})`,
        borderRadius:16, padding:24,
        boxShadow: hover
          ? '0 0 30px rgba(14,165,233,0.15)'
          : '0 0 20px rgba(14,165,233,0.05)',
        transition:'all 0.25s cubic-bezier(0.4,0,0.2,1)',
        display:'flex', flexDirection:'column', gap:12,
      }}>
      <div style={{
        width:48, height:48, borderRadius:12,
        background:'linear-gradient(135deg, rgba(14,165,233,0.15), rgba(56,189,248,0.05))',
        border:'1px solid rgba(14,165,233,0.30)',
        display:'grid', placeItems:'center', color:'#38bdf8',
      }}>{icon}</div>
      <h3 style={{ fontFamily:'Inter', fontWeight:700, fontSize:18, color:'#e0f2fe', letterSpacing:'-0.01em' }}>{title}</h3>
      <p style={{ fontFamily:'Inter', fontSize:14, color:'#94a3b8', lineHeight:1.6 }}>{body}</p>
    </div>
  );
};

// ─── CTA button ───────────────────────────────────────────
window.CtaButton = function CtaButton({ children, variant='primary', icon, onClick }) {
  const primary = {
    background:'linear-gradient(135deg,#0ea5e9,#0284c7)', color:'#fff',
    border:'1px solid transparent', boxShadow:'0 0 30px rgba(14,165,233,0.30)',
  };
  const ghost = {
    background:'transparent', color:'#bae6fd', border:'1px solid rgba(3,105,161,0.5)',
  };
  return (
    <button onClick={onClick} style={{
      padding:'12px 24px', borderRadius:12, cursor:'pointer',
      fontFamily:'Inter', fontWeight:600, fontSize:14,
      display:'inline-flex', alignItems:'center', gap:8,
      transition:'all 0.25s', ...(variant==='primary'?primary:ghost),
    }}>{children} {icon}</button>
  );
};

// ─── Section wrapper ──────────────────────────────────────
window.Section = function Section({ id, eyebrow, title, subtitle, children, hex }) {
  return (
    <section id={id} style={{
      padding:'96px 40px', position:'relative',
      backgroundImage: hex
        ? "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='56' height='100'%3E%3Cpath d='M28 66L0 50V16L28 0l28 16v34L28 66zm0-2l26-15V17L28 2 2 17v32l26 15z' fill='none' stroke='%230ea5e9' stroke-width='0.3' opacity='0.12'/%3E%3C/svg%3E\")"
        : 'none',
    }}>
      <div style={{ maxWidth:1280, margin:'0 auto' }}>
        {eyebrow && (
          <div style={{
            fontFamily:'Inter', fontSize:12, fontWeight:500, color:'#38bdf8',
            letterSpacing:'0.24em', textTransform:'uppercase', marginBottom:16,
          }}>{eyebrow}</div>
        )}
        {title && (
          <h2 style={{
            fontFamily:'Inter', fontWeight:900, fontSize:48, lineHeight:1.1,
            letterSpacing:'-0.02em', marginBottom:16,
            background:'linear-gradient(135deg,#e0f2fe 0%,#7dd3fc 50%,#0ea5e9 100%)',
            WebkitBackgroundClip:'text', backgroundClip:'text', color:'transparent',
          }}>{title}</h2>
        )}
        {subtitle && (
          <p style={{
            fontFamily:'Inter', fontSize:18, color:'#94a3b8', lineHeight:1.6,
            maxWidth:720, marginBottom:48,
          }}>{subtitle}</p>
        )}
        {children}
      </div>
    </section>
  );
};

Object.assign(window, { CyjanMark: window.CyjanMark, TopNav: window.TopNav, AlertTicker: window.AlertTicker,
  FeatureCard: window.FeatureCard, CtaButton: window.CtaButton, Section: window.Section });
