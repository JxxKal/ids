import { useEffect, useRef } from 'react';

const LINES = [
  '> init cyjan.sentry --target=thorsten',
  '> scanning ot-network ............. 6 hosts',
  '> threat.engine = online',
  '> greeting.package = "Moin, Thorsten!"',
  '> status: all systems nominal ✓',
];

export function FuerThorsten() {
  const typingRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const el = typingRef.current;
    if (!el) return;
    const cursor = '<span class="fth-cursor"></span>';
    let li = 0, ci = 0, deleting = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    let cancelled = false;

    const tick = () => {
      if (cancelled || !typingRef.current) return;
      const line = LINES[li];
      if (!deleting) {
        ci++;
        typingRef.current.innerHTML = line.slice(0, ci) + cursor;
        if (ci >= line.length) { deleting = true; timer = setTimeout(tick, 2200); return; }
        timer = setTimeout(tick, 36 + Math.random() * 30);
      } else {
        ci -= 2;
        if (ci < 0) ci = 0;
        typingRef.current.innerHTML = line.slice(0, ci) + cursor;
        if (ci === 0) { deleting = false; li = (li + 1) % LINES.length; timer = setTimeout(tick, 350); return; }
        timer = setTimeout(tick, 14);
      }
    };
    timer = setTimeout(tick, 2200);
    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, []);

  return (
    <div className="fth-root">
      <style>{CSS}</style>

      <div className="fth-hexbg" aria-hidden="true" />

      <div className="fth-hud fth-tl"><span className="fth-dot" /> CYJAN · SENTRY MODE · LIVE</div>
      <div className="fth-hud fth-tr">SESSION 0xCY-THR-01</div>
      <div className="fth-hud fth-bl">NODE/DE-BREMEN · OT-SEGMENT 04</div>
      <div className="fth-hud fth-br">TRUST · DETECT · PROTECT</div>

      <div className="fth-stage">
        <div className="fth-sweep-line" />

        <div className="fth-globe-wrap">
          <svg className="fth-globe" viewBox="0 0 680 680" aria-hidden="true">
            <defs>
              <radialGradient id="fth-gBg" cx="50%" cy="50%" r="50%">
                <stop offset="0%"   stopColor="rgba(14,165,233,0.18)" />
                <stop offset="70%"  stopColor="rgba(14,165,233,0.05)" />
                <stop offset="100%" stopColor="rgba(2,6,23,0)" />
              </radialGradient>
              <filter id="fth-glow">
                <feGaussianBlur stdDeviation="3" result="b" />
                <feMerge><feMergeNode in="b" /><feMergeNode in="SourceGraphic" /></feMerge>
              </filter>
            </defs>

            <circle cx="340" cy="340" r="310" fill="url(#fth-gBg)" stroke="rgba(34,211,238,.25)" strokeWidth="1" />

            <g className="fth-rot" transformOrigin="340 340">
              <g fill="none" stroke="rgba(56,189,248,.22)" strokeWidth=".8">
                <ellipse cx="340" cy="340" rx="280" ry="35" />
                <ellipse cx="340" cy="340" rx="260" ry="90" />
                <ellipse cx="340" cy="340" rx="230" ry="150" />
                <ellipse cx="340" cy="340" rx="190" ry="210" />
                <ellipse cx="340" cy="340" rx="120" ry="260" />
              </g>
              <g fill="none" stroke="rgba(56,189,248,.16)" strokeWidth=".6">
                <ellipse cx="340" cy="340" rx="45"  ry="280" />
                <ellipse cx="340" cy="340" rx="110" ry="280" />
                <ellipse cx="340" cy="340" rx="180" ry="280" />
                <ellipse cx="340" cy="340" rx="240" ry="280" />
                <ellipse cx="340" cy="340" rx="275" ry="280" />
              </g>

              <g fill="none" strokeWidth="1.1" filter="url(#fth-glow)">
                <path d="M200 250 Q 330 170 460 220" stroke="#38bdf8" strokeOpacity=".75" />
                <path d="M460 220 Q 520 320 500 440" stroke="#38bdf8" strokeOpacity=".65" />
                <path d="M500 440 Q 400 520 260 490" stroke="#38bdf8" strokeOpacity=".7" />
                <path d="M260 490 Q 170 410 200 250" stroke="#fb923c" strokeOpacity=".6" />
                <path d="M340 340 Q 400 290 460 220" stroke="#22d3ee" strokeOpacity=".85" />
                <path d="M340 340 Q 290 400 260 490" stroke="#22d3ee" strokeOpacity=".75" />
                <path d="M340 340 Q 420 380 500 440" stroke="#ef4444" strokeDasharray="4 4" strokeOpacity=".8" strokeWidth="1.3" />
              </g>

              <g>
                <g className="fth-host" style={{ animationDelay: '.1s' }} transform="translate(200 250)">
                  <circle className="fth-host-ring" r="3" fill="none" stroke="#38bdf8" strokeWidth="1.2" />
                  <circle r="4" fill="#22d3ee" />
                </g>
                <g className="fth-host" style={{ animationDelay: '.5s' }} transform="translate(460 220)">
                  <circle className="fth-host-ring" r="3" fill="none" stroke="#7dd3fc" strokeWidth="1.2" />
                  <circle r="4" fill="#7dd3fc" />
                </g>
                <g className="fth-host" style={{ animationDelay: '1s' }} transform="translate(500 440)">
                  <circle className="fth-host-ring" r="3" fill="none" stroke="#ef4444" strokeWidth="1.2" />
                  <circle r="4.5" fill="#ef4444" />
                </g>
                <g className="fth-host" style={{ animationDelay: '1.5s' }} transform="translate(260 490)">
                  <circle className="fth-host-ring" r="3" fill="none" stroke="#fb923c" strokeWidth="1.2" />
                  <circle r="4" fill="#fb923c" />
                </g>
                <g className="fth-host" style={{ animationDelay: '2s' }} transform="translate(160 380)">
                  <circle className="fth-host-ring" r="3" fill="none" stroke="#22c55e" strokeWidth="1.2" />
                  <circle r="3.5" fill="#22c55e" />
                </g>
                <g className="fth-host" style={{ animationDelay: '.8s' }} transform="translate(540 320)">
                  <circle className="fth-host-ring" r="3" fill="none" stroke="#38bdf8" strokeWidth="1.2" />
                  <circle r="3.5" fill="#38bdf8" />
                </g>
                <g transform="translate(340 340)">
                  <circle r="26" fill="none" stroke="#22d3ee" strokeWidth="1.4" opacity=".6" />
                  <circle r="14" fill="none" stroke="#67e8f9" strokeWidth="1.2" opacity=".8" />
                  <circle r="6"  fill="#22d3ee" />
                  <circle r="2.5" fill="#e0f9ff" />
                </g>
              </g>
            </g>
          </svg>
        </div>

        <div className="fth-scan">
          <svg viewBox="0 0 680 680" aria-hidden="true">
            <defs>
              <linearGradient id="fth-scanGrad" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%"   stopColor="rgba(34,211,238,0)" />
                <stop offset="100%" stopColor="rgba(34,211,238,.55)" />
              </linearGradient>
            </defs>
            <g className="fth-scanline" transformOrigin="340 340">
              <path d="M340 340 L340 60 A280 280 0 0 1 540 160 Z" fill="url(#fth-scanGrad)" opacity=".45" />
            </g>
          </svg>
        </div>

        <div className="fth-packets">
          <div className="fth-pkt fth-p1">→ MODBUS TCP · 502 · READ_COIL</div>
          <div className="fth-pkt fth-p2">⚠ ANOMALY · LATERAL · 10.0.4.17</div>
          <div className="fth-pkt fth-p3">✓ PROFINET · cyclic OK</div>
          <div className="fth-pkt fth-p4">◉ ASSET DISCOVERED · S7-1500</div>
          <div className="fth-pkt fth-p5">→ S7COMM · READ_VAR · DB1</div>
        </div>

        <div className="fth-center">
          <div className="fth-eyebrow">CYJAN · Sentry Mode</div>
          <h1 className="fth-title">
            <span className="fth-for">für</span>
            <span className="fth-name">Thorsten</span>
          </h1>
          <div className="fth-typing" ref={typingRef}><span className="fth-cursor" /></div>
          <div className="fth-badges">
            <span className="fth-badge">◉ SECURE</span>
            <span className="fth-badge fth-ot">⚙ OT / ICS</span>
            <span className="fth-badge">↯ MADE&nbsp;IN&nbsp;BREMEN</span>
          </div>
        </div>
      </div>
    </div>
  );
}

const CSS = `
.fth-root {
  position: relative; width: 100%; height: 100%; min-height: 680px; overflow: hidden;
  background:
    radial-gradient(ellipse at 30% 20%, rgba(34,211,238,0.12), transparent 55%),
    radial-gradient(ellipse at 70% 80%, rgba(251,146,60,0.08), transparent 55%),
    #020617;
  color: #f1f5f9; font-family: 'Inter', system-ui, sans-serif;
  display: flex; align-items: center; justify-content: center;
}
.fth-hexbg {
  position: absolute; inset: 0; pointer-events: none;
  background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='60' height='52' viewBox='0 0 60 52'><polygon points='30,2 58,18 58,34 30,50 2,34 2,18' fill='none' stroke='%23164e63' stroke-width='0.7' stroke-opacity='0.3'/></svg>");
  opacity: .35;
  animation: fth-drift 60s linear infinite;
}
@keyframes fth-drift { to { background-position: 60px 52px; } }

.fth-hud {
  position: absolute; font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 10px; letter-spacing: 3px; color: #67e8f9; text-transform: uppercase; z-index: 10;
}
.fth-tl { top: 20px; left: 24px; display: flex; align-items: center; gap: 10px; }
.fth-tr { top: 20px; right: 24px; color: #64748b; }
.fth-bl { bottom: 20px; left: 24px; color: #64748b; }
.fth-br { bottom: 20px; right: 24px; color: #67e8f9; }
.fth-dot {
  width: 8px; height: 8px; border-radius: 50%; background: #22c55e;
  box-shadow: 0 0 10px #22c55e; animation: fth-pulse 1.5s ease-in-out infinite;
}
@keyframes fth-pulse { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: .4; transform: scale(.7); } }

.fth-stage {
  position: relative; width: min(92%, 980px); height: min(92%, 680px);
  display: flex; align-items: center; justify-content: center;
}

.fth-globe-wrap {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center;
  animation: fth-spinIn 1.8s cubic-bezier(.2,.7,.3,1) both;
}
@keyframes fth-spinIn {
  from { opacity: 0; transform: scale(.7) rotate(-12deg); }
  to   { opacity: 1; transform: scale(1) rotate(0); }
}
.fth-globe { width: 100%; height: 100%; max-width: 680px; max-height: 680px; }
.fth-rot { transform-origin: 340px 340px; animation: fth-spin 42s linear infinite; }
@keyframes fth-spin { to { transform: rotate(360deg); } }

.fth-scan {
  position: absolute; inset: 0;
  display: flex; align-items: center; justify-content: center; pointer-events: none;
}
.fth-scan svg { width: 100%; height: 100%; max-width: 680px; max-height: 680px; }
.fth-scanline { transform-origin: 340px 340px; animation: fth-sweep 6s linear infinite; }
@keyframes fth-sweep { to { transform: rotate(360deg); } }

.fth-host { transform-origin: center; animation: fth-hostPing 3.5s ease-out infinite; }
@keyframes fth-hostPing {
  0% { transform: scale(1);    opacity: .85; }
  50%{ transform: scale(1.35); opacity: 1;   }
  100%{transform: scale(1);    opacity: .85; }
}
.fth-host-ring {
  transform-origin: center;
  animation: fth-hostRing 3.5s ease-out infinite;
  transform-box: fill-box;
}
@keyframes fth-hostRing {
  0%  { r: 3;  opacity: .8; }
  80% { r: 22; opacity: 0;  }
  100%{ r: 22; opacity: 0;  }
}

.fth-center {
  position: relative; z-index: 5; text-align: center; padding: 28px 44px;
  opacity: 0; animation: fth-fadeUp 1.1s cubic-bezier(.2,.7,.3,1) 1.2s both;
}
@keyframes fth-fadeUp { from { opacity: 0; transform: translateY(14px); } to { opacity: 1; transform: none; } }

.fth-eyebrow {
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 11px; letter-spacing: 6px; color: #67e8f9; text-transform: uppercase;
  display: inline-flex; align-items: center; gap: 12px; margin-bottom: 14px;
}
.fth-eyebrow::before, .fth-eyebrow::after {
  content: ''; height: 1px; width: 36px;
  background: linear-gradient(90deg, transparent, #22d3ee, transparent);
}

.fth-title {
  font-family: 'Inter', system-ui, sans-serif; font-weight: 900;
  font-size: clamp(54px, 9vw, 120px);
  line-height: .95; letter-spacing: -2.5px; margin: 0; color: #f1f5f9;
}
.fth-for {
  display: block; font-size: clamp(18px, 2vw, 28px);
  font-weight: 700; letter-spacing: 14px; color: #67e8f9;
  text-transform: uppercase; margin-bottom: 6px; opacity: 0;
  animation: fth-letterIn .7s ease-out 1.4s forwards;
}
.fth-name {
  background: linear-gradient(135deg, #a5f3fc 0%, #22d3ee 40%, #06b6d4 100%);
  -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  filter: drop-shadow(0 0 24px rgba(34,211,238,.4));
  display: inline-block;
  animation: fth-glitch 6s ease-in-out 2.2s infinite;
}
@keyframes fth-letterIn { from { opacity: 0; letter-spacing: 28px; } to { opacity: 1; letter-spacing: 14px; } }
@keyframes fth-glitch {
  0%, 94%, 100% { transform: none; filter: drop-shadow(0 0 24px rgba(34,211,238,.4)); }
  95% { transform: translate(-2px, 0); filter: drop-shadow(2px 0 0 #ef4444) drop-shadow(-2px 0 0 #22d3ee); }
  96% { transform: translate(2px, 0); }
  97% { transform: none; }
}

.fth-typing {
  margin-top: 22px;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 13px; color: #67e8f9; letter-spacing: 1.5px; min-height: 1.4em;
}
.fth-cursor {
  display: inline-block; width: 8px; height: 14px; background: #22d3ee;
  vertical-align: middle; margin-left: 2px;
  animation: fth-blink 1s step-end infinite;
}
@keyframes fth-blink { 50% { opacity: 0; } }

.fth-badges {
  margin-top: 20px;
  display: flex; justify-content: center; gap: 10px; flex-wrap: wrap;
  opacity: 0; animation: fth-fadeUp .8s ease-out 3.4s forwards;
}
.fth-badge {
  padding: 6px 12px;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 10px; letter-spacing: 2px; color: #67e8f9;
  border: 1px solid rgba(34,211,238,.35);
  background: rgba(14,165,233,.06);
  border-radius: 2px;
}
.fth-badge.fth-ot {
  color: #fb923c; border-color: rgba(251,146,60,.35); background: rgba(251,146,60,.05);
}

.fth-packets { position: absolute; inset: 0; pointer-events: none; overflow: hidden; }
.fth-pkt {
  position: absolute;
  font-family: 'JetBrains Mono', ui-monospace, monospace;
  font-size: 10px; color: #67e8f9; opacity: 0; white-space: nowrap;
  text-shadow: 0 0 8px rgba(34,211,238,.6);
}
.fth-p1 { top: 12%; left: 6%;    animation: fth-pktFly 7s linear 2.5s infinite; }
.fth-p2 { top: 28%; right: 4%;   color: #fb923c; text-shadow: 0 0 8px rgba(251,146,60,.5); animation: fth-pktFly 9s linear 3.8s infinite; }
.fth-p3 { bottom: 18%; left: 4%; animation: fth-pktFly 8s linear 4.5s infinite; }
.fth-p4 { bottom: 8%; right: 8%; color: #22c55e; text-shadow: 0 0 8px rgba(34,197,94,.5); animation: fth-pktFly 6s linear 5.5s infinite; }
.fth-p5 { top: 50%; left: 2%;    animation: fth-pktFly 10s linear 6.2s infinite; }
@keyframes fth-pktFly {
  0%  { opacity: 0; transform: translateX(-20px); }
  10% { opacity: .9; }
  90% { opacity: .7; }
  100%{ opacity: 0; transform: translateX(40px); }
}

.fth-sweep-line {
  position: absolute; left: -10%; right: -10%; top: 50%;
  height: 1px;
  background: linear-gradient(90deg, transparent 0%, #22d3ee 50%, transparent 100%);
  opacity: .7; transform: translateY(-50%);
  animation: fth-lineMove 4.5s ease-in-out infinite;
  pointer-events: none;
}
@keyframes fth-lineMove {
  0%, 100% { top: 12%; opacity: 0; }
  20% { opacity: .9; }
  50% { top: 88%; opacity: .9; }
  80% { opacity: 0; }
}
`;
