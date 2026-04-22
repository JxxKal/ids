/* global React */
// Interactive globe with dynamic network hosts — the hero centerpiece.
// Pure SVG, no deps. Hosts orbit a sphere; connections form and dissolve on a timer.

const { useEffect, useRef, useState } = React;

window.NetworkGlobe = function NetworkGlobe({ size = 520 }) {
  const svgRef = useRef(null);
  const [frame, setFrame] = useState(0);
  const [rotation, setRotation] = useState(0);
  const [conns, setConns] = useState([]);
  const [pulses, setPulses] = useState([]);

  // Host definitions — lat, lon, label, kind
  const HOSTS = [
    { id:'plc-01', lat:52,  lon: 13, kind:'plc',   label:'PLC·01' },
    { id:'hmi-02', lat:48,  lon:  9, kind:'hmi',   label:'HMI·02' },
    { id:'scada',  lat:40,  lon: -3, kind:'scada', label:'SCADA·core' },
    { id:'rtu-07', lat:37,  lon:-74, kind:'rtu',   label:'RTU·07' },
    { id:'eng-11', lat:35,  lon:139, kind:'eng',   label:'ENG·11' },
    { id:'plc-12', lat: 1,  lon:103, kind:'plc',   label:'PLC·12' },
    { id:'rtu-19', lat:-23, lon:-46, kind:'rtu',   label:'RTU·19' },
    { id:'hmi-22', lat:-33, lon:151, kind:'hmi',   label:'HMI·22' },
    { id:'ot-gw',  lat:55,  lon:-37, kind:'gw',    label:'OT·gw'  },
    { id:'ids',    lat:51,  lon: 10, kind:'ids',   label:'CYJAN'  },
  ];

  // Animation tick
  useEffect(() => {
    let raf;
    const tick = () => {
      setFrame(f => f + 1);
      setRotation(r => (r + 0.15) % 360);
      raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, []);

  // Spawn and retire connections — every ~900 ms
  useEffect(() => {
    const interval = setInterval(() => {
      setConns(prev => {
        // retire expired
        const now = Date.now();
        const alive = prev.filter(c => now - c.born < c.ttl);
        // maybe add new
        if (alive.length < 5 && Math.random() > 0.2) {
          const a = HOSTS[Math.floor(Math.random() * HOSTS.length)];
          let b = HOSTS[Math.floor(Math.random() * HOSTS.length)];
          while (b.id === a.id) b = HOSTS[Math.floor(Math.random() * HOSTS.length)];
          const protocols = ['TCP', 'TCP', 'TCP', 'UDP', 'UDP', 'ICMP'];
          const proto = protocols[Math.floor(Math.random() * protocols.length)];
          const threat = Math.random() > 0.8;
          alive.push({
            id: `c${now}-${Math.random().toString(36).slice(2,5)}`,
            a: a.id, b: b.id, proto, threat,
            born: now, ttl: 1800 + Math.random() * 1800,
          });
        }
        return alive;
      });
      // also add a pulse from IDS outward occasionally
      if (Math.random() > 0.7) {
        setPulses(prev => [...prev.slice(-3), { id: Date.now(), born: Date.now() }]);
      }
    }, 600);
    return () => clearInterval(interval);
  }, []);

  // Project lat/lon to x/y on the visible hemisphere
  const project = (lat, lon) => {
    const rotLon = lon + rotation;
    const latRad = lat * Math.PI / 180;
    const lonRad = rotLon * Math.PI / 180;
    const x = Math.cos(latRad) * Math.sin(lonRad);
    const y = -Math.sin(latRad);
    const z = Math.cos(latRad) * Math.cos(lonRad);
    return { x, y, z, visible: z > -0.3 };
  };

  const R = size / 2 - 40;
  const cx = size / 2, cy = size / 2;

  const protoColor = p => p === 'TCP' ? '#38bdf8' : p === 'UDP' ? '#fb923c' : '#a78bfa';
  const kindColor = k => ({
    plc:   '#38bdf8', hmi:  '#7dd3fc', scada:'#0ea5e9',
    rtu:   '#38bdf8', eng:  '#7dd3fc', gw:   '#94a3b8',
    ids:   '#22d3ee',
  })[k] || '#94a3b8';

  const points = HOSTS.map(h => ({ ...h, p: project(h.lat, h.lon) }));
  const pointById = Object.fromEntries(points.map(p => [p.id, p]));

  return (
    <div style={{ position:'relative', width:size, height:size }}>
      <svg ref={svgRef} width={size} height={size} viewBox={`0 0 ${size} ${size}`}
           style={{ filter:'drop-shadow(0 0 60px rgba(14,165,233,0.25))' }}>
        <defs>
          <radialGradient id="globeFill">
            <stop offset="0%" stopColor="rgba(14,165,233,0.08)"/>
            <stop offset="70%" stopColor="rgba(14,165,233,0.02)"/>
            <stop offset="100%" stopColor="rgba(2,6,23,0.0)"/>
          </radialGradient>
          <radialGradient id="globeGlow">
            <stop offset="0%" stopColor="rgba(14,165,233,0)"/>
            <stop offset="90%" stopColor="rgba(14,165,233,0.10)"/>
            <stop offset="100%" stopColor="rgba(14,165,233,0)"/>
          </radialGradient>
        </defs>

        {/* outer halo */}
        <circle cx={cx} cy={cy} r={R + 30} fill="url(#globeGlow)" />

        {/* sphere fill */}
        <circle cx={cx} cy={cy} r={R} fill="url(#globeFill)" stroke="rgba(14,165,233,0.3)" strokeWidth="1"/>

        {/* latitude rings */}
        {[-60,-30,0,30,60].map(lat => {
          const latRad = lat * Math.PI/180;
          const ry = Math.abs(R * Math.cos(latRad)) * 0.2;
          const rx = R * Math.cos(latRad);
          const yOff = -R * Math.sin(latRad);
          return (
            <ellipse key={lat} cx={cx} cy={cy + yOff} rx={rx} ry={ry}
                     fill="none" stroke="rgba(56,189,248,0.18)" strokeWidth="0.6"/>
          );
        })}

        {/* meridians */}
        {[0, 30, 60, 90, 120, 150].map(lon => {
          const rotLon = (lon + rotation) % 180;
          const rad = rotLon * Math.PI/180;
          const rx = Math.abs(R * Math.sin(rad));
          return (
            <ellipse key={lon} cx={cx} cy={cy} rx={rx} ry={R}
                     fill="none" stroke="rgba(56,189,248,0.12)" strokeWidth="0.5"/>
          );
        })}

        {/* outgoing radar pulses from IDS */}
        {pulses.map(p => {
          const age = (Date.now() - p.born) / 2000;
          if (age > 1) return null;
          return (
            <circle key={p.id} cx={cx} cy={cy} r={R * age}
                    fill="none" stroke="rgba(34,211,238,0.25)"
                    strokeWidth={1.5 * (1-age)}
                    opacity={1 - age}/>
          );
        })}

        {/* connections: arcs with animated packet dots */}
        {conns.map(c => {
          const pa = pointById[c.a].p, pb = pointById[c.b].p;
          if (!pa.visible && !pb.visible) return null;
          const ax = cx + pa.x * R, ay = cy + pa.y * R;
          const bx = cx + pb.x * R, by = cy + pb.y * R;
          // arc — lift midpoint off the sphere
          const mx = (ax + bx) / 2;
          const my = (ay + by) / 2;
          const dx = bx - ax, dy = by - ay;
          const dist = Math.hypot(dx, dy);
          const lift = Math.min(dist * 0.3, 70);
          const cpX = mx + (-dy / dist) * lift * 0.5;
          const cpY = my + (dx / dist) * lift * 0.5 - lift * 0.3;

          const age = (Date.now() - c.born) / c.ttl;
          const fade = age < 0.2 ? age/0.2 : age > 0.8 ? (1-age)/0.2 : 1;
          const stroke = c.threat ? '#ef4444' : protoColor(c.proto);
          const strokeOp = c.threat ? 0.9 : 0.55;
          return (
            <g key={c.id} opacity={fade}>
              <path d={`M ${ax} ${ay} Q ${cpX} ${cpY} ${bx} ${by}`}
                    fill="none" stroke={stroke} strokeOpacity={strokeOp}
                    strokeWidth={c.threat ? 1.8 : 0.9}
                    strokeDasharray={c.threat ? "4 3" : "none"} />
              {/* traveling packet */}
              {(() => {
                const t = (age * 2) % 1;
                const x = (1-t)*(1-t)*ax + 2*(1-t)*t*cpX + t*t*bx;
                const y = (1-t)*(1-t)*ay + 2*(1-t)*t*cpY + t*t*by;
                return <circle cx={x} cy={y} r={c.threat ? 3 : 2} fill={stroke}
                               style={{ filter:`drop-shadow(0 0 6px ${stroke})` }}/>;
              })()}
            </g>
          );
        })}

        {/* hosts */}
        {points.map(h => {
          if (!h.p.visible) return null;
          const x = cx + h.p.x * R, y = cy + h.p.y * R;
          const z = h.p.z;
          const opacity = 0.4 + z * 0.6;
          const r = h.kind === 'ids' ? 5 : 3;
          const color = kindColor(h.kind);
          return (
            <g key={h.id} opacity={opacity}>
              {h.kind === 'ids' && (
                <circle cx={x} cy={y} r={r + 6 + Math.sin(frame*0.1) * 2}
                        fill="none" stroke={color} strokeOpacity="0.4" strokeWidth="1"/>
              )}
              <circle cx={x} cy={y} r={r} fill={color}
                      style={{ filter:`drop-shadow(0 0 ${r*2}px ${color})` }}/>
              {(h.kind === 'ids' || z > 0.7) && (
                <text x={x + 8} y={y + 3} fill="#7dd3fc"
                      fontFamily="JetBrains Mono" fontSize="9"
                      opacity={z}>
                  {h.label}
                </text>
              )}
            </g>
          );
        })}
      </svg>

      {/* legend overlay */}
      <div style={{
        position:'absolute', bottom:-6, left:0, right:0,
        display:'flex', justifyContent:'center', gap:16,
        fontFamily:'JetBrains Mono', fontSize:10, color:'#64748b',
      }}>
        <span><span style={{ color:'#38bdf8' }}>●</span> TCP</span>
        <span><span style={{ color:'#fb923c' }}>●</span> UDP</span>
        <span><span style={{ color:'#a78bfa' }}>●</span> ICMP</span>
        <span><span style={{ color:'#ef4444' }}>●</span> threat</span>
        <span style={{ color:'#22d3ee' }}>◎ CYJAN IDS</span>
      </div>
    </div>
  );
};
