import { useEffect, useRef } from 'react';

interface Props {
  size?: number;
}

type Host = { id: string; lat: number; lon: number; kind: keyof typeof KIND_COLOR; label: string };
type Conn = { a: Host; b: Host; proto: keyof typeof PROTO_COLOR; threat: boolean; born: number; ttl: number };
type Pulse = { born: number };

const HOSTS: Host[] = [
  { id: 'plc-01',  lat:  52, lon:   13, kind: 'plc',   label: 'PLC·01'  },
  { id: 'hmi-02',  lat:  48, lon:    9, kind: 'hmi',   label: 'HMI·02'  },
  { id: 'scada',   lat:  40, lon:   -3, kind: 'scada', label: 'SCADA'   },
  { id: 'rtu-07',  lat:  18, lon:  -74, kind: 'rtu',   label: 'RTU·07'  },
  { id: 'eng-11',  lat:  30, lon:  139, kind: 'eng',   label: 'ENG·11'  },
  { id: 'plc-12',  lat:   1, lon:  103, kind: 'plc',   label: 'PLC·12'  },
  { id: 'rtu-19',  lat: -23, lon:  -46, kind: 'rtu',   label: 'RTU·19'  },
  { id: 'hmi-22',  lat: -33, lon:  151, kind: 'hmi',   label: 'HMI·22'  },
  { id: 'ot-gw',   lat:  55, lon:  -37, kind: 'gw',    label: 'OT·gw'   },
  { id: 'plc-31',  lat:  60, lon:   25, kind: 'plc',   label: 'PLC·31'  },
  { id: 'rtu-33',  lat:  44, lon:   37, kind: 'rtu',   label: 'RTU·33'  },
  { id: 'eng-41',  lat:  22, lon:   78, kind: 'eng',   label: 'ENG·41'  },
  { id: 'hmi-52',  lat: -12, lon:   28, kind: 'hmi',   label: 'HMI·52'  },
  { id: 'plc-63',  lat: -34, lon:  -64, kind: 'plc',   label: 'PLC·63'  },
  { id: 'rtu-71',  lat:  37, lon: -122, kind: 'rtu',   label: 'RTU·71'  },
  { id: 'scada2',  lat:   6, lon:   -2, kind: 'scada', label: 'SCADA·2' },
  { id: 'gw-edge', lat:  64, lon:  -21, kind: 'gw',    label: 'GW·edge' },
  { id: 'eng-82',  lat:  41, lon:  116, kind: 'eng',   label: 'ENG·82'  },
  { id: 'hmi-91',  lat: -27, lon:  133, kind: 'hmi',   label: 'HMI·91'  },
  { id: 'plc-14',  lat:  15, lon:   44, kind: 'plc',   label: 'PLC·14'  },
];

const KIND_COLOR = { plc: '#38bdf8', hmi: '#7dd3fc', scada: '#0ea5e9', rtu: '#38bdf8', eng: '#7dd3fc', gw: '#94a3b8' } as const;
const PROTO_COLOR = { TCP: '#38bdf8', UDP: '#fb923c', ICMP: '#a78bfa' } as const;
const PROTOS: (keyof typeof PROTO_COLOR)[] = ['TCP', 'TCP', 'TCP', 'UDP', 'UDP', 'ICMP'];

const NS = 'http://www.w3.org/2000/svg';
const el = (tag: string, attrs: Record<string, string | number>): SVGElement => {
  const n = document.createElementNS(NS, tag);
  for (const k in attrs) n.setAttribute(k, String(attrs[k]));
  return n;
};

export function NetworkGlobe({ size = 520 }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);

  useEffect(() => {
    const svg = svgRef.current;
    if (!svg) return;

    const cx = size / 2;
    const cy = size / 2;
    const R = size / 2 - 60;

    let rotation = 0;
    let conns: Conn[] = [];
    let pulses: Pulse[] = [];
    let lastSpawn = 0;
    let rafId = 0;

    svg.innerHTML = `
      <defs>
        <radialGradient id="globeFill" cx="50%" cy="50%" r="50%">
          <stop offset="0%"  stop-color="rgba(14,165,233,0.08)"/>
          <stop offset="70%" stop-color="rgba(14,165,233,0.02)"/>
          <stop offset="100%" stop-color="rgba(2,6,23,0)"/>
        </radialGradient>
        <radialGradient id="globeGlow" cx="50%" cy="50%" r="50%">
          <stop offset="0%"  stop-color="rgba(14,165,233,0)"/>
          <stop offset="85%" stop-color="rgba(14,165,233,0.10)"/>
          <stop offset="100%" stop-color="rgba(14,165,233,0)"/>
        </radialGradient>
      </defs>
      <circle cx="${cx}" cy="${cy}" r="${R + 34}" fill="url(#globeGlow)"/>
      <circle cx="${cx}" cy="${cy}" r="${R}" fill="url(#globeFill)" stroke="rgba(14,165,233,0.3)" stroke-width="1"/>
      <g id="g-lats"></g>
      <g id="g-mers"></g>
      <g id="g-pulses"></g>
      <g id="g-conns"></g>
      <g id="g-hosts"></g>
    `;

    const gLats   = svg.querySelector('#g-lats')!;
    const gMers   = svg.querySelector('#g-mers')!;
    const gPulses = svg.querySelector('#g-pulses')!;
    const gConns  = svg.querySelector('#g-conns')!;
    const gHosts  = svg.querySelector('#g-hosts')!;

    [-60, -30, 0, 30, 60].forEach(lat => {
      const latRad = (lat * Math.PI) / 180;
      const ry = Math.abs(R * Math.cos(latRad)) * 0.2;
      const rx = R * Math.cos(latRad);
      const yOff = -R * Math.sin(latRad);
      gLats.appendChild(el('ellipse', {
        cx, cy: cy + yOff, rx, ry,
        fill: 'none', stroke: 'rgba(56,189,248,0.18)', 'stroke-width': 0.6,
      }));
    });

    const project = (lat: number, lon: number) => {
      const rotLon = lon + rotation;
      const latR = (lat * Math.PI) / 180;
      const lonR = (rotLon * Math.PI) / 180;
      return {
        x: Math.cos(latR) * Math.sin(lonR),
        y: -Math.sin(latR),
        z: Math.cos(latR) * Math.cos(lonR),
      };
    };

    const renderMeridians = () => {
      gMers.innerHTML = '';
      for (let lon = 0; lon < 180; lon += 30) {
        const rotLon = (lon + rotation) % 180;
        const rad = (rotLon * Math.PI) / 180;
        const rx = Math.abs(R * Math.sin(rad));
        gMers.appendChild(el('ellipse', {
          cx, cy, rx, ry: R,
          fill: 'none', stroke: 'rgba(56,189,248,0.12)', 'stroke-width': 0.5,
        }));
      }
    };

    const renderPulses = () => {
      gPulses.innerHTML = '';
      const now = performance.now();
      pulses = pulses.filter(p => now - p.born < 2000);
      pulses.forEach(p => {
        const age = (now - p.born) / 2000;
        gPulses.appendChild(el('circle', {
          cx, cy, r: R * age,
          fill: 'none', stroke: 'rgba(34,211,238,0.25)',
          'stroke-width': 1.5 * (1 - age), opacity: 1 - age,
        }));
      });
    };

    const renderConns = () => {
      gConns.innerHTML = '';
      const now = performance.now();
      conns = conns.filter(c => now - c.born < c.ttl);
      conns.forEach(c => {
        const pa = project(c.a.lat, c.a.lon);
        const pb = project(c.b.lat, c.b.lon);
        if (pa.z < -0.3 && pb.z < -0.3) return;
        const ax = cx + pa.x * R, ay = cy + pa.y * R;
        const bx = cx + pb.x * R, by = cy + pb.y * R;
        const mx = (ax + bx) / 2, my = (ay + by) / 2;
        const dx = bx - ax, dy = by - ay;
        const dist = Math.hypot(dx, dy) || 1;
        const lift = Math.min(dist * 0.3, 70);
        const cpX = mx + (-dy / dist) * lift * 0.5;
        const cpY = my + (dx / dist) * lift * 0.5 - lift * 0.3;
        const age = (now - c.born) / c.ttl;
        const fade = age < 0.2 ? age / 0.2 : age > 0.8 ? (1 - age) / 0.2 : 1;
        const stroke = c.threat ? '#ef4444' : PROTO_COLOR[c.proto];
        const g = el('g', { opacity: fade });
        g.appendChild(el('path', {
          d: `M ${ax} ${ay} Q ${cpX} ${cpY} ${bx} ${by}`,
          fill: 'none', stroke,
          'stroke-opacity': c.threat ? 0.9 : 0.55,
          'stroke-width': c.threat ? 1.8 : 0.9,
          'stroke-dasharray': c.threat ? '4 3' : 'none',
        }));
        const t = (age * 2) % 1;
        const px = (1 - t) * (1 - t) * ax + 2 * (1 - t) * t * cpX + t * t * bx;
        const py = (1 - t) * (1 - t) * ay + 2 * (1 - t) * t * cpY + t * t * by;
        const dot = el('circle', {
          cx: px, cy: py, r: c.threat ? 3 : 2, fill: stroke,
        });
        dot.setAttribute('style', `filter: drop-shadow(0 0 6px ${stroke})`);
        g.appendChild(dot);
        gConns.appendChild(g);
      });
    };

    const renderHosts = () => {
      gHosts.innerHTML = '';
      HOSTS.forEach(h => {
        const p = project(h.lat, h.lon);
        if (p.z < -0.3) return;
        const x = cx + p.x * R, y = cy + p.y * R;
        const opacity = 0.4 + Math.max(0, p.z) * 0.6;
        const color = KIND_COLOR[h.kind] ?? '#94a3b8';
        const g = el('g', { opacity });
        const dot = el('circle', { cx: x, cy: y, r: 3, fill: color });
        dot.setAttribute('style', `filter: drop-shadow(0 0 6px ${color})`);
        g.appendChild(dot);
        if (p.z > 0.7) {
          const text = el('text', {
            x: x + 8, y: y + 3,
            fill: '#7dd3fc',
            'font-family': 'JetBrains Mono, monospace',
            'font-size': 9,
            opacity: p.z,
          });
          text.textContent = h.label;
          g.appendChild(text);
        }
        gHosts.appendChild(g);
      });
    };

    const spawnConnection = () => {
      const a = HOSTS[Math.floor(Math.random() * HOSTS.length)];
      let b = HOSTS[Math.floor(Math.random() * HOSTS.length)];
      while (b.id === a.id) b = HOSTS[Math.floor(Math.random() * HOSTS.length)];
      conns.push({
        a, b,
        proto: PROTOS[Math.floor(Math.random() * PROTOS.length)],
        threat: Math.random() > 0.9,
        born: performance.now(),
        ttl: 2400 + Math.random() * 2400,
      });
    };

    const tick = (now: number) => {
      rotation = (rotation + 0.15) % 360;
      if (now - lastSpawn > 180) {
        lastSpawn = now;
        const deficit = 18 - conns.length;
        if (deficit > 0) {
          const n = Math.min(deficit, 3);
          for (let i = 0; i < n; i++) spawnConnection();
        }
        if (Math.random() > 0.55) pulses.push({ born: now });
      }
      renderMeridians();
      renderPulses();
      renderConns();
      renderHosts();
      rafId = requestAnimationFrame(tick);
    };
    rafId = requestAnimationFrame(tick);

    return () => {
      cancelAnimationFrame(rafId);
    };
  }, [size]);

  return (
    <svg
      ref={svgRef}
      viewBox={`0 0 ${size} ${size}`}
      className="absolute inset-0 w-full h-full"
      aria-hidden="true"
    />
  );
}
