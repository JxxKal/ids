import { useEffect, useState } from 'react';
import { fetchThreatLevel } from '../api';
import type { ThreatLevel } from '../types';

const STATUS_LABEL: Record<string, string> = {
  green:  'Normal',
  yellow: 'Moderat',
  orange: 'Erhöht',
  red:    'Kritisch',
};

const STATUS_COLOR: Record<string, string> = {
  green:  '#22c55e',
  yellow: '#eab308',
  orange: '#f97316',
  red:    '#ef4444',
};

export function ThreatGauge() {
  const [data, setData] = useState<ThreatLevel | null>(null);

  useEffect(() => {
    const load = () =>
      fetchThreatLevel()
        .then(setData)
        .catch(() => {});
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);

  if (!data) {
    return (
      <div className="cyjan-kpi-card flex items-center justify-center" style={{ minHeight: 152 }}>
        <span className="text-slate-600 text-xs font-mono">lade…</span>
      </div>
    );
  }

  const value = Math.max(0, Math.min(100, data.level));
  const color = STATUS_COLOR[data.label] ?? STATUS_COLOR.green;
  const status = STATUS_LABEL[data.label] ?? '–';
  const circ = 2 * Math.PI * 54;
  const offset = circ - (value / 100) * circ;

  const counts = data.alert_counts ?? {};

  return (
    <div className="cyjan-kpi-card flex items-center gap-4" style={{ flex: '0 0 auto', minWidth: 320 }}>
      <svg width="120" height="120" viewBox="0 0 120 120" className="shrink-0">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#172033" strokeWidth="8" />
        <circle
          cx="60" cy="60" r="54" fill="none"
          stroke={color}
          strokeWidth="8"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 60 60)"
          style={{
            transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s ease',
            filter: `drop-shadow(0 0 6px ${color})`,
          }}
        />
        <text
          x="60" y="58" textAnchor="middle"
          fontFamily="JetBrains Mono" fontSize="26" fontWeight="700"
          fill={color}
        >
          {value}
        </text>
        <text
          x="60" y="76" textAnchor="middle"
          fontFamily="JetBrains Mono" fontSize="9"
          fill="#64748b"
          letterSpacing="0.16em"
        >
          THREAT
        </text>
      </svg>

      <div className="flex-1 min-w-0">
        <div className="cyjan-kpi-card-title mb-1" style={{ marginBottom: 4 }}>
          Threat Level · {data.window_min} min
        </div>
        <div className="text-sm font-semibold text-cyan-100 mb-2" style={{ fontFamily: 'Inter, sans-serif' }}>
          {status}
        </div>
        <div className="flex flex-wrap gap-x-3 gap-y-0.5 text-[10px] font-mono text-slate-500">
          <span>C: <span className="text-red-300 font-semibold">{counts.critical ?? 0}</span></span>
          <span>H: <span className="text-red-400 font-semibold">{counts.high ?? 0}</span></span>
          <span>M: <span className="text-orange-400 font-semibold">{counts.medium ?? 0}</span></span>
          <span>L: <span className="text-green-400 font-semibold">{counts.low ?? 0}</span></span>
        </div>
      </div>
    </div>
  );
}
