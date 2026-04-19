import { useEffect, useState } from 'react';
import { fetchThreatLevel } from '../api';
import type { ThreatLevel } from '../types';

const COLORS: Record<string, string> = {
  green:  'from-green-600  to-green-400',
  yellow: 'from-yellow-600 to-yellow-400',
  orange: 'from-orange-600 to-orange-400',
  red:    'from-red-700    to-red-400',
};

const TEXT_COLORS: Record<string, string> = {
  green:  'text-green-400',
  yellow: 'text-yellow-400',
  orange: 'text-orange-400',
  red:    'text-red-400',
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

  if (!data) return null;

  const grad  = COLORS[data.label]      ?? COLORS.green;
  const color = TEXT_COLORS[data.label] ?? TEXT_COLORS.green;

  return (
    <div className="flex items-center gap-3 px-3 py-1.5 rounded-lg bg-slate-800/60 border border-slate-700/60 min-w-[260px]">
      {/* Score */}
      <div className={`text-2xl font-bold tabular-nums leading-none ${color}`}>
        {data.level}
      </div>
      {/* Gauge + counts */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between text-[10px] text-slate-500 mb-1">
          <span className="font-medium text-slate-400">Threat Level</span>
          <span>{data.window_min} min</span>
        </div>
        <div className="h-1.5 bg-slate-700 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full bg-gradient-to-r ${grad} transition-all duration-700`}
            style={{ width: `${data.level}%` }}
          />
        </div>
        <div className="flex gap-2.5 mt-1 text-[10px] text-slate-500">
          {['critical', 'high', 'medium', 'low'].map(sev => (
            <span key={sev}>
              {sev[0].toUpperCase()}: <span className="text-slate-300 font-medium">{data.alert_counts[sev] ?? 0}</span>
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}
