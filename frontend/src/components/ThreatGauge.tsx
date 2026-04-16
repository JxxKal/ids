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
    <div className="card px-5 py-3 flex items-center gap-5 min-w-[280px]">
      {/* Gauge bar */}
      <div className="flex-1">
        <div className="flex justify-between text-xs text-slate-500 mb-1">
          <span>Threat Level</span>
          <span className="text-slate-400">{data.window_min} min</span>
        </div>
        <div className="h-2.5 bg-slate-800 rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full bg-gradient-to-r ${grad} transition-all duration-700`}
            style={{ width: `${data.level}%` }}
          />
        </div>
        <div className="flex justify-between mt-1.5 text-xs text-slate-500">
          {['critical', 'high', 'medium', 'low'].map(sev => (
            <span key={sev}>
              {sev[0].toUpperCase()}: <span className="text-slate-300">{data.alert_counts[sev] ?? 0}</span>
            </span>
          ))}
        </div>
      </div>
      {/* Score */}
      <div className={`text-3xl font-bold tabular-nums ${color}`}>
        {data.level}
      </div>
    </div>
  );
}
