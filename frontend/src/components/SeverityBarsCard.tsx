import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { Alert } from '../types';

interface Props {
  alerts: Alert[];
  showTest: boolean;
}

// Severity-Labels bleiben sprachneutral – die Begriffe critical/high/medium/low
// sind im Security-Kontext etabliert und werden auch in der DE-Version so
// verwendet (gleiche Schreibweise auf Englisch wie auf Deutsch).
const ROWS: { key: Alert['severity']; label: string; color: string }[] = [
  { key: 'critical', label: 'critical', color: '#ef4444' },
  { key: 'high',     label: 'high',     color: '#dc2626' },
  { key: 'medium',   label: 'medium',   color: '#f97316' },
  { key: 'low',      label: 'low',      color: '#22c55e' },
];

export function SeverityBarsCard({ alerts, showTest }: Props) {
  const { t } = useTranslation();
  const counts = useMemo(() => {
    const visible = showTest ? alerts : alerts.filter(a => !a.is_test);
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of visible) {
      if (c[a.severity] !== undefined) c[a.severity]++;
    }
    return c;
  }, [alerts, showTest]);

  const max = Math.max(1, ...Object.values(counts));

  return (
    <div className="cyjan-kpi-card">
      <div className="cyjan-kpi-card-title">{t('severityCard.title')}</div>
      <div className="flex flex-col gap-1.5">
        {ROWS.map(r => {
          const v = counts[r.key];
          return (
            <div
              key={r.key}
              className="grid items-center gap-2"
              style={{ gridTemplateColumns: '64px 1fr 36px' }}
            >
              <span className="cyjan-kpi-row-label">{r.label}</span>
              <div className="cyjan-kpi-bar">
                <div
                  className="cyjan-kpi-bar-fill"
                  style={{ width: `${(v / max) * 100}%`, background: r.color }}
                />
              </div>
              <span className="cyjan-kpi-row-value">{v}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
