import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { Alert } from '../types';
import { isSuppressed } from '../types';
import { effectiveSeverity } from '../lib/severity';

interface Props {
  alerts: Alert[];
  showTest: boolean;
  showSuppressed: boolean;
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

export function SeverityBarsCard({ alerts, showTest, showSuppressed }: Props) {
  const { t } = useTranslation();
  const counts = useMemo(() => {
    const visible = alerts.filter(a =>
      (showTest || !a.is_test) && (showSuppressed || !isSuppressed(a))
    );
    const c: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const a of visible) {
      // effective statt Original-Severity — sonst widerspricht die KPI dem
      // Feed (FP→low, P0→critical werden dort ebenfalls effektiv gezählt).
      const sev = effectiveSeverity(a);
      if (c[sev] !== undefined) c[sev]++;
    }
    return c;
  }, [alerts, showTest, showSuppressed]);

  const max = Math.max(1, ...Object.values(counts));

  return (
    <div className="cyjan-kpi-card">
      <div className="cyjan-kpi-card-title relative z-10">{t('severityCard.title')}</div>
      <div className="flex flex-col gap-1.5 relative z-10">
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
                  style={{
                    width: `${(v / max) * 100}%`,
                    background: r.color,
                    boxShadow: v > 0 ? `0 0 8px -2px ${r.color}` : 'none',
                  }}
                />
              </div>
              <span className="cyjan-kpi-row-value cyjan-tabular">{v}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}
