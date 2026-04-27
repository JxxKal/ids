import { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { Alert } from '../types';

interface Props {
  alerts: Alert[];
  showTest: boolean;
}

export function TopProtocolsCard({ alerts, showTest }: Props) {
  const { t } = useTranslation();
  const rows = useMemo(() => {
    const visible = showTest ? alerts : alerts.filter(a => !a.is_test);
    const total = visible.length || 1;
    const map = new Map<string, number>();
    for (const a of visible) {
      const p = (a.proto || '—').toUpperCase();
      map.set(p, (map.get(p) ?? 0) + 1);
    }
    return [...map.entries()]
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5)
      .map(([proto, count]) => ({ proto, pct: Math.round((count / total) * 100) }));
  }, [alerts, showTest]);

  return (
    <div className="cyjan-kpi-card">
      <div className="cyjan-kpi-card-title">{t('protocolsCard.title')}</div>
      {rows.length === 0 && (
        <div className="text-xs text-slate-600 py-2">{t('common.noData')}</div>
      )}
      <div className="flex flex-col gap-1.5">
        {rows.map(r => (
          <div
            key={r.proto}
            className="grid items-center gap-2"
            style={{ gridTemplateColumns: '84px 1fr 36px' }}
          >
            <span className="cyjan-kpi-row-label" style={{ color: '#fb923c' }}>{r.proto}</span>
            <div className="cyjan-kpi-bar" style={{ height: 4 }}>
              <div className="cyjan-kpi-bar-fill" style={{ width: `${r.pct}%`, background: '#fb923c' }} />
            </div>
            <span className="cyjan-kpi-row-value">{r.pct}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}
