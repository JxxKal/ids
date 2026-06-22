import { useTranslation } from 'react-i18next';
import type { HostRoleEntry, RoleCatalogEntry } from '../types';

interface Props {
  roleId: string;
  entry:  HostRoleEntry;
  // Optionaler Katalog für ein lesbares Label (sonst Fallback auf roleId).
  catalog?: RoleCatalogEntry[];
  size?:  'xs' | 'sm';
}

// Badge für eine erkannte Host-Rolle. Vorlage: TrustBadge.tsx.
// Farbe nach source (auto = cyan/statistisch, manual = violet/Lock).
// Tooltip erklärt WARUM: Evidence, Confidence, seit wann.
export function RoleBadge({ roleId, entry, catalog, size = 'xs' }: Props) {
  const { t } = useTranslation();
  const cls = size === 'xs' ? 'px-1 py-0.5 text-xs rounded' : 'px-1.5 py-1 text-xs rounded';

  const label = catalog?.find(c => c.id === roleId)?.label ?? roleId;
  const manual = entry.source === 'manual';
  const confPct = Math.round((entry.confidence ?? 0) * 100);

  // Tooltip: Quelle + Confidence + Evidence + erste Detektion.
  const tipParts: string[] = [
    manual ? t('roles.tooltip.manual') : t('roles.tooltip.auto', { confidence: confPct }),
  ];
  if (entry.evidence?.length) {
    tipParts.push(t('roles.tooltip.evidence', { evidence: entry.evidence.join(', ') }));
  }
  if (entry.since) {
    tipParts.push(t('roles.tooltip.since', { since: new Date(entry.since).toLocaleString() }));
  }
  const title = tipParts.join('\n');

  if (manual) {
    return (
      <span
        title={title}
        className={`${cls} bg-violet-900/40 text-violet-300 border border-violet-700/40`}
      >
        🔒 {label}
      </span>
    );
  }
  return (
    <span
      title={title}
      className={`${cls} bg-cyan-900/40 text-cyan-300 border border-cyan-700/40`}
    >
      {label}
      <span className="ml-1 text-cyan-500/80 tabular-nums">{confPct}%</span>
    </span>
  );
}
