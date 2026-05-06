import type { Alert } from '../types';
import { effectiveSeverity, severityIsDerived } from '../lib/severity';

interface Props {
  // Entweder reine Severity (alte Aufrufer, statische Filter-UI etc.) ...
  severity?: Alert['severity'];
  // ... oder ein vollständiger Alert (für effective-severity-Ableitung).
  alert?: Pick<Alert, 'severity' | 'feedback' | 'boundary_priority'>;
}

export function SeverityBadge({ severity, alert }: Props) {
  const sev      = alert ? effectiveSeverity(alert) : (severity ?? 'low');
  const derived  = alert ? severityIsDerived(alert) : false;
  const tooltip  = derived
    ? (alert?.feedback === 'fp'
        ? 'Severity auf low gestuft (vom User als False-Positive markiert)'
        : 'Severity auf critical gehoben (P0-Boundary-Breach)')
    : undefined;

  return (
    <span
      className={`cyjan-sev-badge cyjan-sev-${sev}${derived ? ' cyjan-sev-derived' : ''}`}
      title={tooltip}
    >
      {sev}
      {derived && <span aria-hidden="true">*</span>}
    </span>
  );
}
