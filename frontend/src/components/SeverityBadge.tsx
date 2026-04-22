export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`cyjan-sev-badge cyjan-sev-${severity}`}>
      {severity}
    </span>
  );
}
