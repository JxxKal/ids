export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`badge-${severity} px-1.5 py-0.5 rounded text-xs font-medium`}>
      {severity}
    </span>
  );
}
