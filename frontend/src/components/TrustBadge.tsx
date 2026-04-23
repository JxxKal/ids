const SOURCE_LABEL: Record<string, string> = {
  dns:    'DNS',
  csv:    'CSV',
  manual: 'Manuell',
  cmdb:   'iTop/CMDB',
};

interface Props {
  trusted: boolean;
  source?: string | null;
  size?: 'xs' | 'sm';
}

export function TrustBadge({ trusted, source, size = 'xs' }: Props) {
  const cls = size === 'xs' ? 'px-1 py-0.5 text-xs rounded' : 'px-1.5 py-1 text-xs rounded';

  if (trusted) {
    return (
      <span className={`${cls} bg-green-900/40 text-green-400 border border-green-700/40`}>
        ✓ {source ? SOURCE_LABEL[source] ?? source : 'Bekannt'}
      </span>
    );
  }
  return (
    <span className={`${cls} bg-yellow-900/40 text-yellow-400 border border-yellow-700/40`}>
      ? Unbekannt
    </span>
  );
}
