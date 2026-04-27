import { useTranslation } from 'react-i18next';

interface Props {
  trusted: boolean;
  source?: string | null;
  size?: 'xs' | 'sm';
}

export function TrustBadge({ trusted, source, size = 'xs' }: Props) {
  const { t } = useTranslation();
  const cls = size === 'xs' ? 'px-1 py-0.5 text-xs rounded' : 'px-1.5 py-1 text-xs rounded';

  if (trusted) {
    const label = source
      ? t(`trust.sources.${source}`, { defaultValue: source })
      : t('trust.knownLabel');
    return (
      <span className={`${cls} bg-green-900/40 text-green-400 border border-green-700/40`}>
        ✓ {label}
      </span>
    );
  }
  return (
    <span className={`${cls} bg-yellow-900/40 text-yellow-400 border border-yellow-700/40`}>
      ? {t('trust.unknownLabel')}
    </span>
  );
}
