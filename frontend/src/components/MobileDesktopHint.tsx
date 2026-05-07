import { Info } from 'lucide-react';
import { useTranslation } from 'react-i18next';

// Kleiner Hinweis-Banner, der auf Mobile (<768px) eingeblendet wird:
// "diese Sektion ist für Desktop optimiert". Kein Hard-Block — der User
// soll die Seite trotzdem benutzen können, nur mit gemanagter Erwartung.
// Verwendung: oben in Pages, die Form-/Tabellen-heavy sind und nicht
// Phase-1-responsive gemacht wurden (Settings, Networks, Tests).
export function MobileDesktopHint() {
  const { t } = useTranslation();
  return (
    <div className="md:hidden mb-3 px-3 py-2 rounded border border-amber-700/40 bg-amber-950/30 text-amber-300 text-[11px] flex items-start gap-2 leading-snug">
      <Info size={14} className="shrink-0 mt-0.5" />
      <span>{t('common.mobileDesktopHint')}</span>
    </div>
  );
}
