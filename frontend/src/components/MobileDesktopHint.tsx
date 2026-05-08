import { Info, X } from 'lucide-react';
import { useState } from 'react';
import { useTranslation } from 'react-i18next';

const STORAGE_KEY = 'cyjan:mobileHintDismissed';

// Kleiner Hinweis-Banner, der auf Mobile (<768px) eingeblendet wird:
// "diese Sektion ist für Desktop optimiert". Dismissable — beim Klick auf
// das ✕ wird ein Flag in localStorage gesetzt und der Banner taucht in
// keiner Section mehr auf (User hat verstanden, will nicht mehr genervt
// werden). Verwendung: oben in Pages, die Form-/Tabellen-heavy sind.
export function MobileDesktopHint() {
  const { t } = useTranslation();
  const [dismissed, setDismissed] = useState(() => {
    try {
      return typeof window !== 'undefined' && localStorage.getItem(STORAGE_KEY) === '1';
    } catch {
      return false;
    }
  });

  if (dismissed) return null;

  function dismiss() {
    setDismissed(true);
    try {
      localStorage.setItem(STORAGE_KEY, '1');
    } catch { /* localStorage gesperrt — nur in-memory-state */ }
  }

  return (
    <div className="md:hidden mb-3 px-3 py-2 rounded border border-amber-700/40 bg-amber-950/30 text-amber-300 text-[11px] flex items-start gap-2 leading-snug">
      <Info size={14} className="shrink-0 mt-0.5" />
      <span className="flex-1">{t('common.mobileDesktopHint')}</span>
      <button
        type="button"
        onClick={dismiss}
        title={t('common.mobileHintDismiss', { defaultValue: 'Hinweis ausblenden' })}
        aria-label={t('common.mobileHintDismiss', { defaultValue: 'Hinweis ausblenden' })}
        className="shrink-0 -mr-1 -mt-0.5 p-1 rounded hover:bg-amber-900/40 text-amber-400 hover:text-amber-200 transition-colors"
      >
        <X size={14} />
      </button>
    </div>
  );
}
