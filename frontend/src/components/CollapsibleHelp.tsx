import { ChevronDown } from 'lucide-react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';

// Wrapper für lange Erklärtexte in Settings-Sections. Auf Desktop ist der
// Hilfetext direkt sichtbar (Power-Admin-Workflow), auf <768px wird er in
// ein <details>-Element gewickelt und ist standardmäßig zugeklappt — sonst
// fressen 8–12 Zeilen Beschreibung den ganzen oberen Bildschirm, bevor man
// irgendeine Eingabe sieht. User klickt "Was macht das hier?" zum Aufklappen.
export function CollapsibleHelp({ children }: { children: ReactNode }) {
  const { t } = useTranslation();
  return (
    <>
      {/* Desktop: direkt anzeigen */}
      <div className="hidden md:block">{children}</div>

      {/* Mobile: collapsable */}
      <details className="md:hidden mb-2 group">
        <summary className="cursor-pointer list-none flex items-center gap-1.5 text-[11px] text-slate-500 hover:text-slate-300 select-none py-1">
          <ChevronDown size={12} className="transition-transform group-open:rotate-180" />
          <span>{t('common.helpToggle', { defaultValue: 'Was macht das hier?' })}</span>
        </summary>
        <div className="mt-1.5">{children}</div>
      </details>
    </>
  );
}
