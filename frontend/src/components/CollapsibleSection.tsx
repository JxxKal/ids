// ── CollapsibleSection — Card-Wrapper mit Ein-/Ausklapp-Header ──────────────
//
// Speichert den Open-State pro storageKey in localStorage. Header bleibt
// klickbar in beiden Zuständen; Content wird per CSS gehidet (display:none),
// damit React-State + ScrollPosition der Inputs beim Wieder-Öffnen erhalten
// bleiben (alternative wäre conditional-render, würde aber die Form-State
// resetten).

import { useEffect, useState, type ReactNode } from 'react';


export function CollapsibleSection({
  storageKey, title, subtitle, titleClass = 'text-slate-200', defaultOpen = true, children,
}: {
  storageKey:   string;
  title:        ReactNode;
  subtitle?:    ReactNode;
  titleClass?:  string;
  defaultOpen?: boolean;
  children:     ReactNode;
}) {
  const [open, setOpen] = useState<boolean>(() => {
    if (typeof window === 'undefined') return defaultOpen;
    const stored = localStorage.getItem(storageKey);
    return stored === null ? defaultOpen : stored === 'true';
  });

  useEffect(() => {
    try { localStorage.setItem(storageKey, String(open)); }
    catch { /* localStorage disabled — silent */ }
  }, [open, storageKey]);

  return (
    <div className="card p-4">
      <button
        type="button"
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-baseline justify-between gap-2 flex-wrap text-left -mx-1 px-1 rounded hover:bg-slate-800/30 transition-colors"
        aria-expanded={open}
      >
        <h2 className={`text-sm font-semibold ${titleClass}`}>{title}</h2>
        <div className="flex items-center gap-3 flex-wrap text-[11px] text-slate-500">
          {subtitle}
          <span className="text-slate-500 text-xs select-none w-3 text-center" aria-hidden="true">
            {open ? '▼' : '▶'}
          </span>
        </div>
      </button>
      <div className={open ? 'mt-3' : 'hidden'}>
        {children}
      </div>
    </div>
  );
}
