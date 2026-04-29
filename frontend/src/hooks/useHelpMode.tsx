import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';

interface HelpModeContextValue {
  helpMode: boolean;
  toggle: () => void;
  setHelpMode: (v: boolean) => void;
}

const HelpModeContext = createContext<HelpModeContextValue | null>(null);

export function HelpModeProvider({ children }: { children: ReactNode }) {
  const [helpMode, setHelpMode] = useState(false);

  const toggle = useCallback(() => setHelpMode(v => !v), []);

  // ESC verlässt den Help-Mode wieder – sonst klebt der Modus, wenn man
  // zwischendurch in Modal/Drawer-Flows wechselt.
  useEffect(() => {
    if (!helpMode) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') setHelpMode(false);
    };
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [helpMode]);

  const value = useMemo<HelpModeContextValue>(
    () => ({ helpMode, toggle, setHelpMode }),
    [helpMode, toggle],
  );

  return <HelpModeContext.Provider value={value}>{children}</HelpModeContext.Provider>;
}

export function useHelpMode(): HelpModeContextValue {
  const ctx = useContext(HelpModeContext);
  if (!ctx) {
    // Defensiv: Komponenten ohne Provider (z.B. Storybook/Tests) bekommen
    // einfach einen No-Op-Modus zurück, statt zu crashen.
    return { helpMode: false, toggle: () => {}, setHelpMode: () => {} };
  }
  return ctx;
}
