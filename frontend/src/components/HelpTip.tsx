import { useEffect, useRef, useState } from 'react';
import type { CSSProperties, ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useHelpMode } from '../hooks/useHelpMode';

interface Props {
  helpKey: string;                 // i18n-Key unter help.dashboard.*
  children: ReactNode;
  className?: string;              // optionale Wrapper-Klasse (Layout)
  block?: boolean;                 // true: display:block, sonst inline-block
  variant?: 'outline' | 'badge';   // Visualstil im Help-Mode
}

const TOOLTIP_OFFSET = 8;
const TOOLTIP_MAX_WIDTH = 320;

/**
 * Wrapper der Children im Help-Mode mit dashed-outline + Hover-Tooltip versieht.
 * Außerhalb des Help-Modes ist das Element unsichtbar transparent (rendert nur
 * children).
 *
 * Während Help-Mode aktiv ist:
 *  - Klicks auf das gewrappte Element werden unterdrückt (keine Aktion)
 *  - Hover/Click zeigt einen Tooltip mit i18n-Text aus help.dashboard.<helpKey>
 */
export function HelpTip({ helpKey, children, className, block, variant = 'outline' }: Props) {
  const { helpMode } = useHelpMode();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  // Im Help-Mode: Tooltip-Position relativ zur Anchor-Box berechnen, damit
  // er nicht aus dem Viewport rutscht. Wird bei jedem Open neu berechnet.
  useEffect(() => {
    if (!open || !wrapRef.current) return;
    const rect = wrapRef.current.getBoundingClientRect();
    let top = rect.bottom + TOOLTIP_OFFSET;
    let left = rect.left;
    if (left + TOOLTIP_MAX_WIDTH > window.innerWidth - 16) {
      left = Math.max(16, window.innerWidth - TOOLTIP_MAX_WIDTH - 16);
    }
    if (top + 100 > window.innerHeight - 16) {
      top = Math.max(16, rect.top - TOOLTIP_OFFSET - 100);
    }
    setPos({ top, left });
  }, [open]);

  // Wenn helpMode aus geht während Tooltip offen war → schließen.
  useEffect(() => {
    if (!helpMode) setOpen(false);
  }, [helpMode]);

  if (!helpMode) {
    return <>{children}</>;
  }

  const text = t(`help.dashboard.${helpKey}`, { defaultValue: helpKey });
  const wrapperStyle: CSSProperties = block ? {} : { display: 'inline-block' };
  const outline =
    variant === 'badge'
      ? 'ring-2 ring-cyan-400/60 ring-offset-2 ring-offset-slate-950 rounded-md'
      : 'outline outline-2 outline-dashed outline-cyan-400/70 outline-offset-[3px] rounded';

  const onClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setOpen(o => !o);
  };

  return (
    <div
      ref={wrapRef}
      style={wrapperStyle}
      className={`relative ${outline} cursor-help ${className ?? ''}`}
      onMouseEnter={() => setOpen(true)}
      onMouseLeave={() => setOpen(false)}
      onClick={onClick}
    >
      {/* Children werden klick-inaktiv gemacht, damit der Hover/Click immer
          den Tooltip auslöst, statt die normale Funktion. */}
      <div style={{ pointerEvents: 'none' }}>{children}</div>

      {open && pos && (
        <div
          className="fixed z-[1000] px-3 py-2 rounded bg-slate-900 border border-cyan-500/60 text-xs text-slate-100 shadow-xl shadow-cyan-900/40"
          style={{ top: pos.top, left: pos.left, maxWidth: TOOLTIP_MAX_WIDTH }}
          onMouseEnter={() => setOpen(true)}
          onMouseLeave={() => setOpen(false)}
        >
          {text}
        </div>
      )}
    </div>
  );
}
