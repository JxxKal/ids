import { useCallback, useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
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
const TOOLTIP_MAX_WIDTH = 340;
const TOOLTIP_ESTIMATED_HEIGHT = 120;

/**
 * Wrapper der Children im Help-Mode mit dashed-outline + Hover-Tooltip versieht.
 * Außerhalb des Help-Modes ist das Element unsichtbar transparent (rendert nur
 * children).
 *
 * Tooltip wird per Portal an document.body gerendert, damit transformed
 * Ancestors die fixed-Positionierung nicht kapern.
 */
export function HelpTip({ helpKey, children, className, block, variant = 'outline' }: Props) {
  const { helpMode } = useHelpMode();
  const { t } = useTranslation();
  const [open, setOpen] = useState(false);
  const [pos, setPos] = useState<{ top: number; left: number } | null>(null);
  const wrapRef = useRef<HTMLDivElement | null>(null);

  // Position synchron berechnen, bevor das Tooltip gerendert wird.
  const computePos = useCallback(() => {
    if (!wrapRef.current) return null;
    const rect = wrapRef.current.getBoundingClientRect();
    let top = rect.bottom + TOOLTIP_OFFSET;
    let left = rect.left;
    if (left + TOOLTIP_MAX_WIDTH > window.innerWidth - 16) {
      left = Math.max(16, window.innerWidth - TOOLTIP_MAX_WIDTH - 16);
    }
    if (top + TOOLTIP_ESTIMATED_HEIGHT > window.innerHeight - 16) {
      // Nicht genug Platz unten → Tooltip oberhalb anzeigen.
      top = Math.max(16, rect.top - TOOLTIP_OFFSET - TOOLTIP_ESTIMATED_HEIGHT);
    }
    return { top, left };
  }, []);

  // Wenn helpMode aus geht → schließen und pos zurücksetzen.
  useEffect(() => {
    if (!helpMode) {
      setOpen(false);
      setPos(null);
    }
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

  const showTip = () => {
    const p = computePos();
    if (p) {
      setPos(p);
      setOpen(true);
    }
  };
  const hideTip = () => setOpen(false);
  const onClick = (e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (open) hideTip(); else showTip();
  };

  return (
    <div
      ref={wrapRef}
      style={wrapperStyle}
      className={`relative ${outline} cursor-help ${className ?? ''}`}
      onMouseEnter={showTip}
      onMouseLeave={hideTip}
      onClick={onClick}
    >
      {/* Children werden klick-inaktiv gemacht, damit der Hover/Click immer
          den Tooltip auslöst, statt die normale Funktion. */}
      <div style={{ pointerEvents: 'none' }}>{children}</div>

      {open && pos && createPortal(
        <div
          role="tooltip"
          style={{
            position: 'fixed',
            top: pos.top,
            left: pos.left,
            maxWidth: TOOLTIP_MAX_WIDTH,
            zIndex: 10000,
          }}
          className="px-3 py-2 rounded bg-slate-900 border border-cyan-500/70 text-xs leading-relaxed text-slate-100 shadow-xl shadow-cyan-900/40 pointer-events-none"
        >
          {text}
        </div>,
        document.body,
      )}
    </div>
  );
}
