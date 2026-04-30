import { useTranslation } from 'react-i18next';

/**
 * ML-Pipeline-Diagramm als sprachgesteuerte SVG-Komponente.
 * Ersetzt das frühere ml-flow.png — Texte kommen aus i18n
 * (settings.mlOverview.diagram.labels.*), Layout ist 1:1 vom Original
 * übernommen (cyan Boxen für Signature-Path, amber für ML, violet für
 * Suppression-Gateway, slate für Persistenz).
 *
 * viewBox-skalierbar, klassische Cyjankali-Farbpalette.
 */
export function MlFlowDiagram() {
  const { t } = useTranslation();
  const L = (key: string) => t(`settings.mlOverview.diagram.labels.${key}`);

  // Farbpalette (matched mit cyjan-sev-* + Tailwind-Tokens)
  const COL = {
    sigStroke:   '#22d3ee',  // cyan-400 — Signatur-Pfad
    sigFill:     'rgba(8, 51, 68, 0.65)',
    sigText:     '#67e8f9',
    mlStroke:    '#fbbf24',  // amber-400 — ML-Pfad
    mlFill:      'rgba(69, 26, 3, 0.65)',
    mlText:      '#fcd34d',
    gwStroke:    '#a78bfa',  // violet-400 — Gateway/Suppression
    gwFill:      'rgba(46, 16, 101, 0.50)',
    gwText:      '#c4b5fd',
    dbStroke:    '#94a3b8',  // slate-400 — Persistenz
    dbFill:      'rgba(15, 23, 42, 0.85)',
    dbText:      '#cbd5e1',
    skipBg:      'rgba(120, 53, 15, 0.55)',
    skipText:    '#fdba74',
    activeBg:    'rgba(127, 29, 29, 0.55)',
    activeText:  '#fca5a5',
    legendText:  '#94a3b8',
    bg:          '#0b1220',
  };

  return (
    <svg
      viewBox="0 0 760 460"
      role="img"
      aria-label={t('settings.mlOverview.diagram.title')}
      className="w-full max-w-3xl mx-auto rounded border border-slate-800/60"
      style={{ background: COL.bg }}
    >
      {/* Marker-Definitions für Pfeile */}
      <defs>
        <marker id="arr-cyan" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
          <path d="M0,0 L10,5 L0,10 Z" fill={COL.sigStroke} />
        </marker>
        <marker id="arr-amber" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
          <path d="M0,0 L10,5 L0,10 Z" fill={COL.mlStroke} />
        </marker>
        <marker id="arr-violet" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
          <path d="M0,0 L10,5 L0,10 Z" fill={COL.gwStroke} />
        </marker>
        <marker id="arr-slate" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto">
          <path d="M0,0 L10,5 L0,10 Z" fill={COL.dbText} opacity="0.6" />
        </marker>
      </defs>

      {/* ─────────── Top-Reihe: Source → Signature → Queue ─────────── */}
      {/* SOURCE / flow-aggregator */}
      <g>
        <rect x="20" y="40" width="180" height="60" rx="8" fill={COL.sigFill} stroke={COL.sigStroke} strokeWidth="1.5" />
        <text x="35" y="60" fontSize="9" fontFamily="monospace" fill={COL.sigText} opacity="0.7">{L('source')}</text>
        <text x="35" y="82" fontSize="14" fontFamily="monospace" fill={COL.sigText} fontWeight="600">flow-aggregator</text>
      </g>

      {/* SIGNATURE / signature-engine */}
      <g>
        <rect x="280" y="40" width="200" height="60" rx="8" fill={COL.sigFill} stroke={COL.sigStroke} strokeWidth="1.5" />
        <text x="295" y="60" fontSize="9" fontFamily="monospace" fill={COL.sigText} opacity="0.7">{L('signature')}</text>
        <text x="295" y="82" fontSize="14" fontFamily="monospace" fill={COL.sigText} fontWeight="600">signature-engine</text>
      </g>

      {/* QUEUE / alerts-raw */}
      <g>
        <rect x="560" y="40" width="180" height="60" rx="8" fill={COL.sigFill} stroke={COL.sigStroke} strokeWidth="1.5" />
        <text x="575" y="60" fontSize="9" fontFamily="monospace" fill={COL.sigText} opacity="0.7">{L('queue')}</text>
        <text x="575" y="82" fontSize="14" fontFamily="monospace" fill={COL.sigText} fontWeight="600">alerts-raw</text>
      </g>

      {/* Top-Pfeile: durchgezogen, cyan */}
      <line x1="200" y1="70" x2="280" y2="70" stroke={COL.sigStroke} strokeWidth="1.5" markerEnd="url(#arr-cyan)" />
      <line x1="480" y1="70" x2="560" y2="70" stroke={COL.sigStroke} strokeWidth="1.5" markerEnd="url(#arr-cyan)" />

      {/* ─────────── Mitte: ANOMALY / ML-Engine ─────────── */}
      <g>
        <rect x="280" y="150" width="200" height="70" rx="8" fill={COL.mlFill} stroke={COL.mlStroke} strokeWidth="1.5" />
        <text x="295" y="170" fontSize="9" fontFamily="monospace" fill={COL.mlText} opacity="0.7">{L('anomaly')}</text>
        <text x="295" y="192" fontSize="14" fontFamily="monospace" fill={COL.mlText} fontWeight="600">ML-Engine</text>
        <text x="295" y="210" fontSize="11" fontFamily="monospace" fill={COL.mlText} opacity="0.7">IsolationForest</text>
      </g>

      {/* flow-aggregator → ML-Engine: gestrichelt, amber, runter und nach rechts */}
      <path d="M 110 100 L 110 185 L 280 185" fill="none" stroke={COL.mlStroke}
            strokeWidth="1.5" strokeDasharray="5,4" markerEnd="url(#arr-amber)" />

      {/* ─────────── Gateway: alert-manager ─────────── */}
      <g>
        <rect x="220" y="270" width="320" height="80" rx="10" fill={COL.gwFill} stroke={COL.gwStroke} strokeWidth="1.5" />
        <text x="240" y="290" fontSize="9" fontFamily="monospace" fill={COL.gwText} opacity="0.7">{L('gateway')}</text>
        <text x="240" y="313" fontSize="15" fontFamily="monospace" fill={COL.gwText} fontWeight="600">alert-manager</text>
        <text x="240" y="332" fontSize="10" fontFamily="monospace" fill={COL.gwText} opacity="0.65">{L('gatewayDetail')}</text>
      </g>

      {/* ML-Engine → alert-manager: gestrichelt, amber */}
      <line x1="380" y1="220" x2="380" y2="270" stroke={COL.mlStroke}
            strokeWidth="1.5" strokeDasharray="5,4" markerEnd="url(#arr-amber)" />

      {/* alerts-raw → alert-manager: durchgezogen, cyan */}
      <path d="M 650 100 L 650 250 L 540 250 L 540 270" fill="none" stroke={COL.sigStroke}
            strokeWidth="1.5" markerEnd="url(#arr-cyan)" />

      {/* ─────────── Persistenz: alerts (DB) ─────────── */}
      <g>
        <rect x="600" y="280" width="140" height="60" rx="8" fill={COL.dbFill} stroke={COL.dbStroke} strokeWidth="1.5" />
        <text x="615" y="300" fontSize="9" fontFamily="monospace" fill={COL.dbText} opacity="0.7">{L('persistence')}</text>
        <text x="615" y="322" fontSize="14" fontFamily="monospace" fill={COL.dbText} fontWeight="600">alerts (DB)</text>
      </g>

      {/* alert-manager → DB: durchgezogen, violet */}
      <line x1="540" y1="310" x2="600" y2="310" stroke={COL.gwStroke}
            strokeWidth="1.5" markerEnd="url(#arr-violet)" />

      {/* DB → ML-Engine: Feedback-Loop, gestrichelt, dezent */}
      <path d="M 670 280 L 670 240 L 480 240 L 480 220" fill="none" stroke={COL.dbText}
            strokeWidth="1" strokeDasharray="2,4" opacity="0.55" markerEnd="url(#arr-slate)" />

      {/* ─────────── Suppression-Pills ─────────── */}
      <g>
        <rect x="240" y="375" width="135" height="22" rx="11" fill={COL.skipBg} stroke={COL.mlStroke} strokeWidth="0.8" opacity="0.85" />
        <circle cx="252" cy="386" r="3" fill={COL.skipText} />
        <text x="262" y="390" fontSize="10" fontFamily="monospace" fill={COL.skipText}>{L('suppressSkip')}</text>
      </g>
      <g>
        <rect x="395" y="375" width="145" height="22" rx="11" fill={COL.activeBg} stroke="#dc2626" strokeWidth="0.8" opacity="0.85" />
        <circle cx="407" cy="386" r="3" fill={COL.activeText} />
        <text x="417" y="390" fontSize="10" fontFamily="monospace" fill={COL.activeText}>{L('suppressActive')}</text>
      </g>

      {/* ─────────── Legende unten ─────────── */}
      <g transform="translate(20, 425)">
        {/* Signatur-Pfad */}
        <line x1="0" y1="6" x2="30" y2="6" stroke={COL.sigStroke} strokeWidth="1.5" />
        <text x="38" y="10" fontSize="10" fontFamily="monospace" fill={COL.legendText}>{L('legendSig')}</text>

        {/* ML-Pfad */}
        <line x1="160" y1="6" x2="190" y2="6" stroke={COL.mlStroke} strokeWidth="1.5" strokeDasharray="5,4" />
        <text x="198" y="10" fontSize="10" fontFamily="monospace" fill={COL.legendText}>{L('legendMl')}</text>

        {/* Feedback / Retrain */}
        <line x1="290" y1="6" x2="320" y2="6" stroke={COL.dbText} strokeWidth="1" strokeDasharray="2,4" opacity="0.6" />
        <text x="328" y="10" fontSize="10" fontFamily="monospace" fill={COL.legendText}>{L('legendFeedback')}</text>
      </g>
    </svg>
  );
}
