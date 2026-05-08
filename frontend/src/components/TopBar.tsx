import { HelpCircle, LogOut } from 'lucide-react';
import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchThreatLevel } from '../api';
import { useHelpMode } from '../hooks/useHelpMode';
import { HelpTip } from './HelpTip';
import type { RemoteTap, ThreatLevel } from '../types';

// Mini-Threat-Donut für die TopBar — zeigt den aktuellen Threat-Score
// als kleinen Donut + Score, sichtbar auf allen Tabs (nicht nur
// Dashboard). Operator sieht "wie kritisch ist es gerade" auch beim
// Konfigurieren von Settings, Schauen auf Hosts etc. — Brand-Klammer.
const STATUS_COLOR: Record<string, string> = {
  green:  '#22c55e',
  yellow: '#eab308',
  orange: '#f97316',
  red:    '#ef4444',
};
function MiniThreat() {
  const { t } = useTranslation();
  const [data, setData] = useState<ThreatLevel | null>(null);
  useEffect(() => {
    const load = () => fetchThreatLevel().then(setData).catch(() => {});
    load();
    const id = setInterval(load, 30_000);
    return () => clearInterval(id);
  }, []);
  if (!data) return null;
  const value = Math.max(0, Math.min(100, data.level));
  const color = STATUS_COLOR[data.label] ?? STATUS_COLOR.green;
  const circ = 2 * Math.PI * 9;
  const offset = circ - (value / 100) * circ;
  const isCritical = data.label === 'red';
  return (
    <div
      className="flex items-center gap-1.5 px-2 py-1 rounded border font-mono text-[11px] cyjan-tabular shrink-0"
      style={{
        borderColor: data.label === 'red' ? 'rgba(239,68,68,0.45)'
                   : data.label === 'orange' ? 'rgba(249,115,22,0.40)'
                   : 'rgba(34,211,238,0.25)',
        background: 'rgba(11,18,32,0.6)',
        animation: isCritical ? 'cyjan-pulse-dot 2.4s ease-in-out infinite' : undefined,
      }}
      title={t('threatGauge.title', { minutes: data.window_min })}
    >
      <svg width="22" height="22" viewBox="0 0 22 22" className="shrink-0">
        <circle cx="11" cy="11" r="9" fill="none" stroke="#172033" strokeWidth="2" />
        <circle
          cx="11" cy="11" r="9" fill="none"
          stroke={color}
          strokeWidth="2"
          strokeDasharray={circ}
          strokeDashoffset={offset}
          strokeLinecap="round"
          transform="rotate(-90 11 11)"
          style={{
            transition: 'stroke-dashoffset 0.6s ease, stroke 0.3s ease',
            filter: `drop-shadow(0 0 2px ${color})`,
          }}
        />
      </svg>
      <span style={{ color, fontWeight: 700 }}>{value}</span>
    </div>
  );
}

interface Kpi {
  label: string;
  value: string;
  color?: string;
}

interface Props {
  title: string;
  live: boolean;
  kpis?: Kpi[];
  // Tap-Heartbeat-Badges: leer → keine Anzeige; pro Tap ein Badge mit
  // Name + Online-Status, abgeleitet aus last_seen.
  taps?: RemoteTap[];
  username: string;
  onLogout: () => void;
}

// Heartbeat-Schwelle: tap-uplink schickt regelmäßig Frames + Pings; der
// Master setzt last_seen bei jedem Frame neu. Wir betrachten den Tap als
// "live" wenn der letzte Kontakt < 90 s her ist (zwei verpasste Ping-
// Intervalle reichen, um aus 'live' rauszufallen — entlässt z.B. ein
// kurzes Reconnect ohne Alarm). 90–300 s = stale (Verbindung wackelt),
// danach offline.
const TAP_LIVE_THRESHOLD_MS  = 90_000;
const TAP_STALE_THRESHOLD_MS = 300_000;

type TapState = 'live' | 'stale' | 'offline' | 'never';

function tapState(tap: RemoteTap, nowMs: number): TapState {
  if (tap.status === 'revoked') return 'offline';
  if (!tap.last_seen) return 'never';
  const ageMs = nowMs - new Date(tap.last_seen).getTime();
  if (ageMs < TAP_LIVE_THRESHOLD_MS)  return 'live';
  if (ageMs < TAP_STALE_THRESHOLD_MS) return 'stale';
  return 'offline';
}

function fmtAge(lastSeen: string | null | undefined, nowMs: number): string {
  if (!lastSeen) return '—';
  const ageSec = Math.max(0, Math.floor((nowMs - new Date(lastSeen).getTime()) / 1000));
  if (ageSec < 60)    return `${ageSec}s`;
  if (ageSec < 3600)  return `${Math.floor(ageSec / 60)}m`;
  if (ageSec < 86400) return `${Math.floor(ageSec / 3600)}h`;
  return `${Math.floor(ageSec / 86400)}d`;
}

const TAP_BADGE_STYLE: Record<TapState, string> = {
  // Inline-Klassen statt globale CSS-Erweiterung — die TopBar war bisher das
  // einzige Stück mit cyjan-live-badge, ein neuer Status-Badge passt aber
  // visuell identisch wenn wir die gleiche Familie nutzen.
  live:    'bg-green-950/40 text-green-300 border-green-700/50',
  stale:   'bg-amber-950/40 text-amber-300 border-amber-700/50',
  offline: 'bg-red-950/40 text-red-300 border-red-700/50',
  never:   'bg-slate-800/60 text-slate-400 border-slate-600/40',
};

const TAP_DOT_STYLE: Record<TapState, string> = {
  live:    'bg-green-400 shadow-[0_0_5px_#4ade80]',
  stale:   'bg-amber-400',
  offline: 'bg-red-500',
  never:   'bg-slate-500',
};

export function TopBar({ title, live, kpis = [], taps = [], username, onLogout }: Props) {
  const { t } = useTranslation();
  const { helpMode, toggle: toggleHelp } = useHelpMode();
  const nowMs = Date.now();
  // Revokte Taps gehören aus dem Topbar raus — der Header zeigt den
  // operativen Live-Stand, revoked = end-of-life. Audit-Spur bleibt in
  // Settings → Remote Taps voll erhalten (dort sind auch revoked-Einträge
  // weiter sichtbar mit Datum/Begründung).
  const activeTaps = taps.filter(tap => tap.status !== 'revoked');
  return (
    <div className="cyjan-topbar">
      <div className="cyjan-topbar-left">
        <h1 className="cyjan-topbar-title">{title}</h1>
        <MiniThreat />
        <HelpTip helpKey="topbarLive">
          <span className={`cyjan-live-badge ${live ? 'is-live' : 'is-offline'}`}>
            <span className="cyjan-live-dot" />
            {live ? t('topbar.live') : t('topbar.offline')}
          </span>
        </HelpTip>
        {activeTaps.length > 0 && (
          <HelpTip helpKey="topbarTaps">
            <div className="flex items-center gap-1.5 ml-2">
              {activeTaps.map(tap => {
                const state = tapState(tap, nowMs);
                const age   = fmtAge(tap.last_seen, nowMs);
                const tip   = state === 'never'
                  ? t('topbar.tap.never', { name: tap.name, defaultValue: '{{name}}: noch keinen Kontakt seit Pairing' })
                  : t(`topbar.tap.${state}Title`, { name: tap.name, age, defaultValue: '{{name}} · letzter Kontakt {{age}}' });
                return (
                  <span
                    key={tap.id}
                    title={tip}
                    className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-[11px] font-mono border cursor-help ${TAP_BADGE_STYLE[state]}`}
                  >
                    <span className={`w-1.5 h-1.5 rounded-full inline-block ${TAP_DOT_STYLE[state]}`} />
                    {tap.name}
                    {state !== 'never' && (
                      <span className="opacity-60 text-[10px]">{age}</span>
                    )}
                  </span>
                );
              })}
            </div>
          </HelpTip>
        )}
      </div>

      <div className="cyjan-topbar-right">
        {kpis.length > 0 && (
          <HelpTip helpKey="topbarKpi">
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              {kpis.map(k => (
                <div key={k.label} className="cyjan-kpi">
                  <div className="cyjan-kpi-label">{k.label}</div>
                  <div className="cyjan-kpi-value cyjan-tabular" style={k.color ? { color: k.color } : undefined}>
                    {k.value}
                  </div>
                </div>
              ))}
            </div>
          </HelpTip>
        )}

        <button
          type="button"
          onClick={toggleHelp}
          title={helpMode ? t('topbar.helpOff') : t('topbar.helpOn')}
          aria-pressed={helpMode}
          className={`cyjan-topbar-logout ${helpMode ? 'is-active' : ''}`}
          style={
            helpMode
              ? { background: 'rgba(34,211,238,0.15)', color: '#67e8f9', borderColor: '#22d3ee' }
              : undefined
          }
        >
          <HelpCircle size={14} />
        </button>

        <HelpTip helpKey="topbarLogout">
          <div className="cyjan-topbar-user">
            <span className="cyjan-topbar-username">{username}</span>
            <button
              type="button"
              onClick={onLogout}
              title={t('topbar.logout')}
              className="cyjan-topbar-logout"
            >
              <LogOut size={14} />
            </button>
          </div>
        </HelpTip>
      </div>
    </div>
  );
}
