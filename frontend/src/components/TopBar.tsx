import { HelpCircle, LogOut } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useHelpMode } from '../hooks/useHelpMode';
import { HelpTip } from './HelpTip';
import type { RemoteTap } from '../types';

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
