import { HelpCircle, LogOut } from 'lucide-react';
import { useTranslation } from 'react-i18next';
import { useHelpMode } from '../hooks/useHelpMode';
import { HelpTip } from './HelpTip';

interface Kpi {
  label: string;
  value: string;
  color?: string;
}

interface Props {
  title: string;
  live: boolean;
  kpis?: Kpi[];
  username: string;
  onLogout: () => void;
}

export function TopBar({ title, live, kpis = [], username, onLogout }: Props) {
  const { t } = useTranslation();
  const { helpMode, toggle: toggleHelp } = useHelpMode();
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
      </div>

      <div className="cyjan-topbar-right">
        {kpis.length > 0 && (
          <HelpTip helpKey="topbarKpi">
            <div style={{ display: 'flex', gap: '0.75rem' }}>
              {kpis.map(k => (
                <div key={k.label} className="cyjan-kpi">
                  <div className="cyjan-kpi-label">{k.label}</div>
                  <div className="cyjan-kpi-value" style={k.color ? { color: k.color } : undefined}>
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
