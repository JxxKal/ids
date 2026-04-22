import { LogOut } from 'lucide-react';

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
  return (
    <div className="cyjan-topbar">
      <div className="cyjan-topbar-left">
        <h1 className="cyjan-topbar-title">{title}</h1>
        <span className={`cyjan-live-badge ${live ? 'is-live' : 'is-offline'}`}>
          <span className="cyjan-live-dot" />
          {live ? 'Live' : 'Offline'}
        </span>
      </div>

      <div className="cyjan-topbar-right">
        {kpis.map(k => (
          <div key={k.label} className="cyjan-kpi">
            <div className="cyjan-kpi-label">{k.label}</div>
            <div className="cyjan-kpi-value" style={k.color ? { color: k.color } : undefined}>
              {k.value}
            </div>
          </div>
        ))}

        <div className="cyjan-topbar-user">
          <span className="cyjan-topbar-username">{username}</span>
          <button
            type="button"
            onClick={onLogout}
            title="Abmelden"
            className="cyjan-topbar-logout"
          >
            <LogOut size={14} />
          </button>
        </div>
      </div>
    </div>
  );
}
