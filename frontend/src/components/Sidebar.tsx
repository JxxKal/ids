import { FlaskConical, LayoutDashboard, Network, Server, Settings } from 'lucide-react';
import type { ReactNode } from 'react';

export type NavTab = 'dashboard' | 'networks' | 'hosts' | 'tests' | 'settings';

interface Props {
  active: NavTab;
  onNav: (tab: NavTab) => void;
  username: string;
}

const ITEMS: { id: NavTab; label: string; icon: ReactNode }[] = [
  { id: 'dashboard', label: 'Dashboard',    icon: <LayoutDashboard size={16} strokeWidth={1.8} /> },
  { id: 'networks',  label: 'Netzwerke',    icon: <Network         size={16} strokeWidth={1.8} /> },
  { id: 'hosts',     label: 'Hosts',        icon: <Server          size={16} strokeWidth={1.8} /> },
  { id: 'tests',     label: 'Szenarien',    icon: <FlaskConical    size={16} strokeWidth={1.8} /> },
  { id: 'settings',  label: 'Einstellungen',icon: <Settings        size={16} strokeWidth={1.8} /> },
];

export function Sidebar({ active, onNav, username }: Props) {
  return (
    <aside className="cyjan-sidebar">
      <div className="cyjan-sidebar-brand">
        <img src="/cyjan_logo_compact.svg" alt="" className="cyjan-sidebar-logo" />
        <div className="cyjan-sidebar-wordmark">
          CY<span>JAN</span>
        </div>
      </div>

      <nav className="cyjan-sidebar-nav">
        {ITEMS.map(item => {
          const isActive = active === item.id;
          return (
            <button
              key={item.id}
              type="button"
              onClick={() => onNav(item.id)}
              className={`cyjan-sidebar-item ${isActive ? 'is-active' : ''}`}
            >
              <span className="cyjan-sidebar-icon">{item.icon}</span>
              {item.label}
            </button>
          );
        })}
      </nav>

      <div className="cyjan-sidebar-footer">
        {username}@cyjan · v1.0
      </div>
    </aside>
  );
}
