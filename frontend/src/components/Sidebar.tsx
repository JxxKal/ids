import { FlaskConical, LayoutDashboard, Network, Server, Settings } from 'lucide-react';
import { useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { fetchVersion } from '../api';

export type NavTab = 'dashboard' | 'networks' | 'hosts' | 'tests' | 'settings';

interface Props {
  active: NavTab;
  onNav: (tab: NavTab) => void;
  username: string;
}

const ITEMS: { id: NavTab; icon: ReactNode }[] = [
  { id: 'dashboard', icon: <LayoutDashboard size={16} strokeWidth={1.8} /> },
  { id: 'networks',  icon: <Network         size={16} strokeWidth={1.8} /> },
  { id: 'hosts',     icon: <Server          size={16} strokeWidth={1.8} /> },
  { id: 'tests',     icon: <FlaskConical    size={16} strokeWidth={1.8} /> },
  { id: 'settings',  icon: <Settings        size={16} strokeWidth={1.8} /> },
];

export function Sidebar({ active, onNav, username }: Props) {
  const { t } = useTranslation();
  const [version, setVersion] = useState<string | null>(null);
  useEffect(() => {
    let cancelled = false;
    fetchVersion()
      .then(r => { if (!cancelled) setVersion(r.version); })
      .catch(() => {});
    return () => { cancelled = true; };
  }, []);

  return (
    <aside className="cyjan-sidebar">
      <div className="cyjan-sidebar-brand">
        <img src="/cyjan_logo_cyan_max.svg" alt="" className="cyjan-sidebar-logo" />
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
              {t(`sidebar.${item.id}`)}
            </button>
          );
        })}
      </nav>

      <div className="cyjan-sidebar-footer">
        {t('sidebar.footer', { username, version: version ?? '…' })}
      </div>
    </aside>
  );
}
