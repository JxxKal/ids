import { useState } from 'react';
import { AlertFeed } from './components/AlertFeed';
import { NetworksPage } from './components/NetworksPage';
import { TestsPage } from './components/TestsPage';
import { ThreatGauge } from './components/ThreatGauge';
import { useWebSocket } from './hooks/useWebSocket';
import type { Alert } from './types';

type Tab = 'dashboard' | 'networks' | 'tests';

const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'networks',  label: 'Netzwerke' },
  { id: 'tests',     label: 'Tests' },
];

export default function App() {
  const [tab, setTab]         = useState<Tab>('dashboard');
  const [showTest, setShowTest] = useState(false);
  const { alerts, connected, setAlerts } = useWebSocket();

  const handleUpdate = (updated: Alert) => {
    setAlerts(prev => prev.map(a => a.alert_id === updated.alert_id ? updated : a));
  };

  return (
    <div className="min-h-screen flex flex-col">
      {/* Header */}
      <header className="bg-slate-900 border-b border-slate-800 px-4 py-3 flex items-center gap-4">
        <div className="flex items-center gap-2 mr-2">
          <span className="text-base font-bold text-slate-100">IDS</span>
          <span className="text-slate-600 text-xs">Dashboard</span>
        </div>

        {/* Tabs */}
        <nav className="flex gap-1">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                tab === t.id
                  ? 'bg-slate-700 text-slate-100'
                  : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800'
              }`}
            >
              {t.label}
            </button>
          ))}
        </nav>

        <div className="flex-1" />

        {/* Threat Gauge */}
        <ThreatGauge />

        {/* WS Status */}
        <div className="flex items-center gap-1.5 text-xs">
          <span
            className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`}
          />
          <span className="text-slate-500">{connected ? 'Live' : 'Verbinde…'}</span>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 overflow-hidden p-4">
        {tab === 'dashboard' && (
          <div className="h-full flex flex-col gap-3">
            <div className="flex items-center gap-3">
              <span className="text-xs text-slate-500">
                {alerts.filter(a => !a.is_test).length} Alerts
              </span>
              <label className="flex items-center gap-1.5 text-xs text-slate-500 cursor-pointer select-none">
                <input
                  type="checkbox"
                  className="accent-blue-500"
                  checked={showTest}
                  onChange={e => setShowTest(e.target.checked)}
                />
                Testverkehr anzeigen
              </label>
            </div>
            <div className="flex-1 min-h-0">
              <AlertFeed
                alerts={alerts}
                onUpdate={handleUpdate}
                showTest={showTest}
              />
            </div>
          </div>
        )}
        {tab === 'networks' && <NetworksPage />}
        {tab === 'tests'    && <TestsPage />}
      </main>
    </div>
  );
}
