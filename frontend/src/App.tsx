import { useEffect, useState } from 'react';
import { fetchAlerts } from './api';
import { AlertFeed } from './components/AlertFeed';
import { ErrorBoundary } from './components/ErrorBoundary';
import { HostsPage } from './components/HostsPage';
import { NetworksPage } from './components/NetworksPage';
import { TestsPage } from './components/TestsPage';
import { ThreatGauge } from './components/ThreatGauge';
import { useWebSocket } from './hooks/useWebSocket';
import type { Alert } from './types';

type Tab        = 'dashboard' | 'networks' | 'hosts' | 'tests';
type TimeWindow = 'live' | '1m' | '15m' | '1h' | '4h' | '1d';

const TABS: { id: Tab; label: string }[] = [
  { id: 'dashboard', label: 'Dashboard' },
  { id: 'networks',  label: 'Netzwerke' },
  { id: 'hosts',     label: 'Hosts' },
  { id: 'tests',     label: 'Tests' },
];

const TIME_WINDOWS: { id: TimeWindow; label: string; seconds?: number }[] = [
  { id: 'live',  label: 'Live' },
  { id: '1m',    label: '1 Min',   seconds: 60 },
  { id: '15m',   label: '15 Min',  seconds: 900 },
  { id: '1h',    label: '1 Std',   seconds: 3_600 },
  { id: '4h',    label: '4 Std',   seconds: 14_400 },
  { id: '1d',    label: '1 Tag',   seconds: 86_400 },
];

export default function App() {
  const [tab, setTab]         = useState<Tab>('dashboard');
  const [showTest, setShowTest] = useState(
    () => localStorage.getItem('showTest') === 'true'
  );
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('live');
  const [historicAlerts, setHistoricAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading]   = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const { alerts, connected, setAlerts } = useWebSocket();

  const handleUpdate = (updated: Alert) => {
    setAlerts(prev => prev.map(a => a.alert_id === updated.alert_id ? updated : a));
  };

  // Fetch whenever a non-live window is active or refresh is triggered
  useEffect(() => {
    if (timeWindow === 'live') return;
    const win = TIME_WINDOWS.find(w => w.id === timeWindow);
    if (!win?.seconds) return;

    let cancelled = false;
    setIsLoading(true);

    fetchAlerts({ ts_from: Date.now() / 1000 - win.seconds, limit: 500, is_test: showTest ? null : false })
      .then(r  => { if (!cancelled) setHistoricAlerts(r.alerts); })
      .catch(e => { console.error('historic fetch:', e); })
      .finally(() => { if (!cancelled) setIsLoading(false); });

    return () => { cancelled = true; };
  }, [timeWindow, refreshKey, showTest]);

  const handleWindowSelect = (w: TimeWindow) => {
    if (w === timeWindow && w !== 'live') {
      setRefreshKey(k => k + 1);   // gleiche Schaltfläche = Refresh
    } else {
      setTimeWindow(w);
      if (w === 'live') setHistoricAlerts([]);
    }
  };

  const displayAlerts = timeWindow === 'live' ? alerts : historicAlerts;
  const alertCount    = displayAlerts.filter(a => showTest || !a.is_test).length;

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
          <span className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500' : 'bg-red-500'}`} />
          <span className="text-slate-500">{connected ? 'Live' : 'Verbinde…'}</span>
        </div>
      </header>

      {/* Content */}
      <main className="flex-1 overflow-hidden p-4">
        {tab === 'dashboard' && (
          <div className="h-full flex flex-col gap-3">

            {/* Dashboard-Toolbar */}
            <div className="flex items-center gap-3 flex-wrap">

              {/* Zeitfenster-Selector */}
              <div className="flex items-center rounded overflow-hidden border border-slate-700">
                {TIME_WINDOWS.map(w => (
                  <button
                    key={w.id}
                    onClick={() => handleWindowSelect(w.id)}
                    title={w.id !== 'live' && timeWindow === w.id ? 'Klick zum Aktualisieren' : undefined}
                    className={`px-2.5 py-1 text-xs font-medium transition-colors
                      border-r border-slate-700 last:border-r-0 ${
                      timeWindow === w.id
                        ? 'bg-blue-900/70 text-blue-100 font-semibold'
                        : 'bg-slate-900 text-slate-500 hover:text-slate-300 hover:bg-slate-800'
                    }`}
                  >
                    {w.id === 'live' ? (
                      <span className="flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full inline-block ${
                          timeWindow === 'live'
                            ? (connected ? 'bg-green-500' : 'bg-red-500')
                            : 'bg-slate-600'
                        }`} />
                        Live
                      </span>
                    ) : w.label}
                  </button>
                ))}
              </div>

              {/* Alert-Zähler */}
              <span className="text-xs text-slate-500">
                {isLoading ? 'Lade…' : `${alertCount} Alerts`}
              </span>

              {/* Test-Toggle – nur im Live-Modus */}
              {timeWindow === 'live' && (
                <label htmlFor="show-test-toggle" className="flex items-center gap-1.5 text-xs text-slate-500 cursor-pointer select-none">
                  <input
                    id="show-test-toggle"
                    name="show-test-toggle"
                    type="checkbox"
                    className="accent-blue-500"
                    checked={showTest}
                    onChange={e => {
                      setShowTest(e.target.checked);
                      localStorage.setItem('showTest', String(e.target.checked));
                    }}
                  />
                  Testverkehr anzeigen
                </label>
              )}

              {/* Snapshot-Hinweis */}
              {timeWindow !== 'live' && !isLoading && (
                <span className="text-xs text-slate-600 italic">
                  Snapshot · Schaltfläche erneut klicken zum Aktualisieren
                </span>
              )}
            </div>

            <div className="flex-1 min-h-0">
              <ErrorBoundary>
                <AlertFeed
                  alerts={displayAlerts}
                  onUpdate={handleUpdate}
                  showTest={showTest}
                />
              </ErrorBoundary>
            </div>
          </div>
        )}
        {tab === 'networks' && <NetworksPage />}
        {tab === 'hosts'    && <HostsPage />}
        {tab === 'tests'    && <TestsPage />}
      </main>
    </div>
  );
}
