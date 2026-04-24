import { useEffect, useMemo, useState } from 'react';
import { clearToken, fetchAlerts, fetchMe, fetchSystemStats, fetchUnknownHosts, getToken, setToken } from './api';
import type { SystemStats } from './api';
import { UnknownHostsDrawer } from './components/UnknownHostsDrawer';
import { disableDemoMode } from './demo/mode';
import { resetStore as resetDemoStore } from './demo/store';
import { AlertFeed } from './components/AlertFeed';
import { ErrorBoundary } from './components/ErrorBoundary';
import { HostsPage } from './components/HostsPage';
import { LoginPage } from './components/LoginPage';
import { NetworksPage } from './components/NetworksPage';
import { SettingsPage } from './components/SettingsPage';
import { SeverityBarsCard } from './components/SeverityBarsCard';
import { Sidebar, type NavTab } from './components/Sidebar';
import { TestsPage } from './components/TestsPage';
import { ThreatGauge } from './components/ThreatGauge';
import { TopBar } from './components/TopBar';
import { TopProtocolsCard } from './components/TopProtocolsCard';
import { useWebSocket } from './hooks/useWebSocket';
import type { Alert, User } from './types';

type TimeWindow = 'live' | '1m' | '15m' | '1h' | '4h' | '1d';

const TAB_TITLES: Record<NavTab, string> = {
  dashboard: 'Übersicht',
  networks:  'Netzwerk-Inventar',
  hosts:     'Host-Inventar',
  tests:     'Test-Szenarien',
  settings:  'Einstellungen',
};

const TIME_WINDOWS: { id: TimeWindow; label: string; seconds?: number }[] = [
  { id: 'live',  label: 'Live' },
  { id: '1m',    label: '1 Min',   seconds: 60 },
  { id: '15m',   label: '15 Min',  seconds: 900 },
  { id: '1h',    label: '1 Std',   seconds: 3_600 },
  { id: '4h',    label: '4 Std',   seconds: 14_400 },
  { id: '1d',    label: '1 Tag',   seconds: 86_400 },
];

export default function App() {
  const [user,    setUser]    = useState<User | null>(null);
  const [authChk, setAuthChk] = useState(true);

  useEffect(() => {
    // SAML-Callback: /?saml_token=JWT nach ACS-Redirect
    const params = new URLSearchParams(window.location.search);
    const samlToken = params.get('saml_token');
    if (samlToken) {
      setToken(samlToken);
      window.history.replaceState({}, '', window.location.pathname);
    }
    const token = samlToken || getToken();
    if (!token) { setAuthChk(false); return; }
    fetchMe()
      .then(u => setUser(u))
      .catch(() => clearToken())
      .finally(() => setAuthChk(false));
  }, []);

  useEffect(() => {
    const handler = () => { setUser(null); clearToken(); disableDemoMode(); resetDemoStore(); };
    window.addEventListener('ids:unauthorized', handler);
    return () => window.removeEventListener('ids:unauthorized', handler);
  }, []);

  if (authChk) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-950">
        <span className="text-slate-600 text-sm">Lade…</span>
      </div>
    );
  }

  if (!user) {
    return <LoginPage onLogin={u => setUser(u)} />;
  }

  return <Dashboard user={user} onLogout={() => { clearToken(); disableDemoMode(); resetDemoStore(); setUser(null); }} />;
}

function Dashboard({ user, onLogout }: { user: User; onLogout: () => void }) {
  const [tab, setTab]         = useState<NavTab>('dashboard');
  const [showTest, setShowTest] = useState(
    () => localStorage.getItem('showTest') === 'true'
  );
  const [mlOnly, setMlOnly] = useState(
    () => localStorage.getItem('mlOnly') === 'true'
  );
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('live');
  const [historicAlerts, setHistoricAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading]   = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const { alerts, connected, setAlerts } = useWebSocket();
  const [sysStats,       setSysStats]       = useState<SystemStats | null>(null);
  const [unknownCount,   setUnknownCount]   = useState<number | null>(null);
  const [showUnknown,    setShowUnknown]    = useState(false);

  useEffect(() => {
    if (!user) return;
    let alive = true;
    const load = () => fetchSystemStats().then(d => { if (alive) setSysStats(d); }).catch(() => {});
    load();
    const t = setInterval(load, 15_000);
    return () => { alive = false; clearInterval(t); };
  }, [user]);

  useEffect(() => {
    if (!user) return;
    let alive = true;
    const load = () => fetchUnknownHosts(30).then(d => { if (alive) setUnknownCount(d.length); }).catch(() => {});
    load();
    const t = setInterval(load, 60_000);
    return () => { alive = false; clearInterval(t); };
  }, [user]);

  const handleUpdate = (updated: Alert) => {
    setAlerts(prev => prev.map(a => a.alert_id === updated.alert_id ? updated : a));
  };

  useEffect(() => {
    if (timeWindow === 'live') return;
    const win = TIME_WINDOWS.find(w => w.id === timeWindow);
    if (!win?.seconds) return;

    let cancelled = false;
    setIsLoading(true);

    fetchAlerts({
      ts_from: Date.now() / 1000 - win.seconds,
      limit: 500,
      is_test: showTest ? null : false,
      source: mlOnly ? 'ml' : undefined,
    })
      .then(r  => { if (!cancelled) setHistoricAlerts(r.alerts); })
      .catch(e => { console.error('historic fetch:', e); })
      .finally(() => { if (!cancelled) setIsLoading(false); });

    return () => { cancelled = true; };
  }, [timeWindow, refreshKey, showTest, mlOnly]);

  const handleWindowSelect = (w: TimeWindow) => {
    if (w === timeWindow && w !== 'live') {
      setRefreshKey(k => k + 1);
    } else {
      setTimeWindow(w);
      if (w === 'live') setHistoricAlerts([]);
    }
  };

  const displayAlerts = timeWindow === 'live' ? alerts : historicAlerts;
  const alertCount    = displayAlerts.filter(a =>
    (showTest || !a.is_test) && (!mlOnly || a.source === 'ml')
  ).length;

  const kpis = useMemo(() => {
    const cutoff = Date.now() - 3600 * 1000;
    const lastHour = alerts.filter(a => {
      const ms = Date.parse(a.ts);
      return ms >= cutoff && (showTest || !a.is_test);
    }).length;
    return [
      { label: 'alerts / 1h', value: String(lastHour),   color: '#fdba74' },
      { label: 'sichtbar',    value: String(alertCount), color: '#7dd3fc' },
    ];
  }, [alerts, alertCount, showTest]);

  return (
    <div className="min-h-screen flex">
      <Sidebar active={tab} onNav={setTab} username={user.username} />

      <main className="flex-1 flex flex-col overflow-hidden">
        <TopBar
          title={TAB_TITLES[tab]}
          live={connected && timeWindow === 'live'}
          kpis={tab === 'dashboard' ? kpis : []}
          username={user.username}
          onLogout={onLogout}
        />

        {tab === 'dashboard' && (
          <div className="flex-1 overflow-hidden flex flex-col gap-4 p-5">

            {/* KPI Row */}
            <div className="flex items-stretch gap-4 flex-wrap">
              <ThreatGauge />
              <SeverityBarsCard alerts={displayAlerts} showTest={showTest} />
              <TopProtocolsCard alerts={displayAlerts} showTest={showTest} />
            </div>

            {/* Toolbar */}
            <div className="flex items-center gap-3 flex-wrap">
                <div className="flex items-center rounded overflow-hidden border border-slate-800">
                  {TIME_WINDOWS.map(w => {
                    const isActive = timeWindow === w.id;
                    return (
                      <button
                        key={w.id}
                        onClick={() => handleWindowSelect(w.id)}
                        title={w.id !== 'live' && isActive ? 'Klick zum Aktualisieren' : undefined}
                        className={`px-3 py-1.5 text-xs font-medium transition-colors border-r border-slate-800 last:border-r-0 font-mono ${
                          isActive
                            ? 'bg-cyan-500/15 text-cyan-200'
                            : 'bg-slate-900 text-slate-500 hover:text-slate-300 hover:bg-slate-800'
                        }`}
                      >
                        {w.id === 'live' ? (
                          <span className="flex items-center gap-1.5">
                            <span className={`w-1.5 h-1.5 rounded-full inline-block ${
                              isActive
                                ? (connected ? 'bg-green-500 shadow-[0_0_6px_#22c55e]' : 'bg-red-500')
                                : 'bg-slate-600'
                            }`} />
                            Live
                          </span>
                        ) : w.label}
                      </button>
                    );
                  })}
                </div>

                <span className="text-xs text-slate-500 font-mono">
                  {isLoading ? 'Lade…' : `${alertCount} Alerts`}
                </span>

                {/* Unbekannte Hosts */}
                {unknownCount !== null && unknownCount > 0 && (
                  <button
                    onClick={() => setShowUnknown(true)}
                    title={`${unknownCount} IPs in Alerts ohne Host-Eintrag – klicken zum Anzeigen`}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-400 border border-slate-600 hover:border-cyan-600 hover:text-cyan-300 transition-colors"
                  >
                    <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                    </svg>
                    {unknownCount} unbekannt
                  </button>
                )}

                {/* Sniffer-Health-Warnung */}
                {sysStats && sysStats.sniffer.drop_pct !== null && sysStats.sniffer.drop_pct > 1 && (
                  <span
                    title={`Paketverlust am Sniffer: ${sysStats.sniffer.drop_pct.toFixed(2)} % — Details unter Einstellungen → Systemauslastung`}
                    className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono cursor-default ${
                      sysStats.sniffer.drop_pct > 5
                        ? 'bg-red-900/40 text-red-300 border border-red-700/50'
                        : 'bg-amber-900/40 text-amber-300 border border-amber-700/50'
                    }`}
                  >
                    ⚠ Drops {sysStats.sniffer.drop_pct.toFixed(1)} %
                  </span>
                )}

                <label htmlFor="ml-only-toggle" className="flex items-center gap-1.5 text-xs cursor-pointer select-none">
                  <input
                    id="ml-only-toggle"
                    name="ml-only-toggle"
                    type="checkbox"
                    className="accent-cyan-500"
                    checked={mlOnly}
                    onChange={e => {
                      setMlOnly(e.target.checked);
                      localStorage.setItem('mlOnly', String(e.target.checked));
                    }}
                  />
                  <span className={mlOnly ? 'text-cyan-400 font-medium' : 'text-slate-500'}>
                    Nur KI/ML-Alarme
                  </span>
                </label>

                {timeWindow === 'live' && (
                  <label htmlFor="show-test-toggle" className="flex items-center gap-1.5 text-xs text-slate-500 cursor-pointer select-none">
                    <input
                      id="show-test-toggle"
                      name="show-test-toggle"
                      type="checkbox"
                      className="accent-cyan-500"
                      checked={showTest}
                      onChange={e => {
                        setShowTest(e.target.checked);
                        localStorage.setItem('showTest', String(e.target.checked));
                      }}
                    />
                    Testverkehr anzeigen
                  </label>
                )}

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
                  mlOnly={mlOnly}
                />
              </ErrorBoundary>
            </div>
          </div>
        )}

        {tab === 'networks' && <div className="flex-1 overflow-auto p-5"><NetworksPage /></div>}
        {tab === 'hosts'    && <div className="flex-1 overflow-auto p-5"><HostsPage    /></div>}
        {tab === 'tests'    && <div className="flex-1 overflow-auto p-5"><TestsPage    /></div>}
        {tab === 'settings' && <div className="flex-1 overflow-auto p-5"><SettingsPage /></div>}
      </main>

      {showUnknown && <UnknownHostsDrawer onClose={() => setShowUnknown(false)} />}
    </div>
  );
}
