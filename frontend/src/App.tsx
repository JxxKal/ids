import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { clearToken, fetchAlerts, fetchMe, fetchSystemStats, fetchTaps, fetchUnknownHosts, getToken, setToken } from './api';
import type { SystemStats } from './api';
import { UnknownHostsDrawer } from './components/UnknownHostsDrawer';
import { disableDemoMode } from './demo/mode';
import { resetStore as resetDemoStore } from './demo/store';
import { AlertFeed } from './components/AlertFeed';
import { ErrorBoundary } from './components/ErrorBoundary';
import { GettingStartedPage } from './components/GettingStartedPage';
import { HostsPage } from './components/HostsPage';
import { LoginPage } from './components/LoginPage';
import { NetworksPage } from './components/NetworksPage';
import { SettingsPage, type SectionId } from './components/SettingsPage';
import { SeverityBarsCard } from './components/SeverityBarsCard';
import { HostConnectionDrawer } from './components/HostConnectionDrawer';
import { HelpTip } from './components/HelpTip';
import { Sidebar, type NavTab } from './components/Sidebar';
import { TestsPage } from './components/TestsPage';
import { ThreatGauge } from './components/ThreatGauge';
import { TopBar } from './components/TopBar';
import { TopProtocolsCard } from './components/TopProtocolsCard';
import { useWebSocket } from './hooks/useWebSocket';
import type { Alert, RemoteTap, User } from './types';

type TimeWindow = 'live' | '1m' | '15m' | '1h' | '4h' | '1d' | '2d' | '7d' | 'custom';

const TIME_WINDOWS: { id: TimeWindow; seconds?: number }[] = [
  { id: 'live'                     },
  { id: '1m',  seconds: 60         },
  { id: '15m', seconds: 900        },
  { id: '1h',  seconds: 3_600      },
  { id: '4h',  seconds: 14_400     },
  { id: '1d',  seconds: 86_400     },
  { id: '2d',  seconds: 172_800    },
  { id: '7d',  seconds: 604_800    },
  { id: 'custom'                   },
];

interface CustomRange {
  from: number;  // unix seconds
  to:   number;
}

// "yyyy-MM-ddTHH:mm" für datetime-local. Lokale Zeitzone — JS-Browser-Default.
function unixToLocalDtInput(unixSec: number): string {
  const d = new Date(unixSec * 1000);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function localDtInputToUnix(s: string): number {
  return Math.floor(new Date(s).getTime() / 1000);
}

export default function App() {
  const { t } = useTranslation();
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
        <span className="text-slate-600 text-sm">{t('common.loading')}</span>
      </div>
    );
  }

  if (!user) {
    return <LoginPage onLogin={u => setUser(u)} />;
  }

  return <Dashboard user={user} onLogout={() => { clearToken(); disableDemoMode(); resetDemoStore(); setUser(null); }} />;
}

function Dashboard({ user, onLogout }: { user: User; onLogout: () => void }) {
  const { t } = useTranslation();
  const [tab, setTab]         = useState<NavTab>('dashboard');
  // Wenn Settings über onNavigate von außen geöffnet wird, soll die
  // Sub-Sektion direkt mitspringen (sonst landet jeder Klick auf "→ DNS-
  // Resolver öffnen" auf der Default-Sektion 'general').
  const [settingsSection, setSettingsSection] = useState<SectionId | undefined>(undefined);
  const navigateTo = (target: NavTab, section?: SectionId) => {
    if (target === 'settings' && section) {
      // Force re-mount der SettingsPage über key={section}, damit die Page
      // die neue initialSection auch übernimmt wenn man mehrfach hintereinander
      // verschiedene Settings-Sub-Tabs anspringt.
      setSettingsSection(section);
    }
    setTab(target);
  };
  const [showTest, setShowTest] = useState(
    () => localStorage.getItem('showTest') === 'true'
  );
  const [mlOnly, setMlOnly] = useState(
    () => localStorage.getItem('mlOnly') === 'true'
  );
  const [timeWindow, setTimeWindow] = useState<TimeWindow>('live');
  // Custom-Range: nur ausgewertet wenn timeWindow === 'custom'. Default ist
  // letzte 24 h, der User kann beide Endpunkte verstellen.
  const [customRange, setCustomRange] = useState<CustomRange>(() => {
    const now = Math.floor(Date.now() / 1000);
    return { from: now - 86_400, to: now };
  });
  const [customDraft, setCustomDraft] = useState<CustomRange>(() => {
    const now = Math.floor(Date.now() / 1000);
    return { from: now - 86_400, to: now };
  });
  const [historicAlerts, setHistoricAlerts] = useState<Alert[]>([]);
  const [isLoading, setIsLoading]   = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);
  // Tap-Filter: '' = alle, 'master' = nur Master-lokal, sonst UUID. Hier
  // hochgehoben (statt im AlertFeed), damit der historic-Fetch ihn als
  // Server-side-Param mitschicken kann — sonst würden Tap-Alerts in den
  // älteren Schichten unterhalb des Limits verloren gehen.
  const [tapFilter, setTapFilter] = useState('');

  const { alerts, connected, setAlerts } = useWebSocket();
  const [sysStats,       setSysStats]       = useState<SystemStats | null>(null);
  const [unknownCount,   setUnknownCount]   = useState<number | null>(null);
  const [showUnknown,    setShowUnknown]    = useState(false);
  // Tap-Heartbeat: alle 30 s abgefragt. Topbar nutzt last_seen pro Tap, um
  // online/stale/offline zu rendern. Ohne registrierte Taps bleibt das Array
  // leer und die Topbar zeigt keine Extra-Badges.
  const [taps,           setTaps]           = useState<RemoteTap[]>([]);

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

  useEffect(() => {
    if (!user) return;
    let alive = true;
    const load = () => fetchTaps()
      .then(d => { if (alive) setTaps(d); })
      .catch(() => { if (alive) setTaps([]); });
    load();
    const t = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(t); };
  }, [user]);

  const handleUpdate = (updated: Alert) => {
    setAlerts(prev => prev.map(a => a.alert_id === updated.alert_id ? updated : a));
  };

  useEffect(() => {
    if (timeWindow === 'live') return;
    let tsFrom: number;
    let tsTo:   number | undefined;
    if (timeWindow === 'custom') {
      tsFrom = customRange.from;
      tsTo   = customRange.to;
    } else {
      const win = TIME_WINDOWS.find(w => w.id === timeWindow);
      if (!win?.seconds) return;
      tsFrom = Date.now() / 1000 - win.seconds;
    }

    let cancelled = false;
    setIsLoading(true);

    fetchAlerts({
      ts_from: tsFrom,
      ts_to:   tsTo,
      limit: 5000,
      is_test: showTest ? null : false,
      source: mlOnly ? 'ml' : undefined,
      tap_id: tapFilter || undefined,
    })
      .then(r  => { if (!cancelled) setHistoricAlerts(r.alerts); })
      .catch(e => { console.error('historic fetch:', e); })
      .finally(() => { if (!cancelled) setIsLoading(false); });

    return () => { cancelled = true; };
  }, [timeWindow, customRange, refreshKey, showTest, mlOnly, tapFilter]);

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
      { label: t('dashboard.kpi.alertsPerHour'), value: String(lastHour),   color: '#fdba74' },
      { label: t('dashboard.kpi.visible'),       value: String(alertCount), color: '#7dd3fc' },
    ];
  }, [alerts, alertCount, showTest, t]);

  return (
    <div className="min-h-screen flex">
      <Sidebar active={tab} onNav={setTab} username={user.username} />

      <main className="flex-1 flex flex-col overflow-hidden">
        <TopBar
          title={t(`tabs.${tab}`)}
          live={connected && timeWindow === 'live'}
          kpis={tab === 'dashboard' ? kpis : []}
          taps={taps}
          username={user.username}
          onLogout={onLogout}
        />

        {tab === 'dashboard' && (
          <div className="flex-1 overflow-hidden flex flex-col gap-4 p-5">

            {/* KPI Row */}
            <div className="flex items-stretch gap-4 flex-wrap">
              <HelpTip helpKey="threatGauge"><ThreatGauge /></HelpTip>
              <HelpTip helpKey="severityCard"><SeverityBarsCard alerts={displayAlerts} showTest={showTest} /></HelpTip>
              <HelpTip helpKey="protocolsCard"><TopProtocolsCard alerts={displayAlerts} showTest={showTest} /></HelpTip>
            </div>

            {/* Toolbar */}
            <div className="flex items-center gap-3 flex-wrap">
                <HelpTip helpKey="timeWindow">
                <div className="flex items-center rounded overflow-hidden border border-slate-800">
                  {TIME_WINDOWS.map(w => {
                    const isActive = timeWindow === w.id;
                    return (
                      <button
                        key={w.id}
                        onClick={() => handleWindowSelect(w.id)}
                        title={w.id !== 'live' && w.id !== 'custom' && isActive ? t('dashboard.timeWindows.clickToRefresh') : undefined}
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
                            {t('dashboard.timeWindows.live')}
                          </span>
                        ) : t(`dashboard.timeWindows.${w.id}`)}
                      </button>
                    );
                  })}
                </div>
                </HelpTip>

                {/* Custom-Range-Picker — nur sichtbar bei timeWindow='custom' */}
                {timeWindow === 'custom' && (
                  <HelpTip helpKey="customRange">
                  <div className="flex items-center gap-2 text-xs">
                    <input
                      type="datetime-local"
                      className="input bg-slate-900 border border-slate-700 px-2 py-1 rounded font-mono text-slate-200"
                      value={unixToLocalDtInput(customDraft.from)}
                      onChange={e => setCustomDraft(d => ({ ...d, from: localDtInputToUnix(e.target.value) }))}
                      title={t('dashboard.timeWindows.customFrom')}
                    />
                    <span className="text-slate-500">→</span>
                    <input
                      type="datetime-local"
                      className="input bg-slate-900 border border-slate-700 px-2 py-1 rounded font-mono text-slate-200"
                      value={unixToLocalDtInput(customDraft.to)}
                      onChange={e => setCustomDraft(d => ({ ...d, to: localDtInputToUnix(e.target.value) }))}
                      title={t('dashboard.timeWindows.customTo')}
                    />
                    <button
                      onClick={() => {
                        if (customDraft.from < customDraft.to) {
                          setCustomRange(customDraft);
                        }
                      }}
                      disabled={customDraft.from >= customDraft.to}
                      className="px-2.5 py-1 rounded text-xs font-medium border bg-cyan-500/15 text-cyan-200 border-cyan-500/50 hover:bg-cyan-500/25 disabled:opacity-40 disabled:cursor-not-allowed"
                    >
                      {t('dashboard.timeWindows.apply')}
                    </button>
                  </div>
                  </HelpTip>
                )}

                <HelpTip helpKey="alertCount">
                  <span className="text-xs text-slate-500 font-mono">
                    {isLoading ? t('common.loading') : t('dashboard.alertCount', { count: alertCount })}
                  </span>
                </HelpTip>

                {/* Unbekannte Hosts */}
                {unknownCount !== null && unknownCount > 0 && (
                  <HelpTip helpKey="unknownHosts">
                  <button
                    onClick={() => setShowUnknown(true)}
                    title={t('dashboard.unknownHosts.title', { count: unknownCount })}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono bg-slate-800 text-slate-400 border border-slate-600 hover:border-cyan-600 hover:text-cyan-300 transition-colors"
                  >
                    <svg className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                      <circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 3.6-7 8-7s8 3 8 7"/>
                    </svg>
                    {t('dashboard.unknownHosts.label', { count: unknownCount })}
                  </button>
                  </HelpTip>
                )}

                {/* Sniffer-Health-Warnung */}
                {sysStats && sysStats.sniffer.drop_pct !== null && sysStats.sniffer.drop_pct > 1 && (
                  <HelpTip helpKey="snifferDrops">
                  <span
                    title={t('dashboard.snifferDrops.title', { pct: sysStats.sniffer.drop_pct.toFixed(2) })}
                    className={`flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-mono cursor-default ${
                      sysStats.sniffer.drop_pct > 5
                        ? 'bg-red-900/40 text-red-300 border border-red-700/50'
                        : 'bg-amber-900/40 text-amber-300 border border-amber-700/50'
                    }`}
                  >
                    {t('dashboard.snifferDrops.label', { pct: sysStats.sniffer.drop_pct.toFixed(1) })}
                  </span>
                  </HelpTip>
                )}

                <HelpTip helpKey="mlOnly">
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
                    {t('dashboard.filters.mlOnly')}
                  </span>
                </label>
                </HelpTip>

                {timeWindow === 'live' && (
                  <HelpTip helpKey="showTest">
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
                    {t('dashboard.filters.showTest')}
                  </label>
                  </HelpTip>
                )}

                {timeWindow !== 'live' && !isLoading && (
                  <HelpTip helpKey="snapshotHint">
                    <span className="text-xs text-slate-600 italic">
                      {t('dashboard.snapshotHint')}
                    </span>
                  </HelpTip>
                )}
            </div>

            <div className="flex-1 min-h-0">
              <ErrorBoundary>
                <AlertFeed
                  alerts={displayAlerts}
                  onUpdate={handleUpdate}
                  showTest={showTest}
                  mlOnly={mlOnly}
                  tapFilter={tapFilter}
                  onTapFilterChange={setTapFilter}
                />
              </ErrorBoundary>
            </div>
          </div>
        )}

        {tab === 'gettingStarted' && <div className="flex-1 overflow-auto p-5"><GettingStartedPage onNavigate={navigateTo} /></div>}
        {tab === 'networks' && <div className="flex-1 overflow-auto p-5"><NetworksPage /></div>}
        {tab === 'hosts'    && <div className="flex-1 overflow-auto p-5"><HostsPage    /></div>}
        {tab === 'tests'    && <div className="flex-1 overflow-auto p-5"><TestsPage    /></div>}
        {tab === 'settings' && <div className="flex-1 overflow-auto p-5"><SettingsPage key={settingsSection ?? 'default'} initialSection={settingsSection} /></div>}
      </main>

      {showUnknown && <UnknownHostsDrawer onClose={() => setShowUnknown(false)} />}

      {/* Globaler Host-Connection-Drawer: lauscht auf
          window.dispatchEvent(new CustomEvent('ids:show-host-connections', {detail:{ip}})) */}
      <HostConnectionDrawer />
    </div>
  );
}
