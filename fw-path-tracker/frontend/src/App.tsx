import { Info, LogOut, Route } from 'lucide-react';
import { useEffect, useState } from 'react';
import { runTrace, setToken } from './api';
import LoginPage from './components/LoginPage';
import HistoryList from './components/HistoryList';
import PathGraph from './components/PathGraph';
import ResultDrawer from './components/ResultDrawer';
import SuggestionCard from './components/SuggestionCard';
import TraceForm from './components/TraceForm';
import DnsPanel from './components/settings/DnsPanel';
import FmgPanel from './components/settings/FmgPanel';
import ItopPanel from './components/settings/ItopPanel';
import SitesPanel from './components/settings/SitesPanel';
import UsersPanel from './components/settings/UsersPanel';
import { de } from './i18n/de';
import type { Hop, Session, TraceRequest, TraceResult } from './types';

type Tab = 'tracker' | 'verlauf' | 'einstellungen';

const verdictBanner: Record<string, string> = {
  ALLOW: 'border-emerald-800 bg-emerald-950/60 text-emerald-300',
  DENY: 'border-red-800 bg-red-950/60 text-red-300',
  DEGRADED: 'border-amber-800 bg-amber-950/60 text-amber-300',
};

function loadSession(): Session | null {
  const raw = localStorage.getItem('fwpt-session');
  return raw ? (JSON.parse(raw) as Session) : null;
}

export default function App() {
  const [session, setSession] = useState<Session | null>(loadSession);
  const [tab, setTab] = useState<Tab>('tracker');
  const [result, setResult] = useState<TraceResult | null>(null);
  const [pendingReq, setPendingReq] = useState<TraceRequest | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [suggestHop, setSuggestHop] = useState<Hop | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);

  useEffect(() => {
    const onLogout = () => logout();
    window.addEventListener('fwpt-logout', onLogout);
    return () => window.removeEventListener('fwpt-logout', onLogout);
  }, []);

  function onLogin(s: Session) {
    localStorage.setItem('fwpt-session', JSON.stringify(s));
    setSession(s);
  }

  function logout() {
    localStorage.removeItem('fwpt-session');
    setToken(null);
    setSession(null);
  }

  async function execute(req: TraceRequest) {
    setBusy(true);
    setError(null);
    setSuggestHop(null);
    setTab('tracker');
    setPendingReq(req);
    try {
      setResult(await runTrace(req));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
      setResult(null);
    } finally {
      setBusy(false);
    }
  }

  if (!session) return <LoginPage onLogin={onLogin} />;

  return (
    <div className="min-h-screen">
      <header className="flex items-center gap-4 border-b border-slate-800 px-4 py-2.5">
        <div className="flex items-center gap-2 text-cyan-400">
          <Route size={20} />
          <span className="font-semibold text-slate-100">{de.appTitle}</span>
        </div>
        <nav className="flex gap-1">
          {(['tracker', 'verlauf', 'einstellungen'] as Tab[])
            .filter((t) => t !== 'einstellungen' || session.role === 'admin')
            .map((t) => (
              <button
                key={t} type="button"
                className={`rounded-md px-3 py-1.5 text-sm capitalize transition-colors ${
                  tab === t ? 'bg-slate-800 text-cyan-400' : 'text-slate-400 hover:text-slate-200'
                }`}
                onClick={() => setTab(t)}
              >
                {t === 'tracker' ? de.tabs.tracker : t === 'verlauf' ? de.tabs.history : de.tabs.settings}
              </button>
            ))}
        </nav>
        <div className="ml-auto flex items-center gap-3 text-sm text-slate-400">
          <span>{session.username}</span>
          <button type="button" className="hover:text-slate-200" onClick={logout} title={de.common.logout}>
            <LogOut size={16} />
          </button>
        </div>
      </header>

      <main className="mx-auto max-w-6xl space-y-4 p-4">
        {tab === 'tracker' && (
          <>
            <TraceForm key={pendingReq ? JSON.stringify(pendingReq) : 'blank'}
              onSubmit={execute} busy={busy} initial={pendingReq} />
            {error && (
              <div className="rounded-md border border-red-800 bg-red-950/60 p-3 text-sm text-red-300">
                {error}
              </div>
            )}
            {result && (
              <>
                <div className={`flex items-center gap-3 rounded-md border p-3 text-sm ${
                  verdictBanner[result.verdict]
                }`}>
                  <span className="font-semibold">{de.verdict[result.verdict]}</span>
                  <span className="text-slate-400">
                    {result.src.ip} → {result.dst.ip} · {result.protocol.toUpperCase()}
                    {result.dst_port ? `/${result.dst_port}` : ''} · {result.duration_ms} ms
                  </span>
                  <button
                    type="button" className="ml-auto text-slate-400 hover:text-slate-200"
                    onClick={() => setDrawerOpen(true)} title={de.drawer.title}
                  >
                    <Info size={16} />
                  </button>
                </div>
                {result.vip && result.vip.mappedip && (
                  <div className="flex items-center gap-3 rounded-md border border-amber-800 bg-amber-950/60 p-3 text-sm text-amber-300">
                    <span>{result.warnings.find((w) => w.includes('VIP')) ?? `Ziel ist VIP '${result.vip.name}'.`}</span>
                    <button
                      type="button" className="fwpt-btn-ghost ml-auto shrink-0 text-xs"
                      onClick={() => pendingReq && execute({ ...pendingReq, dst: result.vip!.mappedip! })}
                    >
                      {de.trace.vipRetrace}
                    </button>
                  </div>
                )}
                <PathGraph result={result} onSuggest={setSuggestHop} />
                {suggestHop?.suggestion && <SuggestionCard suggestion={suggestHop.suggestion} />}
                {drawerOpen && <ResultDrawer result={result} onClose={() => setDrawerOpen(false)} />}
              </>
            )}
          </>
        )}

        {tab === 'verlauf' && <HistoryList onReplay={execute} />}

        {tab === 'einstellungen' && session.role === 'admin' && (
          <>
            <FmgPanel />
            <ItopPanel />
            <DnsPanel />
            <SitesPanel />
            <UsersPanel />
          </>
        )}
      </main>
    </div>
  );
}
