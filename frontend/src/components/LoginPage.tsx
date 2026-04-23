import { useEffect, useState } from 'react';
import { fetchSamlEnabled, login, setToken } from '../api';
import { disableDemoMode, enableDemoMode } from '../demo/mode';
import type { User } from '../types';
import { NetworkGlobe } from './NetworkGlobe';
import { CyjanShield } from './CyjanShield';

interface Props {
  onLogin: (user: User, token: string) => void;
}

export function LoginPage({ onLogin }: Props) {
  const [username,    setUsername]    = useState('');
  const [password,    setPassword]    = useState('');
  const [error,       setError]       = useState('');
  const [loading,     setLoading]     = useState(false);
  const [samlEnabled, setSamlEnabled] = useState(false);

  useEffect(() => {
    fetchSamlEnabled().then(r => setSamlEnabled(r.enabled)).catch(() => {});
  }, []);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      if (username === 'demo' && password === 'demo') enableDemoMode();
      else disableDemoMode();
      const res = await login(username, password);
      setToken(res.access_token);
      onLogin(res.user, res.access_token);
    } catch (err: unknown) {
      disableDemoMode();
      setError(err instanceof Error ? err.message : 'Anmeldung fehlgeschlagen');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="login-page min-h-screen flex flex-col lg:flex-row items-center justify-center relative overflow-hidden">
      <div className="hex-grid-bg" aria-hidden="true" />

      {/* Hero */}
      <div className="relative z-10 flex-1 flex items-center justify-center w-full max-w-[560px] aspect-square px-6 py-8 lg:py-0">
        <div className="cyjan-stage relative w-full h-full max-w-[520px] max-h-[520px] mx-auto">
          <NetworkGlobe size={520} />
          <div className="absolute inset-0 flex items-center justify-center pointer-events-none">
            <div className="cyjan-shield w-[260px]">
              <CyjanShield />
            </div>
          </div>
          <div className="absolute -bottom-2 left-0 right-0 text-center text-[10px] tracking-[6px] text-cyan-400/80 font-mono">
            PROTECT · DETECT · RESPOND
          </div>
        </div>
      </div>

      {/* Form */}
      <div className="relative z-10 w-full max-w-md px-6 py-10 lg:py-0">
        <div className="flex flex-col items-center mb-8 gap-3">
          <h1 className="text-3xl font-bold text-cyan-100 tracking-tight" style={{ fontFamily: 'Inter, sans-serif' }}>
            CYJAN <span className="text-cyan-400">IDS</span>
          </h1>
          <p className="text-xs text-cyan-400/60 tracking-[4px] font-mono">OT SENTRYMODE</p>
        </div>

        <div className="cyjan-card rounded-xl p-6 backdrop-blur-sm">
          <h2 className="text-sm font-semibold text-cyan-200 mb-4 tracking-wide uppercase" style={{ fontFamily: 'JetBrains Mono, monospace' }}>
            Anmelden
          </h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex flex-col gap-1.5">
              <label htmlFor="login-user" className="text-[11px] text-slate-400 tracking-wider uppercase font-mono">
                Benutzername
              </label>
              <input
                id="login-user"
                name="username"
                type="text"
                autoComplete="username"
                className="cyjan-input"
                required
                autoFocus
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label htmlFor="login-pw" className="text-[11px] text-slate-400 tracking-wider uppercase font-mono">
                Passwort
              </label>
              <input
                id="login-pw"
                name="password"
                type="password"
                autoComplete="current-password"
                className="cyjan-input"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
            </div>

            {error && (
              <p className="text-xs text-red-300 bg-red-950/50 border border-red-800/50 rounded px-3 py-2 font-mono">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="cyjan-btn-primary w-full"
            >
              {loading ? 'ANMELDEN…' : 'ANMELDEN'}
            </button>
          </form>

          {samlEnabled && (
            <>
              <div className="flex items-center gap-2 mt-4">
                <div className="flex-1 h-px bg-slate-700/60" />
                <span className="text-[10px] text-slate-600 font-mono tracking-widest">ODER</span>
                <div className="flex-1 h-px bg-slate-700/60" />
              </div>
              <a
                href="/api/auth/saml/login"
                className="mt-3 flex items-center justify-center gap-2 w-full px-4 py-2 rounded
                           border border-purple-700/60 bg-purple-950/30 text-purple-300
                           hover:bg-purple-900/40 hover:border-purple-600 transition-colors
                           text-sm font-medium tracking-wide"
              >
                MIT SSO ANMELDEN
              </a>
            </>
          )}
        </div>

        {/* Demo-Hint */}
        <button
          type="button"
          onClick={() => { setUsername('demo'); setPassword('demo'); setError(''); }}
          className="mt-5 w-full cyjan-demo-hint group"
          title="Demo-Zugangsdaten übernehmen"
        >
          <span className="cyjan-demo-pill">DEMO</span>
          <span className="cyjan-demo-text">
            Zum Ausprobieren: <code>demo</code> / <code>demo</code>
            <span className="cyjan-demo-sub">→ klicken, um Felder zu füllen</span>
          </span>
        </button>

        <p className="text-center text-[10px] text-slate-600 mt-6 tracking-[3px] font-mono uppercase">
          Nur autorisierter Zugriff
        </p>
      </div>
    </div>
  );
}
