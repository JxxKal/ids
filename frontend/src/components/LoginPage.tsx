import { useState } from 'react';
import { login, setToken } from '../api';
import type { User } from '../types';

interface Props {
  onLogin: (user: User, token: string) => void;
}

export function LoginPage({ onLogin }: Props) {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [error,    setError]    = useState('');
  const [loading,  setLoading]  = useState(false);

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const res = await login(username, password);
      setToken(res.access_token);
      onLogin(res.user, res.access_token);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Anmeldung fehlgeschlagen');
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-slate-950">
      <div className="w-full max-w-sm">

        {/* Logo + Titel */}
        <div className="flex flex-col items-center mb-8 gap-3">
          <img src="/cyjan.png" alt="Cyjan" className="h-16 w-auto" />
          <div className="text-center">
            <h1 className="text-xl font-semibold text-slate-100">Cyjan IDS</h1>
            <p className="text-xs text-slate-500 mt-0.5">OT Sentrymode</p>
          </div>
        </div>

        {/* Login-Karte */}
        <div className="card p-6">
          <h2 className="text-sm font-semibold text-slate-300 mb-4">Anmelden</h2>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="flex flex-col gap-1">
              <label htmlFor="login-user" className="text-xs text-slate-400">Benutzername</label>
              <input
                id="login-user"
                name="username"
                type="text"
                autoComplete="username"
                className="input"
                required
                autoFocus
                value={username}
                onChange={e => setUsername(e.target.value)}
              />
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="login-pw" className="text-xs text-slate-400">Passwort</label>
              <input
                id="login-pw"
                name="password"
                type="password"
                autoComplete="current-password"
                className="input"
                required
                value={password}
                onChange={e => setPassword(e.target.value)}
              />
            </div>

            {error && (
              <p className="text-xs text-red-400 bg-red-950/40 border border-red-800/40 rounded px-3 py-2">
                {error}
              </p>
            )}

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full justify-center"
            >
              {loading ? 'Anmelden…' : 'Anmelden'}
            </button>
          </form>
        </div>

        <p className="text-center text-xs text-slate-700 mt-4">
          Nur autorisierter Zugriff
        </p>
      </div>
    </div>
  );
}
