import { CheckCircle2, RefreshCw, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { fmgSync, fmgSyncStatus, fmgTest, getConfig, patchConfig } from '../../api';
import { de } from '../../i18n/de';
import type { SyncStatus } from '../../types';

export default function FmgPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [testResult, setTestResult] = useState<{ ok: boolean; text: string; adoms: string[] } | null>(null);
  const [sync, setSync] = useState<SyncStatus | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getConfig('fmg').then(setCfg);
    fmgSyncStatus().then(setSync).catch(() => undefined);
  }, []);

  useEffect(() => {
    if (sync?.phase !== 'running') return;
    const t = setInterval(() => fmgSyncStatus().then(setSync), 2000);
    return () => clearInterval(t);
  }, [sync?.phase]);

  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));
  const authMode = (cfg.auth_mode as string) ?? 'token';
  const selectedAdoms = (cfg.adoms as string[]) ?? [];

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('fmg', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally {
      setBusy(false);
    }
  }

  async function test() {
    setBusy(true);
    setTestResult(null);
    try {
      const r = await fmgTest();
      setTestResult({ ok: true, text: `FMG ${r.version ?? '?'}`, adoms: r.adoms });
    } catch (e) {
      setTestResult({ ok: false, text: e instanceof Error ? e.message : String(e), adoms: [] });
    } finally {
      setBusy(false);
    }
  }

  async function startSync() {
    try {
      await fmgSync();
      setSync(await fmgSyncStatus());
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    }
  }

  return (
    <div className="fwpt-card space-y-3">
      <h2 className="font-medium text-slate-100">{de.settings.fmg}</h2>
      <div className="grid gap-3 sm:grid-cols-2">
        <div>
          <label className="mb-1 block text-xs text-slate-400">Host</label>
          <input className="fwpt-input" value={(cfg.host as string) ?? ''}
            placeholder="fmg.example.net" onChange={(e) => set('host', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">Auth-Modus</label>
          <select className="fwpt-input" value={authMode}
            onChange={(e) => set('auth_mode', e.target.value)}>
            <option value="token">API-Token (FMG ≥ 7.2.2)</option>
            <option value="session">User/Passwort (Session)</option>
          </select>
        </div>
        {authMode === 'token' ? (
          <div className="sm:col-span-2">
            <label className="mb-1 block text-xs text-slate-400">API-Token</label>
            <input className="fwpt-input" type="password" value={(cfg.token as string) ?? ''}
              onChange={(e) => set('token', e.target.value)} />
          </div>
        ) : (
          <>
            <div>
              <label className="mb-1 block text-xs text-slate-400">Benutzer</label>
              <input className="fwpt-input" value={(cfg.username as string) ?? ''}
                onChange={(e) => set('username', e.target.value)} />
            </div>
            <div>
              <label className="mb-1 block text-xs text-slate-400">Passwort</label>
              <input className="fwpt-input" type="password" value={(cfg.password as string) ?? ''}
                onChange={(e) => set('password', e.target.value)} />
            </div>
          </>
        )}
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={(cfg.ssl_verify as boolean) ?? true}
          onChange={(e) => set('ssl_verify', e.target.checked)} />
        TLS-Zertifikat prüfen
      </label>

      {testResult && (
        <div className={`flex items-start gap-2 text-sm ${testResult.ok ? 'text-emerald-400' : 'text-red-400'}`}>
          {testResult.ok ? <CheckCircle2 size={16} className="mt-0.5" /> : <XCircle size={16} className="mt-0.5" />}
          <span>{testResult.text}</span>
        </div>
      )}
      {testResult?.ok && testResult.adoms.length > 0 && (
        <div>
          <p className="mb-1 text-xs text-slate-400">ADOMs (für Sync auswählen)</p>
          <div className="flex flex-wrap gap-2">
            {testResult.adoms.map((a) => (
              <label key={a} className="flex items-center gap-1.5 rounded border border-slate-700 px-2 py-1 text-sm">
                <input
                  type="checkbox"
                  checked={selectedAdoms.includes(a)}
                  onChange={(e) => set('adoms', e.target.checked
                    ? [...selectedAdoms, a]
                    : selectedAdoms.filter((x) => x !== a))}
                />
                {a}
              </label>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={test} disabled={busy}>{de.settings.test}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={startSync}
          disabled={busy || sync?.phase === 'running'}>
          <RefreshCw size={14} className={sync?.phase === 'running' ? 'animate-spin' : ''} />
          {sync?.phase === 'running' ? de.settings.syncRunning : de.settings.sync}
        </button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>

      {sync && sync.log.length > 0 && (
        <pre className="max-h-40 overflow-auto rounded-md bg-slate-950 p-2 text-xs text-slate-400">
          {sync.log.join('\n')}
        </pre>
      )}
    </div>
  );
}
