import { CheckCircle2, XCircle } from 'lucide-react';
import { useEffect, useState } from 'react';
import { getConfig, itopTest, patchConfig } from '../../api';
import { de } from '../../i18n/de';

export default function ItopPanel() {
  const [cfg, setCfg] = useState<Record<string, unknown>>({});
  const [status, setStatus] = useState<string | null>(null);
  const [test, setTest] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => { getConfig('itop').then(setCfg); }, []);
  const set = (k: string, v: unknown) => setCfg((c) => ({ ...c, [k]: v }));

  async function save() {
    setBusy(true);
    try {
      setCfg(await patchConfig('itop', cfg));
      setStatus(de.settings.saved);
    } catch (e) {
      setStatus(`${de.common.error}: ${e instanceof Error ? e.message : e}`);
    } finally { setBusy(false); }
  }

  async function runTest() {
    setBusy(true);
    setTest(null);
    try {
      const r = await itopTest();
      setTest({ ok: true, text: `OK — Organisationen: ${r.organisations.join(', ')}` });
    } catch (e) {
      setTest({ ok: false, text: e instanceof Error ? e.message : String(e) });
    } finally { setBusy(false); }
  }

  return (
    <div className="fwpt-card space-y-3">
      <h2 className="font-medium text-slate-100">{de.settings.itop}</h2>
      <div className="grid gap-3 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label className="mb-1 block text-xs text-slate-400">Base-URL</label>
          <input className="fwpt-input" value={(cfg.base_url as string) ?? ''}
            placeholder="https://itop.example.net/itop" onChange={(e) => set('base_url', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">Benutzer</label>
          <input className="fwpt-input" value={(cfg.user as string) ?? ''}
            onChange={(e) => set('user', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">Passwort</label>
          <input className="fwpt-input" type="password" value={(cfg.password as string) ?? ''}
            onChange={(e) => set('password', e.target.value)} />
        </div>
        <div>
          <label className="mb-1 block text-xs text-slate-400">Org-Filter (optional)</label>
          <input className="fwpt-input" value={(cfg.org_filter as string) ?? ''}
            onChange={(e) => set('org_filter', e.target.value)} />
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm text-slate-300">
        <input type="checkbox" checked={(cfg.ssl_verify as boolean) ?? true}
          onChange={(e) => set('ssl_verify', e.target.checked)} />
        TLS-Zertifikat prüfen
      </label>
      {test && (
        <div className={`flex items-start gap-2 text-sm ${test.ok ? 'text-emerald-400' : 'text-red-400'}`}>
          {test.ok ? <CheckCircle2 size={16} className="mt-0.5" /> : <XCircle size={16} className="mt-0.5" />}
          <span>{test.text}</span>
        </div>
      )}
      <div className="flex items-center gap-2">
        <button type="button" className="fwpt-btn" onClick={save} disabled={busy}>{de.settings.save}</button>
        <button type="button" className="fwpt-btn-ghost" onClick={runTest} disabled={busy}>{de.settings.test}</button>
        {status && <span className="text-sm text-slate-400">{status}</span>}
      </div>
    </div>
  );
}
