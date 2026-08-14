// ── AppConnectSettings — Einstellungen → Integrationen → CYJAN App ───────────
//
// GUI für den app-connect-Dienst: Status, Konfiguration, Egress-Test,
// Gerätekopplung und Geräteverwaltung.
//
// Backend: /api/app-connect (api/src/routers/app_connect.py). Der Router hält
// die Konfiguration in system_config['app_connect'] und reicht Status, Pairing,
// Geräte und Egress-Test an den app-connect-Container weiter.
//
// Zwei Dinge, die hier bewusst so gebaut sind:
//
//  1. Die Section bleibt vollständig bedienbar, wenn der Dienst NICHT läuft.
//     Genau dann braucht man sie ja — der Container ist erst konfigurierbar,
//     bevor er etwas tut. Ein 503 aus dem Proxy-Router wird als Hinweis
//     gerendert, nicht als Fehler.
//  2. Das QR-SVG wird als data:-URI in ein <img> gehängt und NICHT per
//     dangerouslySetInnerHTML eingesetzt. Der Inhalt kommt zwar aus dem
//     eigenen Backend, aber ein QR-Bild rechtfertigt keinen DOM-Injektionspfad
//     (so steht es auch im Vertrag, app-connect/docs/internal-api.md).

import { useCallback, useEffect, useRef, useState } from 'react';
import {
  Check, Copy, LoaderCircle, QrCode, RefreshCw, Smartphone, TriangleAlert, Trash2, X,
} from 'lucide-react';
import { CollapsibleHelp } from './CollapsibleHelp';
import { ConfirmDialog } from './ConfirmDialog';
import {
  fetchAppConnectConfig, fetchAppConnectDevices, fetchAppConnectStatus,
  isAppConnectUnavailable, pairAppConnectDevice, revokeAppConnectDevice,
  saveAppConnectConfig, testAppConnectEgress,
} from '../api';
import type {
  AppConnectConfig, AppConnectConfigResponse, AppConnectDevice,
  AppConnectEgressResult, AppConnectPairResult, AppConnectSeverity, AppConnectStatus,
} from '../api';

const SEVERITIES: AppConnectSeverity[] = ['low', 'medium', 'high', 'critical'];

const DEFAULT_CONFIG: AppConnectConfig = {
  enabled:      false,
  proxy_url:    '',
  sentry_name:  '',
  https_proxy:  '',
  no_proxy:     '',
  ca_file:      '',
  allow_triage: false,
  severity_min: 'medium',
};

// Verbindungszustände aus dem Vertrag, mit deutschem Klartext und Farbe.
const CONNECTION_META: Record<string, { label: string; cls: string }> = {
  connected:    { label: 'verbunden',       cls: 'text-emerald-300 bg-emerald-900/30 border-emerald-700/40' },
  reconnecting: { label: 'verbindet neu',   cls: 'text-amber-300 bg-amber-900/30 border-amber-700/40' },
  starting:     { label: 'startet',         cls: 'text-cyan-300 bg-cyan-900/30 border-cyan-700/40' },
  down:         { label: 'getrennt',        cls: 'text-red-300 bg-red-900/30 border-red-700/40' },
  dormant:      { label: 'im Ruhezustand',  cls: 'text-slate-400 bg-slate-800/40 border-slate-700/40' },
};

// Feste Stufenleiter für den Egress-Test. Der Dienst liefert nur die Stufen,
// die er tatsächlich erreicht hat — die restlichen zeigen wir als "nicht
// erreicht", damit man sieht, WO der Weg abgebrochen ist.
const EGRESS_STAGES: Array<{ key: string; label: string }> = [
  { key: 'dns',     label: 'DNS-Auflösung' },
  { key: 'connect', label: 'CONNECT (TCP / Proxy)' },
  { key: 'tls',     label: 'TLS-Handshake' },
  { key: 'cert',    label: 'Zertifikatsprüfung' },
];

/** SVG → data:-URI. Umweg über TextEncoder, weil btoa() an Umlauten und
 *  sonstigen Nicht-Latin1-Zeichen im SVG scheitern würde. */
function svgToDataUri(svg: string): string {
  const bytes = new TextEncoder().encode(svg);
  let binary = '';
  bytes.forEach(b => { binary += String.fromCharCode(b); });
  return `data:image/svg+xml;base64,${btoa(binary)}`;
}

function fmtDate(value: string | null | undefined): string {
  if (!value) return '—';
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString();
}

function fmtSince(epochSeconds: number | null): string {
  if (!epochSeconds) return '—';
  const d = new Date(epochSeconds * 1000);
  return Number.isNaN(d.getTime()) ? '—' : d.toLocaleString();
}

function errText(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}


export function AppConnectSettings() {
  // ── Konfiguration ─────────────────────────────────────────────────────────
  const [form,        setForm]        = useState<AppConnectConfig>(DEFAULT_CONFIG);
  const [meta,        setMeta]        = useState<AppConnectConfigResponse | null>(null);
  const [tokenInput,  setTokenInput]  = useState('');
  const [clearToken,  setClearToken]  = useState(false);
  const [showToken,   setShowToken]   = useState(false);
  const [loadErr,     setLoadErr]     = useState('');
  const [saving,      setSaving]      = useState(false);
  const [saveMsg,     setSaveMsg]     = useState<{ ok: boolean; text: string } | null>(null);

  // ── Status / Geräte (Auto-Refresh) ────────────────────────────────────────
  const [status,      setStatus]      = useState<AppConnectStatus | null>(null);
  const [serviceDown, setServiceDown] = useState(false);
  const [statusErr,   setStatusErr]   = useState('');
  const [devices,     setDevices]     = useState<AppConnectDevice[]>([]);
  const [devicesErr,  setDevicesErr]  = useState('');

  // ── Egress-Test ───────────────────────────────────────────────────────────
  const [testing,     setTesting]     = useState(false);
  const [testResult,  setTestResult]  = useState<AppConnectEgressResult | null>(null);
  const [testErr,     setTestErr]     = useState('');

  // ── Kopplung ──────────────────────────────────────────────────────────────
  const [pairOpen,    setPairOpen]    = useState(false);
  const [pairLabel,   setPairLabel]   = useState('');
  const [pairBusy,    setPairBusy]    = useState(false);
  const [pairErr,     setPairErr]     = useState('');
  const [pairResult,  setPairResult]  = useState<AppConnectPairResult | null>(null);
  const [codeCopied,  setCodeCopied]  = useState(false);
  const [nowTick,     setNowTick]     = useState(() => Date.now());

  // ── Widerruf ──────────────────────────────────────────────────────────────
  const [revokeTarget, setRevokeTarget] = useState<AppConnectDevice | null>(null);
  const [revokeBusy,   setRevokeBusy]   = useState(false);

  // Die Formularfelder werden GENAU EINMAL aus dem Server-Stand befüllt.
  // Andernfalls würde der 15-s-Poller jede Eingabe unter den Fingern
  // zurücksetzen (dieselbe Falle wie bei der ML-Tuning-Card).
  const hydrated = useRef(false);

  const loadConfig = useCallback(async () => {
    try {
      const resp = await fetchAppConnectConfig();
      setMeta(resp);
      setLoadErr('');
      if (!hydrated.current) {
        hydrated.current = true;
        setForm(resp.config);
      }
    } catch (e) {
      setLoadErr(errText(e));
    }
  }, []);

  const loadRuntime = useCallback(async () => {
    try {
      const s = await fetchAppConnectStatus();
      setStatus(s);
      setServiceDown(false);
      setStatusErr('');
    } catch (e) {
      setStatus(null);
      if (isAppConnectUnavailable(e)) {
        setServiceDown(true);
        setStatusErr('');
      } else {
        setServiceDown(false);
        setStatusErr(errText(e));
      }
      setDevices([]);
      return;
    }
    try {
      setDevices(await fetchAppConnectDevices());
      setDevicesErr('');
    } catch (e) {
      setDevices([]);
      setDevicesErr(isAppConnectUnavailable(e) ? '' : errText(e));
    }
  }, []);

  useEffect(() => { void loadConfig(); }, [loadConfig]);

  useEffect(() => {
    void loadRuntime();
    const id = window.setInterval(() => { void loadRuntime(); }, 15_000);
    return () => window.clearInterval(id);
  }, [loadRuntime]);

  // Sekunden-Ticker nur solange ein Kopplungscode offen ist — der Countdown
  // muss laufen, der Rest der Section braucht keine 1-Hz-Renderrunde.
  useEffect(() => {
    if (!pairResult) return;
    const id = window.setInterval(() => setNowTick(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [pairResult]);

  function flash(ok: boolean, text: string) {
    setSaveMsg({ ok, text });
    window.setTimeout(() => setSaveMsg(null), 6000);
  }

  const envFields = meta?.env_fields ?? [];
  const isEnv = (field: string) => envFields.includes(field);
  const envValue = (field: string) => meta?.env_values?.[field] ?? '';
  const tokenSet = meta?.device_token_set ?? false;

  // ── Speichern ─────────────────────────────────────────────────────────────
  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    if (loadErr) {
      flash(false, 'Konfiguration konnte nicht geladen werden — Speichern blockiert, damit '
                 + 'die Server-Konfiguration nicht mit Defaults überschrieben wird. Seite neu laden.');
      return;
    }
    setSaving(true);
    try {
      const resp = await saveAppConnectConfig({
        ...form,
        device_token:       clearToken ? '' : tokenInput,
        clear_device_token: clearToken,
      });
      setMeta(resp);
      setForm(resp.config);
      setTokenInput('');
      setClearToken(false);
      flash(true, 'Gespeichert. app-connect übernimmt die Änderung beim nächsten Poll (~30 s).');
      void loadRuntime();
    } catch (e) {
      flash(false, errText(e));
    } finally {
      setSaving(false);
    }
  }

  // ── Egress-Test (gegen die aktuell im Formular stehenden Werte) ───────────
  async function handleTest() {
    setTesting(true);
    setTestErr('');
    setTestResult(null);
    try {
      setTestResult(await testAppConnectEgress({
        proxy_url:   form.proxy_url,
        https_proxy: form.https_proxy,
        no_proxy:    form.no_proxy,
        ca_file:     form.ca_file,
      }));
    } catch (e) {
      setTestErr(isAppConnectUnavailable(e)
        ? 'App-Connect-Dienst läuft nicht — der Egress-Test läuft im Container und braucht ihn.'
        : errText(e));
    } finally {
      setTesting(false);
    }
  }

  // ── Kopplung ──────────────────────────────────────────────────────────────
  async function handlePair() {
    setPairBusy(true);
    setPairErr('');
    try {
      const res = await pairAppConnectDevice(pairLabel.trim() || 'Neues Gerät');
      setPairResult(res);
      setNowTick(Date.now());
      setPairOpen(false);
      setPairLabel('');
    } catch (e) {
      setPairErr(isAppConnectUnavailable(e)
        ? 'App-Connect-Dienst läuft nicht — ohne ihn gibt es keinen Kopplungscode.'
        : errText(e));
    } finally {
      setPairBusy(false);
    }
  }

  async function copyCode(code: string) {
    let ok = false;
    if (navigator.clipboard?.writeText) {
      try { await navigator.clipboard.writeText(code); ok = true; } catch { ok = false; }
    }
    if (!ok) {
      // Fallback für HTTP-Kontexte, in denen die Clipboard-API fehlt.
      try {
        const ta = document.createElement('textarea');
        ta.value = code;
        ta.setAttribute('readonly', '');
        document.body.appendChild(ta);
        ta.select();
        ok = document.execCommand('copy');
        document.body.removeChild(ta);
      } catch { ok = false; }
    }
    if (ok) {
      setCodeCopied(true);
      window.setTimeout(() => setCodeCopied(false), 2500);
    }
  }

  async function doRevoke() {
    if (!revokeTarget) return;
    setRevokeBusy(true);
    try {
      await revokeAppConnectDevice(revokeTarget.id);
      setRevokeTarget(null);
      await loadRuntime();
    } catch (e) {
      setDevicesErr(errText(e));
      setRevokeTarget(null);
    } finally {
      setRevokeBusy(false);
    }
  }

  // Countdown bis expires_at
  let pairRemaining = '';
  let pairExpired = false;
  if (pairResult) {
    const ms = new Date(pairResult.expires_at).getTime() - nowTick;
    if (Number.isNaN(ms)) {
      pairRemaining = '—';
    } else if (ms <= 0) {
      pairExpired = true;
      pairRemaining = 'abgelaufen';
    } else {
      const total = Math.floor(ms / 1000);
      pairRemaining = `${Math.floor(total / 60)}:${String(total % 60).padStart(2, '0')}`;
    }
  }

  const conn = status ? (CONNECTION_META[status.connection] ?? CONNECTION_META.dormant) : null;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h2 className="text-sm font-semibold text-slate-200 flex items-center gap-2">
          <Smartphone size={15} className="text-cyan-400" />
          CYJAN App
        </h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-cyan-500"
            checked={form.enabled}
            onChange={e => setForm(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={form.enabled ? 'text-cyan-300 font-medium' : 'text-slate-500'}>Aktiv</span>
        </label>
      </div>

      <CollapsibleHelp>
        <p className="text-xs text-slate-500 leading-relaxed">
          Verbindet diesen Master über eine ausgehende Verbindung (Port 443) mit dem CYJAN-Cloud-Proxy,
          damit gekoppelte Smartphones Alarme und Threat-Level sehen. Es wird <strong>kein Port geöffnet</strong> —
          die Verbindung baut immer der Master nach draußen auf. Ohne Proxy-URL und Device-Token bleibt der
          Dienst im Ruhezustand.
        </p>
      </CollapsibleHelp>

      {loadErr && (
        <div className="rounded border border-red-700/50 bg-red-900/20 p-3 text-xs text-red-300">
          Konfiguration konnte nicht geladen werden: {loadErr}
        </div>
      )}

      {/* ── Statuszeile ──────────────────────────────────────────────────── */}
      <div className="rounded-lg border border-slate-700/40 bg-slate-900/40 p-3 space-y-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">Status</span>
          {status && conn ? (
            <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${conn.cls}`}>
              {conn.label}
            </span>
          ) : (
            <span className="text-[10px] font-mono px-2 py-0.5 rounded border text-slate-400 bg-slate-800/40 border-slate-700/40">
              {serviceDown ? 'Dienst läuft nicht' : 'lade …'}
            </span>
          )}
          <button type="button" onClick={() => void loadRuntime()}
            className="btn-ghost text-[10px] flex items-center gap-1" title="Status neu laden">
            <RefreshCw size={11} /> aktualisieren
          </button>
        </div>

        {status ? (
          <>
            <div className="grid grid-cols-2 gap-x-4 gap-y-1.5 text-[11px] sm:grid-cols-3 md:grid-cols-4">
              <div>
                <div className="text-slate-500">Sentry-Name</div>
                <div className="font-mono text-slate-200 truncate" title={status.sentry_name}>
                  {status.sentry_name || '—'}
                </div>
              </div>
              <div>
                <div className="text-slate-500">Proxy-Version</div>
                <div className="font-mono text-slate-300">{status.proxy_version || '—'}</div>
              </div>
              <div>
                <div className="text-slate-500">Push</div>
                <div className={status.push_enabled ? 'text-emerald-300' : 'text-slate-400'}>
                  {status.push_enabled ? 'aktiv' : 'inaktiv'}
                </div>
              </div>
              <div>
                <div className="text-slate-500">Ereignisse gesendet</div>
                <div className="font-mono text-slate-200 tabular-nums">
                  {status.events_sent.toLocaleString()}
                  {status.events_dropped > 0 && (
                    <span className="text-amber-400"> / {status.events_dropped.toLocaleString()} verworfen</span>
                  )}
                </div>
              </div>
              <div>
                <div className="text-slate-500">Verbunden seit</div>
                <div className="font-mono text-slate-400">{fmtSince(status.connected_since)}</div>
              </div>
              <div>
                <div className="text-slate-500">Schreibzugriff</div>
                <div className={status.read_only ? 'text-slate-300' : 'text-amber-300'}>
                  {status.read_only ? 'nur lesen' : 'Triage erlaubt'}
                </div>
              </div>
              <div>
                <div className="text-slate-500">Egress</div>
                <div className="font-mono text-slate-400 truncate" title={status.egress ?? 'direkt'}>
                  {status.egress ?? 'direkt'}
                  <span className="text-slate-600"> ({status.egress_source})</span>
                </div>
              </div>
              <div>
                <div className="text-slate-500">RPCs (ok/abgelehnt/Fehler)</div>
                <div className="font-mono text-slate-400 tabular-nums">
                  {status.rpc_ok}/{status.rpc_rejected}/{status.rpc_failed}
                </div>
              </div>
            </div>
            {status.last_error && (
              <p className="text-[11px] text-amber-300 flex items-start gap-1.5">
                <TriangleAlert size={12} className="mt-0.5 shrink-0" />
                <span className="break-all">{status.last_error}</span>
              </p>
            )}
            {!status.configured && (
              <p className="text-[11px] text-slate-500">
                Noch nicht eingerichtet — Proxy-URL und Device-Token fehlen. Beides steht unten im Formular.
              </p>
            )}
          </>
        ) : serviceDown ? (
          <div className="text-[11px] text-slate-400 leading-relaxed space-y-1">
            <p>
              Der App-Connect-Dienst läuft nicht. Das ist der Normalfall, solange die Integration nicht
              genutzt wird — die Einstellungen unten lassen sich trotzdem speichern und greifen, sobald
              der Dienst startet.
            </p>
            <p className="text-slate-500">
              Starten: <span className="font-mono text-violet-300">docker compose --profile prod up -d app-connect</span> auf dem Master.
            </p>
          </div>
        ) : statusErr ? (
          <p className="text-[11px] text-red-400">{statusErr}</p>
        ) : null}
      </div>

      {/* ── Konfigurationsformular ───────────────────────────────────────── */}
      <form onSubmit={handleSave} className={`space-y-5 ${!form.enabled ? 'opacity-70' : ''}`}>

        <div className="space-y-3">
          <h3 className="text-[11px] uppercase tracking-wider text-slate-500">Cloud-Proxy</h3>
          <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-2">
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Proxy-URL</label>
              <input className="input font-mono"
                placeholder={isEnv('proxy_url') ? `${envValue('proxy_url')} (aus ENV)` : 'wss://proxy.cyjan.dev/tunnel'}
                value={form.proxy_url}
                onChange={e => setForm(c => ({ ...c, proxy_url: e.target.value }))} />
              <span className="text-[10px] text-slate-600">
                muss mit <span className="font-mono">wss://</span> beginnen
                {isEnv('proxy_url') && ' · leer lassen übernimmt den ENV-Wert'}
              </span>
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Sentry-Name</label>
              <input className="input font-mono"
                placeholder={isEnv('sentry_name') ? `${envValue('sentry_name')} (aus ENV)` : 'cyjan-master'}
                value={form.sentry_name}
                onChange={e => setForm(c => ({ ...c, sentry_name: e.target.value }))} />
              <span className="text-[10px] text-slate-600">Name, unter dem dieser Master in der App erscheint</span>
            </div>

            <div className="flex flex-col gap-1 md:col-span-2">
              <label className="text-slate-400 flex items-center gap-2">
                Device-Token
                {tokenSet && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-emerald-700/40 bg-emerald-900/20 text-emerald-300">
                    gesetzt
                  </span>
                )}
                {!tokenSet && isEnv('device_token') && (
                  <span className="text-[10px] font-mono px-1.5 py-0.5 rounded border border-slate-700 bg-slate-800/40 text-slate-400">
                    aus ENV
                  </span>
                )}
              </label>
              <div className="flex flex-col gap-2 sm:flex-row">
                <input
                  className="input font-mono flex-1"
                  type={showToken ? 'text' : 'password'}
                  autoComplete="new-password"
                  disabled={clearToken}
                  placeholder={
                    clearToken ? '(wird beim Speichern entfernt)'
                      : tokenSet ? '•••••••• gesetzt — leer lassen behält es'
                      : 'Token aus dem CYJAN-Portal einfügen'
                  }
                  value={tokenInput}
                  onChange={e => setTokenInput(e.target.value)}
                />
                <div className="flex gap-2">
                  <button type="button" className="btn-ghost text-xs"
                    onClick={() => setShowToken(v => !v)} disabled={clearToken}>
                    {showToken ? 'Verbergen' : 'Zeigen'}
                  </button>
                  {(tokenSet || clearToken) && (
                    <button type="button"
                      className={clearToken ? 'btn-ghost text-xs text-amber-300' : 'btn-danger text-xs'}
                      onClick={() => { setClearToken(v => !v); setTokenInput(''); }}>
                      {clearToken ? 'Doch behalten' : 'Token entfernen'}
                    </button>
                  )}
                </div>
              </div>
              <span className="text-[10px] text-slate-600">
                Wird nie zurückgeliefert — die Oberfläche zeigt nur, ob eines hinterlegt ist.
                Ein leeres Feld lässt das gespeicherte Token unangetastet.
              </span>
            </div>
          </div>
        </div>

        {/* Egress */}
        <div className="space-y-3">
          <h3 className="text-[11px] uppercase tracking-wider text-slate-500">Ausgehender Weg</h3>
          <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-2">
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Egress-Proxy</label>
              <input className="input font-mono"
                placeholder={isEnv('https_proxy') ? `${envValue('https_proxy')} (aus ENV)` : 'http://proxy.kunde.local:3128'}
                value={form.https_proxy}
                onChange={e => setForm(c => ({ ...c, https_proxy: e.target.value }))} />
              <span className="text-[10px] text-slate-600">
                leer = direkt ins Internet · Anmeldedaten gehören in die URL (<span className="font-mono">http://user:pass@host:3128</span>)
              </span>
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-slate-400">CA-Datei</label>
              <input className="input font-mono"
                placeholder={isEnv('ca_file') ? `${envValue('ca_file')} (aus ENV)` : '/etc/cyjan/certs/corp-ca.pem'}
                value={form.ca_file}
                onChange={e => setForm(c => ({ ...c, ca_file: e.target.value }))} />
              <span className="text-[10px] text-slate-600">
                nötig bei TLS-inspizierendem Firmen-Proxy · Pfad im Container
              </span>
            </div>

            <div className="flex flex-col gap-1 md:col-span-2">
              <label className="text-slate-400">Kein Proxy für (no_proxy)</label>
              <input className="input font-mono"
                placeholder="10.0.0.0/8,.intern.example"
                value={form.no_proxy}
                onChange={e => setForm(c => ({ ...c, no_proxy: e.target.value }))} />
              <span className="text-[10px] text-slate-600">kommagetrennt · CIDR-Einträge werden verstanden</span>
            </div>
          </div>

          {/* Verbindungstest gegen die aktuell eingetippten Werte */}
          <div className="flex items-center gap-2 flex-wrap">
            <button type="button" className="btn-primary text-xs flex items-center gap-1.5"
              onClick={() => void handleTest()} disabled={testing}>
              {testing && <LoaderCircle size={12} className="animate-spin" />}
              {testing ? 'teste …' : 'Verbindung testen'}
            </button>
            <span className="text-[10px] text-slate-600">
              prüft die Werte aus dem Formular — vor dem Speichern
            </span>
          </div>

          {testErr && <p className="text-xs text-red-400">{testErr}</p>}

          {testResult && (
            <div className={`rounded border p-3 space-y-2 ${
              testResult.ok
                ? 'border-emerald-700/40 bg-emerald-900/10'
                : 'border-red-700/40 bg-red-900/10'}`}>
              <div className="flex items-center gap-2 text-xs font-medium">
                {testResult.ok
                  ? <><Check size={14} className="text-emerald-400" /><span className="text-emerald-300">Weg nach draußen ist frei</span></>
                  : <><X size={14} className="text-red-400" /><span className="text-red-300">Fehlgeschlagen bei „{testResult.stage}"</span></>}
              </div>
              <ul className="space-y-1">
                {EGRESS_STAGES.map(stage => {
                  const step = testResult.steps.find(s => s.name.toLowerCase() === stage.key);
                  return (
                    <li key={stage.key} className="flex items-start gap-2 text-[11px]">
                      {step
                        ? (step.ok
                            ? <Check size={12} className="text-emerald-400 mt-0.5 shrink-0" />
                            : <X size={12} className="text-red-400 mt-0.5 shrink-0" />)
                        : <span className="w-3 text-center text-slate-600 shrink-0">–</span>}
                      <span className={step ? (step.ok ? 'text-slate-300' : 'text-red-300') : 'text-slate-600'}>
                        <span className="font-medium">{stage.label}</span>
                        {step
                          ? (step.detail ? ` — ${step.detail}` : '')
                          : ' — nicht erreicht'}
                      </span>
                    </li>
                  );
                })}
              </ul>
              {testResult.detail && (
                <p className={`text-[11px] ${testResult.ok ? 'text-slate-400' : 'text-red-300'}`}>
                  {testResult.detail}
                </p>
              )}
              {testResult.hint && (
                <p className="text-[11px] text-amber-300 flex items-start gap-1.5">
                  <TriangleAlert size={12} className="mt-0.5 shrink-0" />
                  <span>{testResult.hint}</span>
                </p>
              )}
            </div>
          )}
        </div>

        {/* Verhalten */}
        <div className="space-y-3">
          <h3 className="text-[11px] uppercase tracking-wider text-slate-500">Verhalten</h3>
          <div className="grid grid-cols-1 gap-3 text-xs md:grid-cols-2">
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Mindest-Severity</label>
              <select className="input"
                value={form.severity_min}
                onChange={e => setForm(c => ({ ...c, severity_min: e.target.value as AppConnectSeverity }))}>
                {SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
              </select>
              <span className="text-[10px] text-slate-600">darunter geht nichts an die App</span>
            </div>

            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Triage aus der App</label>
              <label className="flex items-center gap-2 cursor-pointer select-none pt-1.5">
                <input type="checkbox" className="accent-amber-500"
                  checked={form.allow_triage}
                  onChange={e => setForm(c => ({ ...c, allow_triage: e.target.checked }))} />
                <span className={form.allow_triage ? 'text-amber-300 font-medium' : 'text-slate-500'}>
                  Schreibzugriff erlauben
                </span>
              </label>
            </div>
          </div>

          {form.allow_triage && (
            <div className="rounded border border-amber-600/40 bg-amber-900/15 p-3 text-[11px] text-amber-200 flex items-start gap-2">
              <TriangleAlert size={14} className="mt-0.5 shrink-0" />
              <span>
                <strong>Achtung:</strong> Damit darf die App Alarme als richtig oder falsch markieren.
                Diese Markierungen fließen ins ML-Retraining ein und verschieben die Schwellwerte der
                Heuristiken — eine Fehlmarkierung vom Handy wirkt also dauerhaft auf die Erkennung.
                Ohne diesen Schalter ist die Verbindung strikt lesend.
              </span>
            </div>
          )}
        </div>

        <div className="flex items-center justify-between gap-3 flex-wrap pt-1">
          <div className="flex flex-col gap-1">
            {saveMsg && (
              <span className={`text-xs ${saveMsg.ok ? 'text-green-400' : 'text-red-400'}`}>
                {saveMsg.text}
              </span>
            )}
            {meta?.config_source === 'env' && (
              <span className="text-[10px] text-slate-500">
                Der Dienst arbeitet aktuell mit ENV-Werten. Was hier gespeichert wird, überlagert sie Feld für Feld.
              </span>
            )}
          </div>
          <button type="submit" className="btn-primary text-xs" disabled={saving}>
            {saving ? 'speichert …' : 'Speichern'}
          </button>
        </div>
      </form>

      {/* ── Geräte ───────────────────────────────────────────────────────── */}
      <div className="space-y-3 border-t border-slate-800 pt-4">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <h3 className="text-[11px] uppercase tracking-wider text-slate-500">Gekoppelte Geräte</h3>
          <button type="button" className="btn-primary text-xs flex items-center gap-1.5"
            onClick={() => { setPairOpen(true); setPairErr(''); }}>
            <QrCode size={12} /> Gerät koppeln
          </button>
        </div>

        {devicesErr && <p className="text-xs text-red-400">{devicesErr}</p>}

        {serviceDown ? (
          <p className="text-[11px] text-slate-500">
            Geräteliste nicht abrufbar, solange der Dienst nicht läuft — sie liegt beim Cloud-Proxy.
          </p>
        ) : devices.length === 0 ? (
          <p className="text-[11px] text-slate-500">
            Noch kein Gerät gekoppelt. „Gerät koppeln" erzeugt einen Code, den die CYJAN-App scannt oder eintippt.
          </p>
        ) : (
          <>
            {/* Desktop: Tabelle */}
            <div className="hidden md:block overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-slate-400 border-b border-slate-700/50">
                    <th className="text-left px-2 py-1.5">Bezeichnung</th>
                    <th className="text-left px-2 py-1.5">Plattform</th>
                    <th className="text-left px-2 py-1.5">Erstellt</th>
                    <th className="text-left px-2 py-1.5">Zuletzt gesehen</th>
                    <th className="text-left px-2 py-1.5">Push</th>
                    <th className="text-left px-2 py-1.5">Min. Severity</th>
                    <th className="text-right px-2 py-1.5">Aktion</th>
                  </tr>
                </thead>
                <tbody>
                  {devices.map(d => (
                    <tr key={d.id} className="border-b border-slate-800/60">
                      <td className="px-2 py-1.5 text-slate-200">{d.label || '—'}</td>
                      <td className="px-2 py-1.5 font-mono text-slate-400">{d.platform || '—'}</td>
                      <td className="px-2 py-1.5 font-mono text-slate-400">{fmtDate(d.created_at)}</td>
                      <td className="px-2 py-1.5 font-mono text-slate-400">{fmtDate(d.last_seen)}</td>
                      <td className="px-2 py-1.5">
                        <span className={d.push_registered ? 'text-emerald-300' : 'text-slate-500'}>
                          {d.push_registered ? 'registriert' : 'nein'}
                        </span>
                      </td>
                      <td className="px-2 py-1.5 font-mono text-slate-400">{d.push_severity_min ?? '—'}</td>
                      <td className="px-2 py-1.5 text-right">
                        <button type="button" className="btn-danger text-[11px] inline-flex items-center gap-1"
                          onClick={() => setRevokeTarget(d)}>
                          <Trash2 size={11} /> Widerrufen
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Mobile: Card-Stack */}
            <div className="md:hidden flex flex-col gap-2">
              {devices.map(d => (
                <div key={d.id} className="rounded border border-slate-800 bg-slate-900/40 p-3">
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <div className="min-w-0">
                      <div className="text-slate-200 font-medium text-sm truncate">{d.label || '—'}</div>
                      <div className="text-[11px] font-mono text-slate-500">{d.platform || '—'}</div>
                    </div>
                    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0 ${
                      d.push_registered
                        ? 'border-emerald-700/40 bg-emerald-900/20 text-emerald-300'
                        : 'border-slate-700 bg-slate-800/40 text-slate-500'}`}>
                      Push {d.push_registered ? 'an' : 'aus'}
                    </span>
                  </div>
                  <dl className="grid grid-cols-2 gap-x-3 gap-y-1 text-[10px] font-mono text-slate-400 mb-2">
                    <div><dt className="text-slate-600">erstellt</dt><dd>{fmtDate(d.created_at)}</dd></div>
                    <div><dt className="text-slate-600">zuletzt gesehen</dt><dd>{fmtDate(d.last_seen)}</dd></div>
                    <div><dt className="text-slate-600">min. Severity</dt><dd>{d.push_severity_min ?? '—'}</dd></div>
                  </dl>
                  <div className="flex justify-end">
                    <button type="button" className="btn-danger text-[11px] inline-flex items-center gap-1 min-h-[36px]"
                      onClick={() => setRevokeTarget(d)}>
                      <Trash2 size={11} /> Widerrufen
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </>
        )}
      </div>

      {/* ── Dialog: Label für die Kopplung ───────────────────────────────── */}
      {pairOpen && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60] p-4"
          onClick={() => !pairBusy && setPairOpen(false)}>
          <div className="card p-5 w-full max-w-sm space-y-3" onClick={e => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-slate-200">Gerät koppeln</h3>
            <p className="text-[11px] text-slate-500">
              Die Bezeichnung erscheint später in der Geräteliste — z.B. „iPhone Jan".
            </p>
            <input className="input w-full text-xs font-mono" autoFocus
              placeholder="iPhone Jan"
              value={pairLabel}
              onChange={e => setPairLabel(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter' && !pairBusy) void handlePair(); }} />
            {pairErr && <p className="text-[11px] text-red-400">{pairErr}</p>}
            <div className="flex justify-end gap-2">
              <button type="button" className="btn-ghost text-xs"
                onClick={() => setPairOpen(false)} disabled={pairBusy}>Abbrechen</button>
              <button type="button" className="btn-primary text-xs flex items-center gap-1.5"
                onClick={() => void handlePair()} disabled={pairBusy}>
                {pairBusy && <LoaderCircle size={12} className="animate-spin" />}
                {pairBusy ? 'erzeuge …' : 'Code erzeugen'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Dialog: Kopplungscode + QR ───────────────────────────────────── */}
      {pairResult && (
        // Kein Schließen per Backdrop-Klick: der Code ist nur dieses eine Mal
        // sichtbar, ein Fehlklick daneben würde ihn verschlucken.
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[60] p-4">
          <div className="card p-5 w-full max-w-sm space-y-3 text-center">
            <h3 className="text-sm font-semibold text-slate-200">Kopplungscode</h3>

            {/* QR als data:-URI, bewusst NICHT via dangerouslySetInnerHTML */}
            {pairResult.qr_svg && (
              <div className="flex justify-center">
                <img
                  src={svgToDataUri(pairResult.qr_svg)}
                  alt="QR-Code zum Koppeln der CYJAN-App"
                  className="w-48 h-48 bg-white rounded p-2"
                />
              </div>
            )}

            <button type="button"
              onClick={() => void copyCode(pairResult.code)}
              title="Code in die Zwischenablage kopieren"
              className="w-full font-mono text-2xl tracking-[0.3em] text-cyan-200 bg-slate-900 border border-slate-700 rounded py-3 hover:border-cyan-600 transition-colors break-all">
              {pairResult.code}
            </button>
            <div className="flex items-center justify-center gap-1.5 text-[11px] text-slate-500">
              {codeCopied
                ? <><Check size={12} className="text-emerald-400" /><span className="text-emerald-300">kopiert</span></>
                : <><Copy size={12} /><span>zum Kopieren auf den Code tippen</span></>}
            </div>

            <div className={`text-xs ${pairExpired ? 'text-red-400' : 'text-slate-400'}`}>
              {pairExpired
                ? 'Code abgelaufen — bitte neu erzeugen.'
                : <>gültig noch <span className="font-mono tabular-nums text-slate-200">{pairRemaining}</span></>}
            </div>

            <p className="text-[10px] text-slate-600 leading-relaxed">
              In der CYJAN-App „Sentry hinzufügen" wählen und den QR-Code scannen. Der Code enthält
              bereits die Proxy-Adresse — Abtippen ist nur der Notweg.
            </p>

            <button type="button" className="btn-ghost text-xs w-full"
              onClick={() => { setPairResult(null); void loadRuntime(); }}>
              Schließen
            </button>
          </div>
        </div>
      )}

      {/* ── Widerruf-Bestätigung ─────────────────────────────────────────── */}
      {revokeTarget && (
        <ConfirmDialog
          message={`Gerät „${revokeTarget.label || revokeTarget.id}" wirklich widerrufen? `
                 + 'Alle laufenden Verbindungen dieses Geräts werden sofort getrennt.'}
          confirmLabel={revokeBusy ? '…' : 'Widerrufen'}
          onConfirm={() => void doRevoke()}
          onCancel={() => setRevokeTarget(null)}
        />
      )}
    </div>
  );
}
