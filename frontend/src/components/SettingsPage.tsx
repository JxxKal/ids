import { useEffect, useRef, useState, type ReactNode } from 'react';
import {
  Activity, Database, FileText, KeyRound, ListTree, Lock, Plug, RotateCcw, Sliders, Sparkles, Upload, Users,
} from 'lucide-react';
import {
  addRuleSource, applySslAcme, applySslSelfSigned, createUser, deleteRuleSource, deleteUser,
  fetchIrmaConfig, fetchItopConfig, fetchMLConfig, fetchMLStatus, fetchRuleSources,
  fetchRuleUpdateStatus, fetchRules, fetchSamlConfig, fetchSslStatus, fetchSyslogConfig,
  fetchSystemUpdateStatus, fetchUsers, generateApiToken, getItopSyncStatus, patchRuleSource,
  saveIrmaConfig, saveItopConfig, saveMLConfig, saveSamlConfig, saveSyslogConfig,
  restartStack, startSystemUpdate, testItopConnection, testSyslog, triggerItopSync, triggerMLRetrain,
  triggerRuleUpdate, updateUser, uploadSslCert, uploadSslPfx, setSslHostname,
} from '../api';
import type { SslAcmeConfig, SslSelfSignedRequest, SslStatus, SyslogConfig } from '../api';
import type { IrmaConfig, ItopConfig, ItopSyncState, MLConfig, MLStatus, Rule, RuleSource, SamlConfig, SystemUpdateStatus, UpdateStatus, User } from '../types';
import { ConfirmDialog } from './ConfirmDialog';
import { FuerThorsten } from './FuerThorsten';

// ── Helpers ───────────────────────────────────────────────────────────────────

function SourceBadge({ source }: { source: string }) {
  return source === 'saml'
    ? <span className="px-1.5 py-0.5 text-[10px] rounded bg-purple-900/50 text-purple-300 border border-purple-700/40">SAML</span>
    : <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">Lokal</span>;
}

function RoleBadge({ role }: { role: string }) {
  if (role === 'admin')
    return <span className="px-1.5 py-0.5 text-[10px] rounded bg-amber-900/50 text-amber-300 border border-amber-700/40">Admin</span>;
  if (role === 'api')
    return <span className="px-1.5 py-0.5 text-[10px] rounded bg-indigo-900/50 text-indigo-300 border border-indigo-700/40">API</span>;
  return <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">Viewer</span>;
}

interface NewUserForm { username: string; email: string; display_name: string; role: 'admin' | 'viewer' | 'api'; password: string; password2: string; }
const EMPTY_FORM: NewUserForm = { username: '', email: '', display_name: '', role: 'viewer', password: '', password2: '' };

// ── UserManagement ────────────────────────────────────────────────────────────

function UserManagement() {
  const [users,   setUsers]   = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');
  const [form,    setForm]    = useState(EMPTY_FORM);
  const [formErr, setFormErr] = useState('');
  const [saving,  setSaving]  = useState(false);
  const [showNew, setShowNew] = useState(false);
  const [editId,  setEditId]  = useState<string | null>(null);
  const [editData, setEditData] = useState<Partial<User & { password: string; password2: string }>>({});
  const [apiToken, setApiToken] = useState<{ userId: string; token: string } | null>(null);
  const [confirmUser, setConfirmUser] = useState<User | null>(null);

  useEffect(() => {
    fetchUsers()
      .then(setUsers)
      .catch(() => setError('Benutzer konnten nicht geladen werden'))
      .finally(() => setLoading(false));
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormErr('');
    // API-User: kein Passwort nötig → zufälliges generieren
    const isApi = form.role === 'api';
    const pw = isApi
      ? crypto.getRandomValues(new Uint8Array(16)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '')
      : form.password;
    if (!isApi && form.password !== form.password2) { setFormErr('Passwörter stimmen nicht überein'); return; }
    setSaving(true);
    try {
      const u = await createUser({
        username:     form.username,
        email:        form.email || undefined,
        display_name: form.display_name || undefined,
        role:         form.role,
        password:     pw,
      });
      setUsers(prev => [...prev, u]);
      setForm(EMPTY_FORM);
      setShowNew(false);
      // Direkt Token generieren für neuen API-User
      if (isApi) {
        const t = await generateApiToken(u.id);
        setApiToken({ userId: u.id, token: t.token });
      }
    } catch (err: unknown) {
      setFormErr(err instanceof Error ? err.message : 'Fehler beim Erstellen');
    } finally {
      setSaving(false);
    }
  }

  async function handleGenerateToken(userId: string) {
    try {
      const t = await generateApiToken(userId);
      setApiToken({ userId, token: t.token });
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Fehler beim Token-Generieren');
    }
  }

  async function handleUpdate(id: string) {
    setSaving(true);
    try {
      const payload: Parameters<typeof updateUser>[1] = {};
      if (editData.email        !== undefined) payload.email        = editData.email;
      if (editData.display_name !== undefined) payload.display_name = editData.display_name;
      if (editData.role         !== undefined) payload.role         = editData.role as 'admin' | 'viewer' | 'api';
      if (editData.password) {
        if (editData.password !== editData.password2) { setFormErr('Passwörter stimmen nicht überein'); setSaving(false); return; }
        payload.password = editData.password;
      }
      const u = await updateUser(id, payload);
      setUsers(prev => prev.map(x => x.id === id ? u : x));
      setEditId(null);
      setEditData({});
      setFormErr('');
    } catch (err: unknown) {
      setFormErr(err instanceof Error ? err.message : 'Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  }

  async function handleToggleActive(user: User) {
    try {
      const u = await updateUser(user.id, { active: !user.active });
      setUsers(prev => prev.map(x => x.id === user.id ? u : x));
    } catch { /* ignore */ }
  }

  async function handleDelete(user: User) {
    try {
      await deleteUser(user.id);
      setUsers(prev => prev.filter(x => x.id !== user.id));
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : 'Fehler beim Löschen');
    }
  }

  if (loading) return <p className="text-slate-500 text-sm">Lade…</p>;
  if (error)   return <p className="text-red-400 text-sm">{error}</p>;

  return (
    <div>
      {/* API Token Banner */}
      {apiToken && (
        <div className="mb-4 p-3 rounded border border-indigo-700/50 bg-indigo-950/40 text-xs">
          <div className="flex items-center justify-between mb-1">
            <span className="text-indigo-300 font-semibold">API-Token generiert (nur einmal sichtbar!)</span>
            <button className="text-slate-500 hover:text-slate-300 text-base leading-none" onClick={() => setApiToken(null)}>✕</button>
          </div>
          <div className="flex gap-2 items-center">
            <code className="flex-1 bg-slate-900 border border-slate-700 rounded px-2 py-1 text-slate-200 break-all font-mono text-[11px] select-all">
              {apiToken.token}
            </code>
            <button
              className="btn-ghost text-xs shrink-0"
              onClick={() => navigator.clipboard.writeText(apiToken.token)}
            >
              Kopieren
            </button>
          </div>
          <p className="mt-1 text-slate-500">Speichere den Token sicher – er kann nicht erneut abgerufen werden.</p>
        </div>
      )}

      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-slate-200">Benutzer</h2>
        <button className="btn-primary text-xs" onClick={() => { setShowNew(v => !v); setFormErr(''); }}>
          {showNew ? 'Abbrechen' : '+ Neuer Benutzer'}
        </button>
      </div>

      {/* Neuer-Benutzer-Formular */}
      {showNew && (
        <form onSubmit={handleCreate} className="card p-4 mb-4 grid grid-cols-2 gap-3 text-xs">
          <div className="flex flex-col gap-1">
            <label htmlFor="new-username" className="text-slate-400">Benutzername *</label>
            <input id="new-username" name="new-username" className="input" required
              value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor="new-email" className="text-slate-400">E-Mail</label>
            <input id="new-email" name="new-email" type="email" className="input"
              value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor="new-displayname" className="text-slate-400">Anzeigename</label>
            <input id="new-displayname" name="new-displayname" className="input"
              value={form.display_name} onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor="new-role" className="text-slate-400">Rolle</label>
            <select id="new-role" name="new-role" className="input"
              value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value as 'admin' | 'viewer' | 'api' }))}>
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
              <option value="api">API (Service-Account)</option>
            </select>
          </div>
          {form.role !== 'api' && <>
            <div className="flex flex-col gap-1">
              <label htmlFor="new-pw" className="text-slate-400">Passwort * (min. 8 Zeichen)</label>
              <input id="new-pw" name="new-pw" type="password" className="input" required minLength={8}
                value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="new-pw2" className="text-slate-400">Passwort wiederholen *</label>
              <input id="new-pw2" name="new-pw2" type="password" className="input" required
                value={form.password2} onChange={e => setForm(f => ({ ...f, password2: e.target.value }))} />
            </div>
          </>}
          {form.role === 'api' && (
            <p className="col-span-2 text-indigo-400/80 text-xs bg-indigo-950/30 rounded px-3 py-2 border border-indigo-800/40">
              API-User nutzen langlebige JWT-Token (365 Tage) statt Passwörter. Nach dem Anlegen wird der Token einmalig angezeigt.
            </p>
          )}
          {formErr && <p className="col-span-2 text-red-400 text-xs">{formErr}</p>}
          <div className="col-span-2 flex justify-end gap-2">
            <button type="button" className="btn-ghost text-xs" onClick={() => setShowNew(false)}>Abbrechen</button>
            <button type="submit" className="btn-primary text-xs" disabled={saving}>
              {saving ? 'Speichern…' : 'Benutzer anlegen'}
            </button>
          </div>
        </form>
      )}

      {/* Benutzertabelle */}
      <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead className="cyjan-table-head">
          <tr className="text-left">
            <th>Benutzer</th>
            <th>E-Mail</th>
            <th>Rolle</th>
            <th>Quelle</th>
            <th>Letzter Login</th>
            <th>Aktiv</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={u.id} className="border-b border-slate-800/50 hover:bg-slate-800/20">
              {editId === u.id ? (
                /* Edit-Zeile */
                <>
                  <td className="py-2 pr-3">
                    <span className="text-slate-300 font-medium">{u.username}</span>
                    {u.source === 'local' && (
                      <div className="mt-1 flex flex-col gap-1">
                        <input className="input w-full" placeholder="Neues Passwort" type="password"
                          value={editData.password ?? ''}
                          onChange={e => setEditData(d => ({ ...d, password: e.target.value }))} />
                        <input className="input w-full" placeholder="Wiederholen" type="password"
                          value={editData.password2 ?? ''}
                          onChange={e => setEditData(d => ({ ...d, password2: e.target.value }))} />
                      </div>
                    )}
                  </td>
                  <td className="py-2 pr-3">
                    <input className="input w-full" placeholder="E-Mail" type="email"
                      value={editData.email ?? u.email ?? ''}
                      onChange={e => setEditData(d => ({ ...d, email: e.target.value }))} />
                  </td>
                  <td className="py-2 pr-3">
                    <select className="input"
                      value={editData.role ?? u.role}
                      onChange={e => setEditData(d => ({ ...d, role: e.target.value as 'admin' | 'viewer' | 'api' }))}>
                      <option value="viewer">Viewer</option>
                      <option value="admin">Admin</option>
                      <option value="api">API</option>
                    </select>
                  </td>
                  <td className="py-2 pr-3"><SourceBadge source={u.source} /></td>
                  <td className="py-2 pr-3 text-slate-500">—</td>
                  <td className="py-2 pr-3">—</td>
                  <td className="py-2 text-right">
                    {formErr && <p className="text-red-400 mb-1">{formErr}</p>}
                    <div className="flex gap-1.5 justify-end">
                      <button className="btn-ghost text-xs" onClick={() => { setEditId(null); setEditData({}); setFormErr(''); }}>Abbrechen</button>
                      <button className="btn-primary text-xs" disabled={saving} onClick={() => handleUpdate(u.id)}>
                        {saving ? '…' : 'Speichern'}
                      </button>
                    </div>
                  </td>
                </>
              ) : (
                /* Anzeigezeile */
                <>
                  <td className="py-2 pr-3">
                    <span className="text-slate-200 font-medium">{u.username}</span>
                    {u.display_name && <div className="text-slate-500">{u.display_name}</div>}
                  </td>
                  <td className="py-2 pr-3 text-slate-400">{u.email ?? '—'}</td>
                  <td className="py-2 pr-3"><RoleBadge role={u.role} /></td>
                  <td className="py-2 pr-3"><SourceBadge source={u.source} /></td>
                  <td className="py-2 pr-3 text-slate-500">
                    {u.last_login ? new Date(u.last_login).toLocaleString() : '—'}
                  </td>
                  <td className="py-2 pr-3">
                    <button
                      onClick={() => handleToggleActive(u)}
                      className={`w-8 h-4 rounded-full transition-colors relative ${u.active ? 'bg-green-600' : 'bg-slate-700'}`}
                      title={u.active ? 'Aktiv – klicken zum Deaktivieren' : 'Inaktiv – klicken zum Aktivieren'}
                    >
                      <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${u.active ? 'left-4' : 'left-0.5'}`} />
                    </button>
                  </td>
                  <td className="py-2 text-right">
                    <div className="flex gap-1.5 justify-end">
                      {u.role === 'api' && (
                        <button
                          className="text-xs text-indigo-400 hover:text-indigo-300 px-2 py-1 rounded hover:bg-indigo-950/30 transition-colors"
                          onClick={() => handleGenerateToken(u.id)}
                          title="Neues API-Token generieren (invalidiert vorheriges Token nicht)"
                        >
                          Token
                        </button>
                      )}
                      <button className="btn-ghost text-xs"
                        onClick={() => { setEditId(u.id); setEditData({}); setFormErr(''); }}>
                        Bearbeiten
                      </button>
                      <button className="text-xs text-red-500 hover:text-red-400 px-2 py-1 rounded hover:bg-red-950/30 transition-colors"
                        onClick={() => setConfirmUser(u)}>
                        Löschen
                      </button>
                    </div>
                  </td>
                </>
              )}
            </tr>
          ))}
        </tbody>
      </table>
      </div>

      {confirmUser && (
        <ConfirmDialog
          message={`Benutzer "${confirmUser.username}" wirklich löschen?`}
          onConfirm={() => { const u = confirmUser; setConfirmUser(null); handleDelete(u); }}
          onCancel={() => setConfirmUser(null)}
        />
      )}
    </div>
  );
}

// ── SamlSettings ──────────────────────────────────────────────────────────────

/** Parst eine IdP-Metadata-XML und gibt die relevanten Felder zurück. */
function parseIdpMetadataXml(xml: string): Partial<SamlConfig> {
  try {
    const doc = new DOMParser().parseFromString(xml, 'text/xml');
    if (doc.querySelector('parsererror')) throw new Error('Ungültiges XML');

    const ns = 'urn:oasis:names:tc:SAML:2.0:metadata';
    const entityId = doc.documentElement.getAttribute('entityID') ?? '';

    const ssoServices = Array.from(doc.getElementsByTagNameNS(ns, 'SingleSignOnService'));
    const sloServices = Array.from(doc.getElementsByTagNameNS(ns, 'SingleLogoutService'));

    const ssoRedirect = ssoServices.find(e => e.getAttribute('Binding')?.endsWith('HTTP-Redirect'))?.getAttribute('Location')
      ?? ssoServices[0]?.getAttribute('Location') ?? '';

    const sloPost = sloServices.find(e => e.getAttribute('Binding')?.endsWith('HTTP-POST'))?.getAttribute('Location')
      ?? sloServices[0]?.getAttribute('Location') ?? '';

    // X509Certificate aus Signing KeyDescriptor
    const keyDescs = Array.from(doc.getElementsByTagNameNS(ns, 'KeyDescriptor'));
    const signingKey = keyDescs.find(k => !k.getAttribute('use') || k.getAttribute('use') === 'signing') ?? keyDescs[0];
    const cert = signingKey?.getElementsByTagNameNS('http://www.w3.org/2000/09/xmldsig#', 'X509Certificate')[0]?.textContent?.replace(/\s/g, '') ?? '';

    return { idp_entity_id: entityId, idp_sso_url: ssoRedirect, idp_slo_url: sloPost, idp_x509_cert: cert };
  } catch (e) {
    throw new Error(`XML-Parse-Fehler: ${e instanceof Error ? e.message : e}`);
  }
}

function CopyButton({ value }: { value: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button"
      className="text-[10px] px-1.5 py-0.5 rounded border border-slate-700 text-slate-500 hover:text-slate-300 transition-colors"
      onClick={() => { navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 2000); }}>
      {done ? 'Kopiert' : 'Kopieren'}
    </button>
  );
}

const SAML_DEFAULTS: SamlConfig = {
  enabled: false,
  idp_entity_id: '', idp_sso_url: '', idp_slo_url: '', idp_x509_cert: '',
  sp_entity_id: '', acs_url: '', slo_url: '',
  attribute_username: 'uid', attribute_email: 'email',
  attribute_display_name: 'displayName', default_role: 'viewer',
};

function SamlSettings() {
  const [cfg,       setCfg]       = useState<SamlConfig>(SAML_DEFAULTS);
  const [loading,   setLoading]   = useState(true);
  const [saving,    setSaving]    = useState(false);
  const [msg,       setMsg]       = useState<{ type: 'ok'|'err'; text: string }|null>(null);
  const [xmlInput,  setXmlInput]  = useState('');
  const [xmlError,  setXmlError]  = useState('');
  const [showCert,  setShowCert]  = useState(false);

  useEffect(() => {
    fetchSamlConfig()
      .then(setCfg)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  function flash(type: 'ok'|'err', text: string) {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 4000);
  }

  function handleImportXml() {
    setXmlError('');
    try {
      const parsed = parseIdpMetadataXml(xmlInput);
      setCfg(c => ({ ...c, ...parsed }));
      setXmlInput('');
      flash('ok', 'IdP-Metadaten importiert ✓');
    } catch (e: unknown) {
      setXmlError(e instanceof Error ? e.message : 'Parse-Fehler');
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try { await saveSamlConfig(cfg); flash('ok', 'Gespeichert ✓'); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : 'Fehler'); }
    finally { setSaving(false); }
  }

  const inp = (label: string, key: keyof SamlConfig, placeholder = '', type = 'text') => (
    <div className="flex flex-col gap-1">
      <label className="text-xs text-slate-400">{label}</label>
      <input className="input text-xs font-mono" type={type} placeholder={placeholder}
        value={String(cfg[key] ?? '')}
        onChange={e => setCfg(c => ({ ...c, [key]: e.target.value }))} />
    </div>
  );

  if (loading) return <p className="text-slate-500 text-sm">Lade…</p>;

  return (
    <form onSubmit={handleSave} className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">SAML / SSO</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-purple-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-purple-300 font-medium' : 'text-slate-500'}>
            SAML aktiviert
          </span>
        </label>
      </div>

      {/* ── IdP-Metadaten XML importieren ────────────────────────────────────── */}
      <div className="rounded border border-slate-700/60 bg-slate-900/50 p-3 space-y-2">
        <p className="text-xs font-medium text-slate-300">IdP-Metadaten importieren</p>
        <p className="text-[11px] text-slate-500">
          XML aus dem FortiAuthenticator herunterladen und hier einfügen — füllt die IdP-Felder automatisch.
        </p>
        <textarea
          className="input text-[11px] font-mono w-full h-24 resize-none"
          placeholder={'<?xml version="1.0"?>\n<md:EntityDescriptor …'}
          value={xmlInput}
          onChange={e => { setXmlInput(e.target.value); setXmlError(''); }}
        />
        {xmlError && <p className="text-[11px] text-red-400">{xmlError}</p>}
        <button type="button" className="btn-ghost text-xs"
          disabled={!xmlInput.trim()}
          onClick={handleImportXml}>
          XML parsen &amp; Felder befüllen
        </button>
      </div>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>

        {/* ── IdP-Felder ───────────────────────────────────────────────────── */}
        <div>
          <p className="text-xs text-slate-400 font-medium mb-2">Identity Provider (IdP)</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {inp('Entity-ID des IdP',   'idp_entity_id', 'http://10.180.18.66/saml-idp/…')}
            {inp('SSO-URL (HTTP-Redirect)', 'idp_sso_url', 'http://10.180.18.66/…/login/')}
            {inp('SLO-URL (Logout)',    'idp_slo_url',  'http://10.180.18.66/…/logout/')}
          </div>
          <div className="mt-3 flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <label className="text-xs text-slate-400">X.509-Zertifikat des IdP (Base64, ohne PEM-Header)</label>
              <button type="button" className="text-[10px] text-slate-500 hover:text-slate-300"
                onClick={() => setShowCert(v => !v)}>
                {showCert ? 'Verbergen' : 'Zeigen'}
              </button>
            </div>
            {showCert
              ? <textarea className="input text-[11px] font-mono w-full h-20 resize-none"
                  value={cfg.idp_x509_cert}
                  onChange={e => setCfg(c => ({ ...c, idp_x509_cert: e.target.value }))} />
              : <p className="text-[11px] text-slate-600 font-mono truncate">
                  {cfg.idp_x509_cert ? `${cfg.idp_x509_cert.slice(0, 60)}…` : '(nicht gesetzt)'}
                </p>
            }
          </div>
        </div>

        {/* ── SP-Felder ────────────────────────────────────────────────────── */}
        <div>
          <p className="text-xs text-slate-400 font-medium mb-2">Service Provider (SP) – diese Werte beim FortiAuthenticator eintragen</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-slate-400">SP Entity-ID</label>
              <input className="input text-xs font-mono" type="text" placeholder="http://192.168.1.230"
                value={cfg.sp_entity_id}
                onChange={e => {
                  const base = e.target.value.replace(/\/$/, '');
                  setCfg(c => ({
                    ...c,
                    sp_entity_id: e.target.value,
                    acs_url: base ? `${base}/api/auth/saml/acs` : c.acs_url,
                    slo_url: base ? `${base}/api/auth/saml/sls` : c.slo_url,
                  }));
                }} />
            </div>
            {inp('ACS-URL (Login)',  'acs_url',  'http://192.168.1.230/api/auth/saml/acs')}
            {inp('SLS-URL (Logout)', 'slo_url',  'http://192.168.1.230/api/auth/saml/sls')}
          </div>

          {/* SP-Info-Box mit Copy-Buttons */}
          {cfg.sp_entity_id && (
            <div className="mt-3 rounded border border-slate-700/40 bg-slate-900/60 divide-y divide-slate-800 text-[11px] font-mono">
              {[
                ['SP Entity-ID',    cfg.sp_entity_id],
                ['ACS-URL (Login)', cfg.acs_url],
                ['SLS-URL (Logout)', cfg.slo_url],
              ].map(([label, val]) => (
                <div key={label} className="flex items-center justify-between px-3 py-1.5 gap-2">
                  <span className="text-slate-500 shrink-0 w-32">{label}</span>
                  <span className="text-slate-300 truncate flex-1">{val || '–'}</span>
                  {val && <CopyButton value={val} />}
                </div>
              ))}
            </div>
          )}

          {/* SP Metadata XML herunterladen */}
          {cfg.sp_entity_id && cfg.enabled && (
            <a
              href="/api/auth/saml/metadata"
              download="sp-metadata.xml"
              className="mt-2 inline-flex items-center gap-1.5 text-xs text-slate-400 hover:text-slate-200 border border-slate-700 rounded px-2.5 py-1 transition-colors"
            >
              ↓ SP-Metadata XML herunterladen
            </a>
          )}
        </div>

        {/* ── Attribut-Mapping ─────────────────────────────────────────────── */}
        <div>
          <p className="text-xs text-slate-500 mb-2">
            Attribut-Mapping — SAML-Assertion-Attributname, der den jeweiligen Wert liefert.
            FortiAuthenticator sendet je nach Konfiguration z.B. <span className="font-mono text-slate-400">username</span> oder <span className="font-mono text-slate-400">uid</span>.
          </p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {inp('Benutzername-Attribut',  'attribute_username',     'uid')}
            {inp('E-Mail-Attribut',        'attribute_email',        'email')}
            {inp('Anzeigename-Attribut',   'attribute_display_name', 'displayName')}
          </div>
        </div>

        <div className="flex flex-col gap-1 max-w-xs">
          <label className="text-xs text-slate-400">Standard-Rolle für neue SAML-User</label>
          <select className="input text-xs"
            value={cfg.default_role}
            onChange={e => setCfg(c => ({ ...c, default_role: e.target.value as 'admin'|'viewer' }))}>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
        </div>
      </div>

      <div className="flex items-center justify-between pt-1">
        <div>
          {msg?.type === 'ok'  && <span className="text-xs text-green-400">{msg.text}</span>}
          {msg?.type === 'err' && <span className="text-xs text-red-400">{msg.text}</span>}
        </div>
        <button type="submit" className="btn-primary text-xs" disabled={saving}>
          {saving ? 'Speichern…' : 'SAML-Konfiguration speichern'}
        </button>
      </div>
    </form>
  );
}

// ── MLStatusSection ───────────────────────────────────────────────────────────

function fmtDuration(secs: number): string {
  if (secs < 60)    return `${secs} Sek.`;
  if (secs < 3600)  return `${Math.round(secs / 60)} Min.`;
  if (secs < 86400) return `${Math.round(secs / 3600)} Std.`;
  return `${Math.round(secs / 86400)} Tage`;
}

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

function PhaseIndicator({ phase }: { phase: MLStatus['phase'] }) {
  const cfg = {
    passthrough: { dot: 'bg-slate-500',  text: 'text-slate-400',  label: 'Datensammlung' },
    learning:    { dot: 'bg-yellow-500 animate-pulse', text: 'text-yellow-400', label: 'Lernphase' },
    active:      { dot: 'bg-green-500',  text: 'text-green-400',  label: 'Aktiv' },
  }[phase];
  return (
    <span className={`flex items-center gap-1.5 font-medium ${cfg.text}`}>
      <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

const PARAM_DOCS = [
  {
    key: 'alert_threshold' as const,
    label: 'Alert-Schwellwert',
    min: 0.50, max: 0.95, step: 0.01,
    fmt: (v: number) => v.toFixed(2),
    hint: 'Score ab dem ein Flow als Anomalie gilt (0.50–0.95). Höher = weniger, aber konfidentere Alerts. Für große Umgebungen mit viel Hintergrundrauschen empfohlen: 0.75–0.85.',
    presets: [
      { label: 'Sensibel',     value: 0.60, desc: 'Viele Alerts, frühe Erkennung' },
      { label: 'Ausgewogen',   value: 0.65, desc: 'Standard' },
      { label: 'Präzise',     value: 0.75, desc: 'Weniger Alerts, höhere Konfidenz' },
      { label: 'Konservativ', value: 0.85, desc: 'Nur eindeutige Anomalien' },
    ],
  },
  {
    key: 'contamination' as const,
    label: 'Contamination',
    min: 0.001, max: 0.2, step: 0.001,
    fmt: (v: number) => `${(v * 100).toFixed(1)} %`,
    hint: 'Erwarteter Anteil anomaler Flows im Trainingsdatensatz (0.1 %–20 %). Änderung löst automatisch einen Retrain aus. OT/SCADA mit stabilem Traffic: 0.5–1 %. Große IT-Netze: 2–5 %.',
    presets: [
      { label: 'OT/SCADA',  value: 0.005, desc: 'Sehr stabiles Protokollbild' },
      { label: 'Standard',  value: 0.010, desc: 'Ausgewogen' },
      { label: 'Gemischtes Netz', value: 0.030, desc: 'IT + OT kombiniert' },
      { label: 'Große IT',  value: 0.050, desc: 'Viel diverser Verkehr' },
    ],
  },
  {
    key: 'bootstrap_min_samples' as const,
    label: 'Mindest-Flows für Training',
    min: 100, max: 50000, step: 100,
    fmt: (v: number) => v.toLocaleString(),
    hint: 'Anzahl Flows die gesammelt werden müssen bevor das erste Modell trainiert wird. Für große Netze mit breitem Traffic-Profil: 2.000–10.000.',
    presets: [
      { label: 'Klein',   value: 500,   desc: 'Schneller Start' },
      { label: 'Mittel',  value: 2000,  desc: 'Ausgewogen' },
      { label: 'Groß',    value: 10000, desc: 'Breites Traffic-Profil' },
      { label: 'Sehr groß', value: 50000, desc: 'Großes Rechenzentrum' },
    ],
  },
  {
    key: 'partial_fit_interval' as const,
    label: 'Scaler-Update-Intervall',
    min: 50, max: 5000, step: 50,
    fmt: (v: number) => `alle ${v.toLocaleString()} Flows`,
    hint: 'Wie oft der Feature-Normalisierer (StandardScaler) inkrementell angepasst wird. Kleinerer Wert = schnellere Adaption an neue Traffic-Muster, höhere CPU-Last.',
    presets: [
      { label: 'Reaktiv',   value: 100,  desc: 'Schnelle Adaption' },
      { label: 'Standard',  value: 200,  desc: '' },
      { label: 'Stabil',    value: 1000, desc: 'Weniger CPU-Last' },
    ],
  },
];

function MLStatusDisplay() {
  const [status,  setStatus]  = useState<MLStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(() => {
    fetchMLStatus()
      .then(setStatus)
      .catch(() => setError('ML-Status konnte nicht geladen werden'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <p className="text-slate-500 text-sm">Lade…</p>;
  if (error)   return <p className="text-red-400 text-sm">{error}</p>;
  if (!status) return null;

  const { phase, phase_label, model, bootstrap, stats_24h, top_anomaly_features } = status;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">KI/ML-Engine</h2>
        <PhaseIndicator phase={phase} />
      </div>

      {/* ── Phase-Banner ─────────────────────────────────────────────── */}
      <div className={`rounded-lg border px-4 py-3 text-xs ${
        phase === 'active'
          ? 'bg-green-950/30 border-green-800/40 text-green-300'
          : phase === 'learning'
          ? 'bg-yellow-950/30 border-yellow-800/40 text-yellow-300'
          : 'bg-slate-800/40 border-slate-700/40 text-slate-400'
      }`}>
        <p className="font-medium mb-1">{phase_label}</p>
        {phase === 'passthrough' && (
          <p>Das Modell wartet auf ausreichend Netzwerkdaten. Noch kein ML-Filtering aktiv – alle Flows werden durchgelassen.</p>
        )}
        {phase === 'learning' && (
          <p>Das Modell wurde initial trainiert und verfeinert sich kontinuierlich. ML-Filtering ist bereits aktiv, aber noch nicht vollständig kalibriert.</p>
        )}
        {phase === 'active' && (
          <p>Das Modell ist vollständig trainiert. Anomaler Verkehr wird automatisch erkannt und als ML-Alert markiert.</p>
        )}
      </div>

      {/* ── Lernfortschritt (nur wenn noch kein Modell) ──────────────── */}
      {phase === 'passthrough' && (
        <div>
          <div className="flex justify-between text-xs text-slate-400 mb-1.5">
            <span>Datensammlung</span>
            <span>{bootstrap.current_flows.toLocaleString()} / {bootstrap.required.toLocaleString()} Flows</span>
          </div>
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-cyan-500 rounded-full transition-all"
              style={{ width: `${bootstrap.progress_pct}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-600 mt-1">
            <span>{bootstrap.progress_pct}% abgeschlossen</span>
            {bootstrap.estimated_remaining_s != null && (
              <span>ca. {fmtDuration(bootstrap.estimated_remaining_s)} verbleibend</span>
            )}
            {bootstrap.estimated_remaining_s == null && (
              <span>Schätzung nicht verfügbar (kein Netzwerkverkehr)</span>
            )}
          </div>
        </div>
      )}

      {/* ── Modell-Details ───────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
        {[
          { label: 'Trainings-Samples',  value: model.n_samples.toLocaleString() },
          { label: 'Davon Angriffe',     value: model.n_attack > 0 ? model.n_attack.toLocaleString() : '—' },
          { label: 'Contamination',      value: `${(model.contamination * 100).toFixed(1)} %` },
          { label: 'Letztes Training',   value: model.trained_at ? fmtTs(model.trained_at) : '—' },
        ].map(({ label, value }) => (
          <div key={label} className="bg-slate-800/40 rounded-lg px-3 py-2 border border-slate-700/40">
            <div className="text-slate-500 mb-0.5">{label}</div>
            <div className="text-slate-200 font-medium">{value}</div>
          </div>
        ))}
      </div>

      {/* ── 24h-Statistik (nur im aktiven Modus) ─────────────────────── */}
      {phase === 'active' && (
        <div>
          <p className="text-xs font-medium text-slate-400 mb-2">Letzte 24 Stunden</p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
            {[
              { label: 'Analysierte Flows',  value: stats_24h.flows_total.toLocaleString() },
              { label: 'ML-Alerts',          value: stats_24h.ml_alerts.toLocaleString() },
              {
                label: 'Filter-Rate',
                value: stats_24h.flows_total > 0
                  ? `${stats_24h.filter_rate_pct.toFixed(3)} %`
                  : '—',
              },
              { label: 'Score-Schwellwert',  value: stats_24h.alert_threshold.toFixed(2) },
            ].map(({ label, value }) => (
              <div key={label} className="bg-slate-800/40 rounded-lg px-3 py-2 border border-slate-700/40">
                <div className="text-slate-500 mb-0.5">{label}</div>
                <div className="text-slate-200 font-medium">{value}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ── Feature-Abweichungen ─────────────────────────────────────── */}
      {top_anomaly_features.length > 0 && (
        <div>
          <p className="text-xs font-medium text-slate-400 mb-2">
            Warum werden Flows als anomal erkannt? <span className="font-normal text-slate-600">(Merkmal-Abweichungen in ML-Alerts vs. normaler Verkehr)</span>
          </p>
          <div className="space-y-2">
            {top_anomaly_features.map(f => {
              const isHigh = f.deviation_pct > 0;
              const absDev = Math.abs(f.deviation_pct);
              const barW   = Math.min(100, absDev / 5);  // 500% = volle Breite
              return (
                <div key={f.name} className="text-xs">
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-slate-300">{f.label}</span>
                    <span className={`font-mono ${isHigh ? 'text-orange-400' : 'text-blue-400'}`}>
                      {isHigh ? '↑' : '↓'} {absDev.toFixed(0)} %
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${isHigh ? 'bg-orange-500' : 'bg-cyan-500'}`}
                      style={{ width: `${barW}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-600 mt-0.5">
                    <span>Normal: {f.avg_normal.toFixed(3)} {f.unit}</span>
                    <span>In ML-Alerts: {f.avg_in_alerts.toFixed(3)} {f.unit}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {phase === 'active' && stats_24h.ml_alerts === 0 && (
        <p className="text-xs text-slate-600 italic">
          In den letzten 24 Stunden keine ML-Alerts – kein anomaler Verkehr erkannt oder ML-Filter zu lax konfiguriert.
        </p>
      )}
    </div>
  );
}

function MLFilterConfig() {
  const [cfg,      setCfg]      = useState<MLConfig | null>(null);
  const [cfgDraft, setCfgDraft] = useState<MLConfig | null>(null);
  const [saving,   setSaving]   = useState(false);
  const [saveMsg,  setSaveMsg]  = useState('');
  const [retraining, setRetraining] = useState(false);

  useEffect(() => {
    fetchMLConfig()
      .then(c => { setCfg(c); setCfgDraft(c); })
      .catch(() => {});
  }, []);

  async function handleSaveConfig() {
    if (!cfgDraft) return;
    setSaving(true); setSaveMsg('');
    try {
      const updated = await saveMLConfig(cfgDraft);
      setCfg(updated); setCfgDraft(updated);
      setSaveMsg('ok');
      setTimeout(() => setSaveMsg(''), 3000);
    } catch (err: unknown) {
      setSaveMsg('err:' + (err instanceof Error ? err.message : 'Fehler'));
    } finally {
      setSaving(false);
    }
  }

  async function handleRetrain() {
    setRetraining(true); setSaveMsg('');
    try {
      await triggerMLRetrain();
      setSaveMsg('retrain');
      setTimeout(() => setSaveMsg(''), 5000);
    } catch (err: unknown) {
      setSaveMsg('err:' + (err instanceof Error ? err.message : 'Fehler'));
    } finally {
      setRetraining(false);
    }
  }

  if (!cfgDraft) return <p className="text-slate-500 text-sm">Lade…</p>;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">Filter-Konfiguration</h2>
        <div className="flex items-center gap-2">
          {saveMsg === 'ok'          && <span className="text-xs text-green-400">Gespeichert ✓</span>}
          {saveMsg === 'retrain'     && <span className="text-xs text-blue-400">Retrain ausgelöst ✓</span>}
          {saveMsg.startsWith('err:')&& <span className="text-xs text-red-400">{saveMsg.slice(4)}</span>}
          <button className="btn-ghost text-xs" disabled={retraining} onClick={handleRetrain}>
            {retraining ? 'Wird ausgelöst…' : '↺ Retrain jetzt starten'}
          </button>
          <button
            className="btn-primary text-xs"
            disabled={saving || !cfg || JSON.stringify(cfgDraft) === JSON.stringify(cfg)}
            onClick={handleSaveConfig}
          >
            {saving ? 'Speichern…' : 'Speichern'}
          </button>
        </div>
      </div>

      {PARAM_DOCS.map(p => {
        const val = cfgDraft[p.key] as number;
        return (
          <div key={p.key} className="space-y-2">
            <div className="flex items-baseline justify-between">
              <label className="text-xs font-medium text-slate-300">{p.label}</label>
              <span className="text-xs font-mono text-cyan-400">{p.fmt(val)}</span>
            </div>
            <div className="flex items-center gap-3">
              <input
                type="range" min={p.min} max={p.max} step={p.step} value={val}
                onChange={e => setCfgDraft(d => d ? { ...d, [p.key]: parseFloat(e.target.value) } : d)}
                className="flex-1 accent-cyan-500 cursor-pointer h-1.5"
              />
              <input
                type="number" lang="en" min={p.min} max={p.max} step={p.step} value={val}
                onChange={e => {
                  const n = parseFloat(e.target.value);
                  if (!isNaN(n) && n >= p.min && n <= p.max)
                    setCfgDraft(d => d ? { ...d, [p.key]: n } : d);
                }}
                className="input text-xs w-24 font-mono"
              />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {p.presets.map(pr => (
                <button
                  key={pr.label}
                  onClick={() => setCfgDraft(d => d ? { ...d, [p.key]: pr.value } : d)}
                  title={pr.desc}
                  className={`px-2 py-0.5 text-[11px] rounded border transition-colors ${
                    Math.abs(val - pr.value) < p.step * 0.5
                      ? 'bg-cyan-900/50 border-cyan-600/60 text-cyan-300'
                      : 'bg-slate-800/50 border-slate-700/40 text-slate-400 hover:border-slate-500/60 hover:text-slate-300'
                  }`}
                >{pr.label}</button>
              ))}
            </div>
            <p className="text-[11px] text-slate-600 leading-relaxed">{p.hint}</p>
          </div>
        );
      })}
    </div>
  );
}

// ── RulesEngine ───────────────────────────────────────────────────────────────

const OT_TAGS = ['OT', 'ICS', 'SCADA', 'Modbus', 'DNP3', 'EtherNet/IP', 'BACnet', 'Rockwell', 'Gebäudeautomation', 'Angriffserkennung'];

function TagBadges({ tags }: { tags: string[] }) {
  return (
    <span className="flex flex-wrap gap-1">
      {tags.map(t => (
        <span key={t} className={`px-1.5 py-0.5 text-[10px] rounded border ${
          OT_TAGS.includes(t)
            ? 'bg-orange-900/40 text-orange-300 border-orange-700/40'
            : 'bg-slate-700/50 text-slate-400 border-slate-600/30'
        }`}>{t}</span>
      ))}
    </span>
  );
}

function RuleSources() {
  const [sources,   setSources]   = useState<RuleSource[]>([]);
  const [status,    setStatus]    = useState<UpdateStatus | null>(null);
  const [updating,  setUpdating]  = useState(false);
  const [showAdd,   setShowAdd]   = useState(false);
  const [newName,   setNewName]   = useState('');
  const [newUrl,    setNewUrl]    = useState('');
  const [newErr,    setNewErr]    = useState('');
  const [confirmSrc, setConfirmSrc] = useState<RuleSource | null>(null);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Quellen + Update-Status initial laden
  useEffect(() => {
    fetchRuleSources().then(setSources).catch(() => {});
    fetchRuleUpdateStatus().then(setStatus).catch(() => {});
  }, []);

  // Polling wenn Update angefordert
  useEffect(() => {
    if (!status?.requested) { if (pollRef.current) clearTimeout(pollRef.current); return; }
    pollRef.current = setTimeout(async () => {
      const s = await fetchRuleUpdateStatus().catch(() => null);
      if (s) setStatus(s);
    }, 5000);
    return () => { if (pollRef.current) clearTimeout(pollRef.current); };
  }, [status]);

  async function handleToggleSource(src: RuleSource) {
    const updated = await patchRuleSource(src.id, { enabled: !src.enabled }).catch(() => null);
    if (updated) setSources(prev => prev.map(s => s.id === src.id ? updated : s));
  }

  async function handleDeleteSource(src: RuleSource) {
    await deleteRuleSource(src.id).catch(() => {});
    setSources(prev => prev.filter(s => s.id !== src.id));
  }

  async function handleAddSource(e: React.FormEvent) {
    e.preventDefault(); setNewErr('');
    try {
      const src = await addRuleSource({ name: newName, url: newUrl, enabled: true });
      setSources(prev => [...prev, src]);
      setNewName(''); setNewUrl(''); setShowAdd(false);
    } catch (err: unknown) {
      setNewErr(err instanceof Error ? err.message : 'Fehler');
    }
  }

  async function handleTriggerUpdate() {
    setUpdating(true);
    try { const s = await triggerRuleUpdate(); setStatus(s); }
    catch { /* ignore */ } finally { setUpdating(false); }
  }

  const fmtTs = (ts: number | null) => ts
    ? new Date(ts * 1000).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' })
    : '—';

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">Rule-Quellen</h2>
        <div className="flex items-center gap-2">
          <button onClick={handleTriggerUpdate} disabled={updating || !!status?.requested} className="btn-primary text-xs">
            {status?.requested ? '⏳ Update läuft…' : updating ? '…' : '↻ Update starten'}
          </button>
          <button className="btn-ghost text-xs" onClick={() => { setShowAdd(v => !v); setNewErr(''); }}>
            {showAdd ? 'Abbrechen' : '+ Quelle'}
          </button>
        </div>
      </div>

      {status && (
        <p className="text-xs text-slate-500">
          {status.requested
            ? `Update angefordert um ${fmtTs(status.requested_at)} – Suricata lädt gerade neu…`
            : status.last_updated
              ? `Letzte Aktualisierung: ${fmtTs(status.last_updated)}`
              : 'Noch kein Update durchgeführt'}
        </p>
      )}

      {showAdd && (
        <form onSubmit={handleAddSource} className="card p-3 flex flex-wrap gap-2 items-end text-xs">
          <div className="flex flex-col gap-1 flex-1 min-w-[160px]">
            <label className="text-slate-400">Name</label>
            <input className="input" required value={newName} onChange={e => setNewName(e.target.value)} placeholder="Meine Custom Rules" />
          </div>
          <div className="flex flex-col gap-1 flex-[2] min-w-[260px]">
            <label className="text-slate-400">URL (.rules oder .tar.gz)</label>
            <input className="input" required type="url" value={newUrl} onChange={e => setNewUrl(e.target.value)} placeholder="https://example.com/my.rules" />
          </div>
          {newErr && <p className="w-full text-red-400">{newErr}</p>}
          <button type="submit" className="btn-primary text-xs">Hinzufügen</button>
        </form>
      )}

      <div className="space-y-1.5">
        {sources.map(src => (
          <div key={src.id} className={`flex items-center gap-3 px-3 py-2.5 rounded border text-xs transition-colors ${
            src.enabled ? 'bg-slate-800/50 border-slate-700/60' : 'bg-slate-900/30 border-slate-800/40 opacity-60'
          }`}>
            <button
              onClick={() => handleToggleSource(src)}
              className={`w-8 h-4 rounded-full transition-colors relative flex-shrink-0 ${src.enabled ? 'bg-green-600' : 'bg-slate-700'}`}
              title={src.enabled ? 'Aktiviert' : 'Deaktiviert'}
            >
              <span className={`absolute top-0.5 w-3 h-3 rounded-full bg-white transition-all ${src.enabled ? 'left-4' : 'left-0.5'}`} />
            </button>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className={`font-medium ${src.enabled ? 'text-slate-200' : 'text-slate-500'}`}>{src.name}</span>
                {src.builtin && <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/50 text-slate-500 border border-slate-600/30">Built-in</span>}
                <TagBadges tags={src.tags} />
              </div>
              <div className="text-slate-600 truncate mt-0.5 font-mono text-[10px]">{src.url}</div>
            </div>
            {!src.builtin && (
              <button onClick={() => setConfirmSrc(src)}
                className="text-red-500 hover:text-red-400 px-1.5 py-1 rounded hover:bg-red-950/30 transition-colors flex-shrink-0"
                title="Quelle entfernen">✕</button>
            )}
          </div>
        ))}
      </div>

      {confirmSrc && (
        <ConfirmDialog
          message={`Quelle "${confirmSrc.name}" entfernen?`}
          confirmLabel="Entfernen"
          onConfirm={() => { const s = confirmSrc; setConfirmSrc(null); handleDeleteSource(s); }}
          onCancel={() => setConfirmSrc(null)}
        />
      )}
    </div>
  );
}

function RulesList() {
  const [rules,    setRules]    = useState<Rule[]>([]);
  const [total,    setTotal]    = useState(0);
  const [search,   setSearch]   = useState('');
  const [offset,   setOffset]   = useState(0);
  const [loading,  setLoading]  = useState(false);
  const LIMIT = 100;

  useEffect(() => {
    setLoading(true);
    fetchRules({ search, limit: LIMIT, offset })
      .then(r => { setRules(r.rules); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [search, offset]);

  const pages = Math.ceil(total / LIMIT);
  const page  = Math.floor(offset / LIMIT);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="text-sm font-semibold text-slate-200">
          Aktive Regeln
          {total > 0 && <span className="ml-2 text-slate-500 font-normal">{total.toLocaleString()}</span>}
        </h2>
        <input
          className="input text-xs w-56"
          placeholder="Suche nach msg, sid, classtype…"
          value={search}
          onChange={e => { setSearch(e.target.value); setOffset(0); }}
        />
      </div>

      {loading ? (
        <p className="text-slate-500 text-xs">Lade…</p>
      ) : rules.length === 0 ? (
        <p className="text-slate-600 text-xs">
          {total === 0 ? 'Keine Regeln geladen – bitte ein Update starten.' : 'Keine Treffer.'}
        </p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="border-b border-slate-800">
                <tr className="text-left text-slate-500">
                  <th className="pb-2 pr-3 w-20">SID</th>
                  <th className="pb-2 pr-3">Beschreibung (msg)</th>
                  <th className="pb-2 pr-3 w-28">Classtype</th>
                  <th className="pb-2 pr-3 w-16">Aktion</th>
                  <th className="pb-2 pr-3 w-16">Status</th>
                  <th className="pb-2 w-40">Datei</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => (
                  <tr key={`${r.sid}-${i}`} className={`border-b border-slate-800/40 hover:bg-slate-800/20 ${!r.enabled ? 'opacity-40' : ''}`}>
                    <td className="py-1.5 pr-3 font-mono text-slate-400">{r.sid ?? '—'}</td>
                    <td className="py-1.5 pr-3 text-slate-300 max-w-xs truncate" title={r.msg}>{r.msg}</td>
                    <td className="py-1.5 pr-3 text-slate-500 truncate">{r.classtype ?? '—'}</td>
                    <td className="py-1.5 pr-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-mono ${
                        r.action === 'drop' ? 'bg-red-900/40 text-red-300' :
                        r.action === 'pass' ? 'bg-green-900/40 text-green-300' :
                        'bg-slate-700/50 text-slate-400'
                      }`}>{r.action}</span>
                    </td>
                    <td className="py-1.5 pr-3">
                      <span className={`text-[10px] ${r.enabled ? 'text-green-500' : 'text-slate-600'}`}>
                        {r.enabled ? '● aktiv' : '○ aus'}
                      </span>
                    </td>
                    <td className="py-1.5 font-mono text-slate-600 text-[10px] truncate">{r.file}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {pages > 1 && (
            <div className="flex items-center gap-2 text-xs text-slate-500">
              <button className="btn-ghost text-xs disabled:opacity-30" disabled={page === 0}
                onClick={() => setOffset(Math.max(0, offset - LIMIT))}>← Zurück</button>
              <span>{page + 1} / {pages}</span>
              <button className="btn-ghost text-xs disabled:opacity-30" disabled={page >= pages - 1}
                onClick={() => setOffset(offset + LIMIT)}>Weiter →</button>
            </div>
          )}
        </>
      )}
    </div>
  );
}

// ── SslSettings ───────────────────────────────────────────────────────────────

type SslMode = 'upload' | 'self-signed' | 'acme';
type UploadFormat = 'pem' | 'pfx';

function SslStatusBadge({ status }: { status: SslStatus }) {
  if (!status.active || status.mode === 'none')
    return <span className="px-2 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">Kein TLS</span>;
  const expiry = status.not_after ? new Date(status.not_after) : null;
  const daysLeft = expiry ? Math.ceil((expiry.getTime() - Date.now()) / 86400000) : null;
  const color = daysLeft == null ? 'green' : daysLeft < 14 ? 'red' : daysLeft < 30 ? 'yellow' : 'green';
  return (
    <span className={`px-2 py-0.5 text-[10px] rounded border ${
      color === 'green' ? 'bg-green-950/40 text-green-300 border-green-700/40' :
      color === 'yellow' ? 'bg-yellow-950/40 text-yellow-300 border-yellow-700/40' :
      'bg-red-950/40 text-red-300 border-red-700/40'
    }`}>
      TLS aktiv {daysLeft != null ? `· ${daysLeft}d` : ''}
    </span>
  );
}

function SslSettings() {
  const [status,  setStatus]  = useState<SslStatus | null>(null);
  const [mode,    setMode]    = useState<SslMode>('self-signed');
  const [saving,  setSaving]  = useState(false);
  const [msg,     setMsg]     = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  // Upload state
  const [uploadFormat, setUploadFormat] = useState<UploadFormat>('pem');
  const [certFile, setCertFile] = useState<File | null>(null);
  const [keyFile,  setKeyFile]  = useState<File | null>(null);
  const [caFile,   setCaFile]   = useState<File | null>(null);
  const [pfxFile,  setPfxFile]  = useState<File | null>(null);
  const [pfxPassword, setPfxPassword] = useState('');

  // Hostname state
  const [hostname,     setHostname]     = useState('');
  const [hostnameSaving, setHostnameSaving] = useState(false);

  // Self-signed state
  const [ss, setSs] = useState<SslSelfSignedRequest>({ common_name: '', days: 365, country: 'DE', org: '' });

  // ACME state
  const [acme, setAcme] = useState<SslAcmeConfig>({
    domains: [],
    email: '',
    ca_url: 'https://acme-v02.api.letsencrypt.org/directory',
  });
  const [acmeDomainInput, setAcmeDomainInput] = useState('');

  useEffect(() => {
    fetchSslStatus()
      .then(s => {
        setStatus(s);
        if (s.mode !== 'none') setMode(s.mode as SslMode);
        if (s.hostname) setHostname(s.hostname);
      })
      .catch(() => setStatus({ mode: 'none', active: false }));
  }, []);

  function flash(type: 'ok' | 'err', text: string) {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 4000);
  }

  async function handleSaveHostname() {
    setHostnameSaving(true);
    try {
      await setSslHostname(hostname);
      flash('ok', 'Hostname gespeichert – nginx beim nächsten Neustart aktiv ✓');
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : 'Fehler');
    } finally {
      setHostnameSaving(false);
    }
  }

  async function handleApply() {
    setSaving(true);
    try {
      let s: SslStatus;
      if (mode === 'upload') {
        if (uploadFormat === 'pfx') {
          if (!pfxFile) { flash('err', 'PFX-Datei ist erforderlich'); setSaving(false); return; }
          s = await uploadSslPfx(pfxFile, pfxPassword);
        } else {
          if (!certFile || !keyFile) { flash('err', 'Zertifikat und Schlüssel sind erforderlich'); setSaving(false); return; }
          s = await uploadSslCert(certFile, keyFile, caFile ?? undefined);
        }
      } else if (mode === 'self-signed') {
        if (!ss.common_name) { flash('err', 'Common Name ist erforderlich'); setSaving(false); return; }
        s = await applySslSelfSigned(ss);
      } else {
        if (!acme.email || acme.domains.length === 0) { flash('err', 'E-Mail und mindestens eine Domain erforderlich'); setSaving(false); return; }
        s = await applySslAcme(acme);
      }
      setStatus(s);
      flash('ok', 'SSL-Konfiguration gespeichert ✓');
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : 'Fehler');
    } finally {
      setSaving(false);
    }
  }

  const TAB_LABEL: Record<SslMode, string> = {
    'upload':      'Zertifikat hochladen',
    'self-signed': 'Self-Signed generieren',
    'acme':        'ACME / Let\'s Encrypt',
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">SSL / TLS-Zertifikat</h2>
        {status && <SslStatusBadge status={status} />}
      </div>

      {/* Hostname */}
      <div className="rounded border border-slate-700/60 bg-slate-900/40 p-3 space-y-2">
        <p className="text-xs font-medium text-slate-300">Server-Hostname</p>
        <p className="text-[11px] text-slate-500">
          nginx <code className="font-mono text-slate-400">server_name</code> – Hostname oder IP auf die der Webserver hört.
          Wird beim nächsten Container-Neustart aktiv.
        </p>
        <div className="flex gap-2">
          <input
            className="input text-xs font-mono flex-1"
            placeholder="ids.firma.de oder 192.168.1.230"
            value={hostname}
            onChange={e => setHostname(e.target.value)}
          />
          <button type="button" className="btn-ghost text-xs shrink-0"
            disabled={hostnameSaving}
            onClick={handleSaveHostname}>
            {hostnameSaving ? 'Speichern…' : 'Speichern'}
          </button>
        </div>
      </div>

      {/* Aktuelles Zertifikat */}
      {status?.active && status.mode !== 'none' && (
        <div className="rounded-lg border border-slate-700/60 bg-slate-800/30 px-4 py-3 text-xs space-y-1">
          <p className="text-slate-400 font-medium">Aktives Zertifikat</p>
          {status.subject  && <p className="text-slate-300">Subject: <span className="font-mono">{status.subject}</span></p>}
          {status.issuer   && <p className="text-slate-500">Issuer: <span className="font-mono">{status.issuer}</span></p>}
          {status.not_after && <p className="text-slate-500">Gültig bis: {new Date(status.not_after).toLocaleDateString('de-DE')}</p>}
          {status.domains?.length ? <p className="text-slate-500">Domains: {status.domains.join(', ')}</p> : null}
        </div>
      )}

      {/* Modus-Tabs */}
      <div className="flex gap-1 border-b border-slate-800 pb-0">
        {(['upload', 'self-signed', 'acme'] as SslMode[]).map(m => (
          <button
            key={m}
            onClick={() => setMode(m)}
            className={`px-3 py-1.5 text-xs rounded-t transition-colors border-b-2 -mb-px ${
              mode === m
                ? 'text-cyan-300 border-cyan-500 bg-cyan-950/30'
                : 'text-slate-500 border-transparent hover:text-slate-300'
            }`}
          >{TAB_LABEL[m]}</button>
        ))}
      </div>

      {/* Upload */}
      {mode === 'upload' && (
        <div className="space-y-3 text-xs">
          {/* Format-Toggle */}
          <div className="flex gap-1 p-0.5 bg-slate-800/60 rounded w-fit border border-slate-700/40">
            {(['pem', 'pfx'] as UploadFormat[]).map(f => (
              <button key={f} type="button"
                onClick={() => setUploadFormat(f)}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors ${
                  uploadFormat === f
                    ? 'bg-cyan-500/20 text-cyan-200 border border-cyan-500/40'
                    : 'text-slate-500 hover:text-slate-300'
                }`}>
                {f === 'pem' ? 'PEM-Dateien' : 'PFX / PKCS#12'}
              </button>
            ))}
          </div>

          {uploadFormat === 'pem' ? (
            <>
              <p className="text-slate-500">Lade ein bestehendes PEM-Zertifikat und den zugehörigen privaten Schlüssel hoch.</p>
              {[
                { label: 'Zertifikat (cert.pem) *', set: setCertFile, accept: '.pem,.crt,.cer' },
                { label: 'Privater Schlüssel (key.pem) *', set: setKeyFile, accept: '.pem,.key' },
                { label: 'CA-Chain (optional)', set: setCaFile, accept: '.pem,.crt,.cer' },
              ].map(({ label, set, accept }) => (
                <div key={label} className="flex flex-col gap-1">
                  <label className="text-slate-400">{label}</label>
                  <input type="file" accept={accept}
                    className="block text-slate-300 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:bg-slate-700 file:text-slate-200 hover:file:bg-slate-600 cursor-pointer"
                    onChange={e => set(e.target.files?.[0] ?? null)} />
                </div>
              ))}
            </>
          ) : (
            <>
              <p className="text-slate-500">
                Importiert eine PFX/PKCS#12-Datei (z.B. aus Windows CA exportiert). Zertifikat und privater Schlüssel werden automatisch extrahiert.
              </p>
              <div className="flex flex-col gap-1">
                <label className="text-slate-400">PFX-Datei *</label>
                <input type="file" accept=".pfx,.p12"
                  className="block text-slate-300 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:bg-slate-700 file:text-slate-200 hover:file:bg-slate-600 cursor-pointer"
                  onChange={e => setPfxFile(e.target.files?.[0] ?? null)} />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-slate-400">Passwort für privaten Schlüssel</label>
                <input className="input font-mono" type="password"
                  placeholder="Leer lassen wenn kein Passwort gesetzt"
                  value={pfxPassword}
                  onChange={e => setPfxPassword(e.target.value)} />
              </div>
            </>
          )}
        </div>
      )}

      {/* Self-Signed */}
      {mode === 'self-signed' && (
        <div className="space-y-3 text-xs">
          <p className="text-slate-500">Generiert ein selbstsigniertes Zertifikat direkt auf dem Server. Geeignet für interne Deployments ohne öffentliche Domain.</p>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1 col-span-2">
              <label className="text-slate-400">Common Name (CN) / Hostname *</label>
              <input className="input" placeholder="ids.local oder 192.168.1.79"
                value={ss.common_name} onChange={e => setSs(s => ({ ...s, common_name: e.target.value }))} />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Gültigkeit (Tage)</label>
              <input className="input" type="number" min={1} max={3650}
                value={ss.days} onChange={e => setSs(s => ({ ...s, days: parseInt(e.target.value) || 365 }))} />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">Land (2-stellig)</label>
              <input className="input" maxLength={2} placeholder="DE"
                value={ss.country ?? ''} onChange={e => setSs(s => ({ ...s, country: e.target.value }))} />
            </div>
            <div className="flex flex-col gap-1 col-span-2">
              <label className="text-slate-400">Organisation</label>
              <input className="input" placeholder="Cyjan IDS"
                value={ss.org ?? ''} onChange={e => setSs(s => ({ ...s, org: e.target.value }))} />
            </div>
          </div>
        </div>
      )}

      {/* ACME */}
      {mode === 'acme' && (
        <div className="space-y-3 text-xs">
          <p className="text-slate-500">Automatische Zertifikatsvergabe via ACME (z.B. Let's Encrypt). Der Server muss über Port 80/443 erreichbar sein.</p>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">E-Mail-Adresse *</label>
            <input className="input" type="email" placeholder="admin@example.com"
              value={acme.email} onChange={e => setAcme(a => ({ ...a, email: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Domains *</label>
            <div className="flex gap-2">
              <input className="input flex-1" placeholder="ids.example.com"
                value={acmeDomainInput}
                onChange={e => setAcmeDomainInput(e.target.value)}
                onKeyDown={e => {
                  if ((e.key === 'Enter' || e.key === ',') && acmeDomainInput.trim()) {
                    e.preventDefault();
                    setAcme(a => ({ ...a, domains: [...a.domains, acmeDomainInput.trim()] }));
                    setAcmeDomainInput('');
                  }
                }}
              />
              <button type="button" className="btn-ghost text-xs"
                onClick={() => { if (acmeDomainInput.trim()) { setAcme(a => ({ ...a, domains: [...a.domains, acmeDomainInput.trim()] })); setAcmeDomainInput(''); } }}>
                + Hinzufügen
              </button>
            </div>
            {acme.domains.length > 0 && (
              <div className="flex flex-wrap gap-1 mt-1">
                {acme.domains.map(d => (
                  <span key={d} className="flex items-center gap-1 px-2 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-300 text-[11px]">
                    {d}
                    <button onClick={() => setAcme(a => ({ ...a, domains: a.domains.filter(x => x !== d) }))}
                      className="text-slate-500 hover:text-red-400 leading-none">✕</button>
                  </span>
                ))}
              </div>
            )}
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">ACME-Verzeichnis-URL</label>
            <div className="flex gap-2 flex-wrap">
              {[
                { label: 'Let\'s Encrypt (Prod)',    url: 'https://acme-v02.api.letsencrypt.org/directory' },
                { label: 'Let\'s Encrypt (Staging)', url: 'https://acme-staging-v02.api.letsencrypt.org/directory' },
              ].map(p => (
                <button key={p.label} type="button"
                  onClick={() => setAcme(a => ({ ...a, ca_url: p.url }))}
                  className={`px-2 py-0.5 text-[11px] rounded border transition-colors ${
                    acme.ca_url === p.url
                      ? 'bg-cyan-900/50 border-cyan-600/60 text-cyan-300'
                      : 'bg-slate-800/50 border-slate-700/40 text-slate-400 hover:border-slate-500/60 hover:text-slate-300'
                  }`}>{p.label}</button>
              ))}
            </div>
            <input className="input mt-1" type="url" placeholder="https://acme-v02.api.letsencrypt.org/directory"
              value={acme.ca_url ?? ''} onChange={e => setAcme(a => ({ ...a, ca_url: e.target.value }))} />
          </div>
        </div>
      )}

      {/* Footer */}
      <div className="flex items-center justify-between pt-1">
        <div>
          {msg?.type === 'ok'  && <span className="text-xs text-green-400">{msg.text}</span>}
          {msg?.type === 'err' && <span className="text-xs text-red-400">{msg.text}</span>}
        </div>
        <button className="btn-primary text-xs" disabled={saving} onClick={handleApply}>
          {saving ? 'Wird angewendet…' : 'Anwenden'}
        </button>
      </div>
    </div>
  );
}

// ── SyslogSettings ────────────────────────────────────────────────────────────

const SYSLOG_DEFAULT: SyslogConfig = {
  enabled: false, host: '', port: 514, protocol: 'udp', format: 'rfc5424', min_severity: 'low',
};

function SyslogSettings() {
  const [cfg,     setCfg]     = useState<SyslogConfig>(SYSLOG_DEFAULT);
  const [saving,  setSaving]  = useState(false);
  const [testing, setTesting] = useState(false);
  const [msg,     setMsg]     = useState<{ type: 'ok' | 'err'; text: string } | null>(null);

  useEffect(() => {
    fetchSyslogConfig().then(setCfg).catch(() => {});
  }, []);

  function flash(type: 'ok' | 'err', text: string) {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 4000);
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try { await saveSyslogConfig(cfg); flash('ok', 'Gespeichert ✓'); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : 'Fehler'); }
    finally { setSaving(false); }
  }

  async function handleTest() {
    if (!cfg.host) { flash('err', 'Bitte zuerst einen Syslog-Host eingeben'); return; }
    setTesting(true);
    try {
      const r = await testSyslog({ host: cfg.host, port: cfg.port, protocol: cfg.protocol, format: cfg.format });
      flash('ok', r.message);
    } catch (err: unknown) { flash('err', err instanceof Error ? err.message : 'Test fehlgeschlagen'); }
    finally { setTesting(false); }
  }

  return (
    <form onSubmit={handleSave} className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">Syslog / SIEM-Export</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-cyan-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
            Export aktiviert
          </span>
        </label>
      </div>

      <p className="text-xs text-slate-500">
        Leitet neue Alerts alle 30 Sekunden an einen Syslog-Server weiter. Unterstützt RFC 5424, CEF (ArcSight, QRadar) und LEEF (IBM QRadar).
      </p>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
          <div className="flex flex-col gap-1 col-span-2">
            <label className="text-slate-400">Syslog-Host / IP *</label>
            <input className="input" placeholder="192.168.1.100 oder siem.firma.de"
              value={cfg.host} onChange={e => setCfg(c => ({ ...c, host: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Port</label>
            <input className="input" type="number" min={1} max={65535}
              value={cfg.port} onChange={e => setCfg(c => ({ ...c, port: parseInt(e.target.value) || 514 }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Protokoll</label>
            <select className="input" value={cfg.protocol}
              onChange={e => setCfg(c => ({ ...c, protocol: e.target.value as 'udp' | 'tcp' }))}>
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Format</label>
            <select className="input" value={cfg.format}
              onChange={e => setCfg(c => ({ ...c, format: e.target.value as SyslogConfig['format'] }))}>
              <option value="rfc5424">RFC 5424 (Standard)</option>
              <option value="cef">CEF (ArcSight / QRadar)</option>
              <option value="leef">LEEF (IBM QRadar)</option>
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Mindest-Schweregrad</label>
            <select className="input" value={cfg.min_severity}
              onChange={e => setCfg(c => ({ ...c, min_severity: e.target.value as SyslogConfig['min_severity'] }))}>
              <option value="low">Low und höher (alle)</option>
              <option value="medium">Medium und höher</option>
              <option value="high">High und höher</option>
              <option value="critical">Nur Critical</option>
            </select>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between pt-1">
        <div>
          {msg?.type === 'ok'  && <span className="text-xs text-green-400">{msg.text}</span>}
          {msg?.type === 'err' && <span className="text-xs text-red-400">{msg.text}</span>}
        </div>
        <div className="flex gap-2">
          <button type="button" className="btn-ghost text-xs" disabled={testing || !cfg.host} onClick={handleTest}>
            {testing ? 'Teste…' : 'Verbindung testen'}
          </button>
          <button type="submit" className="btn-primary text-xs" disabled={saving}>
            {saving ? 'Speichern…' : 'Speichern'}
          </button>
        </div>
      </div>
    </form>
  );
}

// ── ItopSettings ──────────────────────────────────────────────────────────────

const ITOP_DEFAULT: ItopConfig = {
  enabled: false, base_url: '', user: '', password: '', org_filter: '', ssl_verify: false,
};

function ItopSettings() {
  const [cfg,     setCfg]     = useState<ItopConfig>(ITOP_DEFAULT);
  const [saving,  setSaving]  = useState(false);
  const [testing, setTesting] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [msg,     setMsg]     = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [sync,    setSync]    = useState<ItopSyncState | null>(null);
  const [showPw,  setShowPw]  = useState(false);
  const pollRef               = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    fetchItopConfig().then(setCfg).catch(() => {});
    getItopSyncStatus().then(setSync).catch(() => {});
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, []);

  function flash(type: 'ok' | 'err', text: string) {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 4000);
  }

  function startPolling() {
    if (pollRef.current) return;
    pollRef.current = setInterval(async () => {
      const s = await getItopSyncStatus().catch(() => null);
      if (s) {
        setSync(s);
        if (s.phase !== 'running') {
          clearInterval(pollRef.current!);
          pollRef.current = null;
          setSyncing(false);
        }
      }
    }, 1500);
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try { await saveItopConfig(cfg); flash('ok', 'Gespeichert ✓'); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : 'Fehler'); }
    finally { setSaving(false); }
  }

  async function handleTest() {
    setTesting(true);
    try {
      const r = await testItopConnection();
      flash('ok', `Verbunden ✓  –  Organisationen: ${r.organisations.join(', ') || '(keine)'}`);
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : 'Verbindung fehlgeschlagen');
    } finally { setTesting(false); }
  }

  async function handleSync() {
    setSyncing(true);
    setSync(null);
    try {
      await triggerItopSync();
      startPolling();
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : 'Fehler beim Starten');
      setSyncing(false);
    }
  }

  const phaseColor: Record<string, string> = {
    running: 'text-cyan-400',
    done:    'text-green-400',
    error:   'text-red-400',
    idle:    'text-slate-500',
  };

  return (
    <form onSubmit={handleSave} className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">iTop CMDB-Integration</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-cyan-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-cyan-300 font-medium' : 'text-slate-500'}>Aktiv</span>
        </label>
      </div>

      <p className="text-xs text-slate-500">
        Importiert Subnets in <span className="text-slate-300 font-mono">Bekannte Netzwerke</span> und
        Server/Geräte in <span className="text-slate-300 font-mono">Hosts</span> aus einer iTop-Instanz.
        Hosts erhalten <span className="text-slate-300 font-mono">trust_source = cmdb</span>.
      </p>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">

          <div className="flex flex-col gap-1 sm:col-span-3">
            <label className="text-slate-400">iTop-URL</label>
            <input className="input font-mono"
              placeholder="https://itop.firma.de"
              value={cfg.base_url}
              onChange={e => setCfg(c => ({ ...c, base_url: e.target.value }))} />
            <span className="text-[10px] text-slate-600">
              Basis-URL der iTop-Instanz (ohne /webservices/rest.php).
            </span>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Benutzer *</label>
            <input className="input font-mono" autoComplete="off"
              value={cfg.user}
              onChange={e => setCfg(c => ({ ...c, user: e.target.value }))} />
          </div>

          <div className="flex flex-col gap-1 sm:col-span-2">
            <label className="text-slate-400">Passwort *</label>
            <div className="flex gap-2">
              <input className="input font-mono flex-1"
                type={showPw ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder={cfg.password ? '••••••••' : 'leer'}
                value={cfg.password}
                onChange={e => setCfg(c => ({ ...c, password: e.target.value }))} />
              <button type="button" className="btn-ghost text-xs"
                onClick={() => setShowPw(v => !v)}>
                {showPw ? 'Verbergen' : 'Zeigen'}
              </button>
            </div>
          </div>

          <div className="flex flex-col gap-1 sm:col-span-2">
            <label className="text-slate-400">Organisations-Filter</label>
            <input className="input font-mono"
              placeholder="z.B. My Company (leer = alle)"
              value={cfg.org_filter}
              onChange={e => setCfg(c => ({ ...c, org_filter: e.target.value }))} />
            <span className="text-[10px] text-slate-600">
              Exakter iTop-Organisationsname – filtert Subnets und CIs auf eine Org.
            </span>
          </div>

          <div className="flex items-end gap-2 pb-1">
            <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
              <input type="checkbox" className="accent-cyan-500"
                checked={cfg.ssl_verify}
                onChange={e => setCfg(c => ({ ...c, ssl_verify: e.target.checked }))} />
              <span className={cfg.ssl_verify ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
                SSL prüfen
              </span>
            </label>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between pt-1 flex-wrap gap-2">
        <div className="flex gap-2">
          <button type="button" className="btn-ghost text-xs"
            disabled={testing || !cfg.enabled}
            onClick={handleTest}>
            {testing ? 'Teste…' : 'Verbindung testen'}
          </button>
          <button type="button" className="btn-ghost text-xs"
            disabled={syncing || !cfg.enabled}
            onClick={handleSync}>
            {syncing ? 'Synchronisiert…' : 'Jetzt synchronisieren'}
          </button>
        </div>
        <div className="flex items-center gap-3">
          {msg?.type === 'ok'  && <span className="text-xs text-green-400">{msg.text}</span>}
          {msg?.type === 'err' && <span className="text-xs text-red-400">{msg.text}</span>}
          <button type="submit" className="btn-primary text-xs" disabled={saving}>
            {saving ? 'Speichern…' : 'Speichern'}
          </button>
        </div>
      </div>

      {/* Sync-Status */}
      {sync && sync.phase !== 'idle' && (
        <div className="mt-2 rounded border border-slate-700 bg-slate-900/60 p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className={`font-mono font-medium ${phaseColor[sync.phase] ?? 'text-slate-400'}`}>
              {sync.phase === 'running' ? 'Läuft…' : sync.phase === 'done' ? 'Fertig' : sync.phase === 'error' ? 'Fehler' : sync.phase}
            </span>
            {sync.finished_at && (
              <span className="text-slate-600">{new Date(sync.finished_at).toLocaleTimeString()}</span>
            )}
          </div>

          {sync.phase === 'done' && sync.stats && (
            <div className="flex gap-4 text-xs text-slate-400">
              <span>Netzwerke: <span className="text-slate-200">{sync.stats.networks_upserted ?? 0}</span></span>
              <span>Hosts: <span className="text-slate-200">{sync.stats.hosts_upserted ?? 0}</span></span>
              {(sync.stats.networks_errors ?? 0) + (sync.stats.hosts_errors ?? 0) > 0 && (
                <span className="text-amber-400">
                  Fehler: {(sync.stats.networks_errors ?? 0) + (sync.stats.hosts_errors ?? 0)}
                </span>
              )}
            </div>
          )}

          <pre className="text-[10px] font-mono text-slate-400 max-h-48 overflow-y-auto whitespace-pre-wrap leading-relaxed">
            {sync.log.join('\n')}
          </pre>
        </div>
      )}
    </form>
  );
}

// ── IrmaSettings ──────────────────────────────────────────────────────────────

const IRMA_DEFAULT: IrmaConfig = {
  enabled: false,
  base_url: 'https://10.133.168.115/rest',
  user: '',
  password: '',
  poll_interval: 30,
  ssl_verify: false,
};

function IrmaSettings() {
  const [cfg,    setCfg]    = useState<IrmaConfig>(IRMA_DEFAULT);
  const [saving, setSaving] = useState(false);
  const [msg,    setMsg]    = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [showPw, setShowPw] = useState(false);

  useEffect(() => {
    fetchIrmaConfig().then(setCfg).catch(() => {});
  }, []);

  function flash(type: 'ok' | 'err', text: string) {
    setMsg({ type, text });
    setTimeout(() => setMsg(null), 4000);
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try { await saveIrmaConfig(cfg); flash('ok', 'Gespeichert ✓ – IRMA-Bridge lädt die Änderungen automatisch beim nächsten Poll.'); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : 'Fehler'); }
    finally { setSaving(false); }
  }

  return (
    <form onSubmit={handleSave} className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">IRMA-Integration</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-cyan-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
            Aktiv
          </span>
        </label>
      </div>

      <p className="text-xs text-slate-500">
        Pollt die REST-API einer IRMA-IDS-Appliance und importiert deren Alarme als <span className="text-violet-300 font-mono">external</span>-Quelle in das Cyjan-Dashboard. Änderungen an Credentials greifen automatisch beim nächsten Poll-Cycle – kein Neustart nötig.
      </p>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50' : ''}`}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">
          <div className="flex flex-col gap-1 sm:col-span-3">
            <label className="text-slate-400">IRMA-Basis-URL</label>
            <input className="input font-mono"
              placeholder="https://10.133.168.115/rest"
              value={cfg.base_url}
              onChange={e => setCfg(c => ({ ...c, base_url: e.target.value }))} />
            <span className="text-[10px] text-slate-600">Volle URL inkl. Schema und /rest-Pfad.</span>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Benutzer *</label>
            <input className="input font-mono" autoComplete="off"
              value={cfg.user}
              onChange={e => setCfg(c => ({ ...c, user: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1 sm:col-span-2">
            <label className="text-slate-400">Passwort *</label>
            <div className="flex gap-2">
              <input
                className="input font-mono flex-1"
                type={showPw ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder={cfg.password ? '••••••••' : 'leer'}
                value={cfg.password}
                onChange={e => setCfg(c => ({ ...c, password: e.target.value }))}
              />
              <button type="button"
                onClick={() => setShowPw(v => !v)}
                className="btn-ghost text-xs">
                {showPw ? 'Verbergen' : 'Zeigen'}
              </button>
            </div>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-slate-400">Poll-Intervall (Sek.)</label>
            <input className="input" type="number" min={10} max={600}
              value={cfg.poll_interval}
              onChange={e => setCfg(c => ({ ...c, poll_interval: parseInt(e.target.value) || 30 }))} />
          </div>
          <div className="flex items-end gap-2 sm:col-span-2">
            <label className="flex items-center gap-2 cursor-pointer select-none text-xs pb-2">
              <input type="checkbox" className="accent-cyan-500"
                checked={cfg.ssl_verify}
                onChange={e => setCfg(c => ({ ...c, ssl_verify: e.target.checked }))} />
              <span className={cfg.ssl_verify ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
                SSL-Zertifikat prüfen
              </span>
            </label>
          </div>
        </div>
      </div>

      <div className="flex items-center justify-between pt-1">
        <div>
          {msg?.type === 'ok'  && <span className="text-xs text-green-400">{msg.text}</span>}
          {msg?.type === 'err' && <span className="text-xs text-red-400">{msg.text}</span>}
        </div>
        <div className="flex gap-2">
          <button type="submit" className="btn-primary text-xs" disabled={saving}>
            {saving ? 'Speichern…' : 'Speichern'}
          </button>
        </div>
      </div>
    </form>
  );
}

// ── SystemUpdate ──────────────────────────────────────────────────────────────

const PHASE_LABEL: Record<SystemUpdateStatus['phase'], string> = {
  idle:       'Bereit',
  extracting: 'Entpacke ZIP …',
  loading:    'Lade Images …',
  building:   'Baue Images …',
  restarting: 'Starte Services neu …',
  done:       'Abgeschlossen',
  error:      'Fehler',
};
const PHASE_COLOR: Record<SystemUpdateStatus['phase'], string> = {
  idle:       'text-slate-400',
  extracting: 'text-cyan-400',
  loading:    'text-cyan-400',
  building:   'text-amber-400',
  restarting: 'text-amber-400',
  done:       'text-green-400',
  error:      'text-red-400',
};

function SystemUpdate() {
  const [file,        setFile]        = useState<File | null>(null);
  const [pullImages,  setPullImages]  = useState(false);
  const [uploading,   setUploading]   = useState(false);
  const [error,       setError]       = useState<string | null>(null);
  const [status,      setStatus]      = useState<SystemUpdateStatus>({
    phase: 'idle', log: [], progress: 0, started_at: null, finished_at: null,
  });
  const [restarting,      setRestarting]      = useState(false);
  const [confirmRestart,  setConfirmRestart]  = useState(false);
  const logRef = useRef<HTMLDivElement>(null);

  const isRunning = ['extracting', 'loading', 'building', 'restarting'].includes(status.phase);

  // Initialen Status laden
  useEffect(() => {
    fetchSystemUpdateStatus().then(setStatus).catch(() => {});
  }, []);

  // Während Update läuft: alle 2s pollen
  useEffect(() => {
    if (!isRunning) return;
    const t = setInterval(() => {
      fetchSystemUpdateStatus().then(setStatus).catch(() => {});
    }, 2000);
    return () => clearInterval(t);
  }, [isRunning]);

  // Nach "done": API-Neustart abwarten – pollen bis API wieder antwortet
  useEffect(() => {
    if (status.phase !== 'done') return;
    setRestarting(true);
    const t = setInterval(() => {
      fetchSystemUpdateStatus()
        .then(s => { setStatus(s); setRestarting(false); clearInterval(t); })
        .catch(() => { /* API noch nicht bereit */ });
    }, 3000);
    return () => clearInterval(t);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [status.phase]);

  // Log automatisch nach unten scrollen
  useEffect(() => {
    if (logRef.current) logRef.current.scrollTop = logRef.current.scrollHeight;
  }, [status.log.length]);

  async function handleStart() {
    if (!file) return;
    setError(null);
    setUploading(true);
    setRestarting(false);
    try {
      await startSystemUpdate(file, pullImages);
      setStatus(s => ({ ...s, phase: 'extracting', log: [], progress: 0, started_at: new Date().toISOString() }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setUploading(false);
    }
  }

  async function handleRestart() {
    setConfirmRestart(false);
    setError(null);
    try {
      await restartStack();
      setRestarting(true);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }

  return (
    <div>
      <div className="flex items-start justify-between mb-5">
        <div>
          <h2 className="text-base font-semibold text-slate-100 mb-1">System-Update</h2>
          <p className="text-sm text-slate-400">
            Laden Sie die aktuelle Version als ZIP von GitHub herunter und importieren Sie sie hier.
            Konfiguration (<code className="text-xs bg-slate-800 px-1 rounded">.env</code>),
            Zertifikate und Datenbank bleiben erhalten.
          </p>
        </div>
        {status.version && (
          <a
            href="https://github.com/JxxKal/ids/releases"
            target="_blank"
            rel="noreferrer"
            className="ml-6 shrink-0 flex flex-col items-end gap-0.5 group"
            title="GitHub Releases öffnen"
          >
            <span className="text-[10px] uppercase tracking-wide text-slate-500">Installierte Version</span>
            <span className="text-sm font-mono font-semibold text-cyan-400 group-hover:text-cyan-300 transition-colors">
              {status.version}
            </span>
          </a>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <label className="flex items-center gap-2 cursor-pointer">
          <input
            type="file"
            accept=".zip"
            className="hidden"
            disabled={isRunning || uploading}
            onChange={e => { setFile(e.target.files?.[0] ?? null); setError(null); }}
          />
          <span className="btn text-sm px-3 py-1.5 border border-slate-600 rounded bg-slate-800 hover:bg-slate-700 text-slate-300">
            {file ? file.name : 'ZIP auswählen …'}
          </span>
        </label>

        <button
          type="button"
          onClick={handleStart}
          disabled={!file || isRunning || uploading}
          className="flex items-center gap-2 px-4 py-1.5 rounded text-sm font-medium
                     bg-cyan-700 hover:bg-cyan-600 text-white
                     disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Upload size={14} />
          {uploading ? 'Wird hochgeladen …' : 'Update starten'}
        </button>
      </div>

      <label className="mt-3 flex items-center gap-2 cursor-pointer w-fit">
        <input
          type="checkbox"
          checked={pullImages}
          disabled={isRunning || uploading}
          onChange={e => setPullImages(e.target.checked)}
          className="accent-cyan-500"
        />
        <span className="text-sm text-slate-400">
          Basis-Images aktualisieren
          <span className="ml-1 text-slate-600 text-xs">(benötigt Internetzugang)</span>
        </span>
      </label>

      {error && (
        <p className="mt-3 text-sm text-red-400">{error}</p>
      )}

      {/* Stack-Neustart */}
      <div className="mt-6 pt-5 border-t border-slate-700/60">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <p className="text-sm font-medium text-slate-200">Stack neu starten</p>
            <p className="text-xs text-slate-500 mt-0.5">
              Startet alle Services neu (~20 Sek. Unterbrechung). Konfiguration und Daten bleiben erhalten.
            </p>
          </div>
          {confirmRestart ? (
            <div className="flex items-center gap-2">
              <span className="text-xs text-amber-300">Wirklich neu starten?</span>
              <button
                type="button"
                onClick={handleRestart}
                className="px-3 py-1 rounded text-xs font-medium bg-red-700 hover:bg-red-600 text-white transition-colors"
              >
                Ja, neu starten
              </button>
              <button
                type="button"
                onClick={() => setConfirmRestart(false)}
                className="px-3 py-1 rounded text-xs font-medium bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
              >
                Abbrechen
              </button>
            </div>
          ) : (
            <button
              type="button"
              onClick={() => setConfirmRestart(true)}
              disabled={isRunning || restarting}
              className="flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium
                         border border-slate-600 bg-slate-800 hover:bg-slate-700 text-slate-300
                         disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
            >
              <RotateCcw size={14} />
              Neu starten
            </button>
          )}
        </div>
      </div>

      {/* Restarting-Banner */}
      {restarting && (
        <div className="mt-4 flex items-center gap-2 rounded border border-amber-700/40 bg-amber-950/30 px-3 py-2">
          <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse shrink-0" />
          <span className="text-xs text-amber-300">
            API-Container wird neu gestartet — bitte warten (~15 Sek.) …
          </span>
        </div>
      )}

      {/* Status + Progressbar */}
      <div className="mt-4 space-y-2">
        <div className="flex items-center justify-between">
          <span className={`text-sm font-medium ${PHASE_COLOR[status.phase]}`}>
            ● {PHASE_LABEL[status.phase]}
          </span>
          {status.started_at && (
            <span className="text-xs text-slate-500">
              {new Date(status.started_at).toLocaleTimeString()}
              {status.finished_at && ` – ${new Date(status.finished_at).toLocaleTimeString()}`}
            </span>
          )}
        </div>

        {/* Progressbar – nur wenn etwas läuft oder gerade fertig */}
        {(isRunning || restarting || (status.phase === 'done' && status.progress > 0)) && (
          <div className="h-2 w-full rounded-full bg-slate-800 overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-500 ${
                status.phase === 'error'
                  ? 'bg-red-500'
                  : status.phase === 'done'
                  ? 'bg-green-500'
                  : 'bg-cyan-500'
              } ${restarting ? 'animate-pulse' : ''}`}
              style={{ width: `${restarting ? 100 : (status.progress ?? 0)}%` }}
            />
          </div>
        )}
      </div>

      {status.log.length > 0 && (
        <div
          ref={logRef}
          className="mt-3 bg-slate-950 rounded border border-slate-700/60 p-3 h-64 overflow-y-auto font-mono text-xs leading-relaxed"
        >
          {status.log.map((line, i) => (
            <div
              key={i}
              className={
                line.includes('FEHLER') ? 'text-red-400' :
                line.includes('erfolgreich') ? 'text-green-400' :
                'text-slate-300'
              }
            >
              {line}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Settings Navigation ───────────────────────────────────────────────────────

type SectionId = 'users' | 'saml' | 'ml-status' | 'ml-config' | 'rules-sources' | 'rules-list' | 'ssl' | 'syslog' | 'irma' | 'itop' | 'update' | 'thorsten';

interface NavItem { id: SectionId; label: string; icon: ReactNode }
interface NavGroup { label: string; items: NavItem[] }

const ICON_PROPS = { size: 14, strokeWidth: 1.8 } as const;

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Benutzer & Zugang',
    items: [
      { id: 'users', label: 'Benutzerverwaltung', icon: <Users     {...ICON_PROPS} /> },
      { id: 'saml',  label: 'SAML / SSO',         icon: <KeyRound  {...ICON_PROPS} /> },
    ],
  },
  {
    label: 'KI/ML-Engine',
    items: [
      { id: 'ml-status', label: 'Status & Lernphase',     icon: <Activity {...ICON_PROPS} /> },
      { id: 'ml-config', label: 'Filter-Konfiguration',   icon: <Sliders  {...ICON_PROPS} /> },
    ],
  },
  {
    label: 'Regelwerk',
    items: [
      { id: 'rules-sources', label: 'Rule-Quellen',  icon: <Database {...ICON_PROPS} /> },
      { id: 'rules-list',    label: 'Aktive Regeln', icon: <ListTree {...ICON_PROPS} /> },
    ],
  },
  {
    label: 'System',
    items: [
      { id: 'ssl',    label: 'SSL-Zertifikat', icon: <Lock     {...ICON_PROPS} /> },
      { id: 'syslog', label: 'Syslog / SIEM',  icon: <FileText {...ICON_PROPS} /> },
      { id: 'update', label: 'System-Update',  icon: <Upload   {...ICON_PROPS} /> },
    ],
  },
  {
    label: 'Integrationen',
    items: [
      { id: 'irma', label: 'IRMA',      icon: <Plug     {...ICON_PROPS} /> },
      { id: 'itop', label: 'iTop CMDB', icon: <Database {...ICON_PROPS} /> },
    ],
  },
  {
    label: 'Extra',
    items: [
      { id: 'thorsten', label: 'Für Thorsten', icon: <Sparkles {...ICON_PROPS} /> },
    ],
  },
];

export function SettingsPage() {
  const [active, setActive] = useState<SectionId>('users');

  const isThorsten = active === 'thorsten';

  return (
    <div className="flex h-full overflow-hidden">

      {/* ── Submenu (Stil wie Hauptmenü) ─────────────────────────────────── */}
      <nav className="cyjan-settings-nav">
        {NAV_GROUPS.map(group => (
          <div key={group.label} className="cyjan-settings-nav-group">
            <div className="cyjan-settings-nav-grouplabel">{group.label}</div>
            {group.items.map(item => (
              <button
                key={item.id}
                type="button"
                onClick={() => setActive(item.id)}
                className={`cyjan-sidebar-item ${active === item.id ? 'is-active' : ''}`}
              >
                <span className="cyjan-sidebar-icon">{item.icon}</span>
                {item.label}
              </button>
            ))}
          </div>
        ))}
      </nav>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        {isThorsten ? (
          <FuerThorsten />
        ) : (
        <div className="max-w-4xl mx-auto py-6 px-6">
          <div className="card p-5">
            {active === 'users'         && <UserManagement />}
            {active === 'saml'          && <SamlSettings />}
            {active === 'ml-status'     && <MLStatusDisplay />}
            {active === 'ml-config'     && <MLFilterConfig />}
            {active === 'rules-sources' && <RuleSources />}
            {active === 'rules-list'    && <RulesList />}
            {active === 'ssl'           && <SslSettings />}
            {active === 'syslog'        && <SyslogSettings />}
            {active === 'irma'          && <IrmaSettings />}
            {active === 'itop'          && <ItopSettings />}
            {active === 'update'        && <SystemUpdate />}
          </div>
        </div>
        )}
      </div>

    </div>
  );
}
