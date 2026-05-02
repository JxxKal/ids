import { Fragment, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import {
  Activity, Database, FileText, Globe, HardDrive, KeyRound, ListTree, Lock, Network, Plug, RotateCcw, Server, Sliders, Sparkles, Upload, Users,
} from 'lucide-react';
import { SUPPORTED_LANGUAGES, type SupportedLanguage } from '../i18n';
import {
  addRuleSource, applySslAcme, applySslSelfSigned, createUser, deleteRuleSource, deleteUser,
  fetchIrmaConfig, fetchItopConfig, fetchMLConfig, fetchMLStatus, fetchRuleSources,
  fetchRuleUpdateStatus, fetchRules, fetchSamlConfig, fetchSslStatus, fetchSyslogConfig,
  fetchSystemUpdateStatus, fetchUsers, generateApiToken, getInterfaces, getItopSyncStatus, patchRuleSource, setInterfaceRole,
  saveIrmaConfig, saveItopConfig, saveMLConfig, saveSamlConfig, saveSyslogConfig,
  restartStack, startSystemUpdate, testItopConnection, testSyslog, triggerItopSync, triggerMLRetrain,
  triggerRuleUpdate, updateUser, uploadSslCert, uploadSslPfx, setSslHostname, fetchSystemStats,
  importSuricataRules,
  fetchRuleFiles, fetchRuleFile, saveRuleFile, deleteRuleFile,
  fetchLearnedPatterns,
  fetchDbStats, cleanupDb, vacuumDb, setRetentionPolicy, backupDbUrl, restoreDb, fetchMaintenanceAudit,
  fetchDnsResolvers, saveDnsResolvers,
  fetchSigRules, fetchSigRulesOverrides, saveSigRulesOverrides,
  fetchMlStatus, startMlTraining, pauseMlTuning, resumeMlTuning,
  type SigRuleEntry, type SigRuleOverride, type SigRuleParamOverride,
  type MlTuningStatus,
  fetchSuricataOverrides, saveSuricataOverrides,
  type SuricataOverrideEntry,
  fetchBoundaryPriorityMap, saveBoundaryPriorityMap,
  fetchTaps, createTapPairingToken, revokeTap,
  fetchPendingTaps, approvePendingTap, rejectPendingTap, fetchTapAuditLog,
  type PendingTap, type TapAuditEntry,
} from '../api';
import type {
  SslAcmeConfig, SslSelfSignedRequest, SslStatus, SyslogConfig, SystemStats, LearnedPattern,
  DbStatsResponse, MaintenanceAuditEntry,
  RuleFileMeta,
} from '../api';
import type { InterfaceInfo, IrmaConfig, ItopConfig, ItopSyncState, MLConfig, MLStatus, RemoteTap, RemoteTapPairingToken, Rule, RuleSource, SamlConfig, SystemUpdateStatus, UpdateStatus, User } from '../types';
import { ConfirmDialog } from './ConfirmDialog';
import { FuerThorsten } from './FuerThorsten';
import { MlFlowDiagram } from './MlFlowDiagram';

// ── Helpers ───────────────────────────────────────────────────────────────────

function SourceBadge({ source }: { source: string }) {
  const { t } = useTranslation();
  return source === 'saml'
    ? <span className="px-1.5 py-0.5 text-[10px] rounded bg-purple-900/50 text-purple-300 border border-purple-700/40">SAML</span>
    : <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">{t('settings.users.sourceLocal')}</span>;
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
  const { t } = useTranslation();
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
      .catch(() => setError(t('settings.users.loadError')))
      .finally(() => setLoading(false));
  }, [t]);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormErr('');
    // API-User: kein Passwort nötig → zufälliges generieren
    const isApi = form.role === 'api';
    const pw = isApi
      ? crypto.getRandomValues(new Uint8Array(16)).reduce((s, b) => s + b.toString(16).padStart(2, '0'), '')
      : form.password;
    if (!isApi && form.password !== form.password2) { setFormErr(t('settings.users.passwordMismatch')); return; }
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
        const tok = await generateApiToken(u.id);
        setApiToken({ userId: u.id, token: tok.token });
      }
    } catch (err: unknown) {
      setFormErr(err instanceof Error ? err.message : t('settings.users.createError'));
    } finally {
      setSaving(false);
    }
  }

  async function handleGenerateToken(userId: string) {
    try {
      const tok = await generateApiToken(userId);
      setApiToken({ userId, token: tok.token });
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : t('settings.users.tokenError'));
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
        if (editData.password !== editData.password2) { setFormErr(t('settings.users.passwordMismatch')); setSaving(false); return; }
        payload.password = editData.password;
      }
      const u = await updateUser(id, payload);
      setUsers(prev => prev.map(x => x.id === id ? u : x));
      setEditId(null);
      setEditData({});
      setFormErr('');
    } catch (err: unknown) {
      setFormErr(err instanceof Error ? err.message : t('settings.users.saveError'));
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
      alert(err instanceof Error ? err.message : t('settings.users.deleteError'));
    }
  }

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;
  if (error)   return <p className="text-red-400 text-sm">{error}</p>;

  return (
    <div>
      {/* API Token Banner */}
      {apiToken && (
        <div className="mb-4 p-3 rounded border border-indigo-700/50 bg-indigo-950/40 text-xs">
          <div className="flex items-center justify-between mb-1">
            <span className="text-indigo-300 font-semibold">{t('settings.users.tokenGenerated')}</span>
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
              {t('settings.users.copy')}
            </button>
          </div>
          <p className="mt-1 text-slate-500">{t('settings.users.tokenSaveHint')}</p>
        </div>
      )}

      <div className="flex items-center justify-between mb-3">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.users.title')}</h2>
        <button className="btn-primary text-xs" onClick={() => { setShowNew(v => !v); setFormErr(''); }}>
          {showNew ? t('common.cancel') : t('settings.users.newUser')}
        </button>
      </div>

      {/* Neuer-Benutzer-Formular */}
      {showNew && (
        <form onSubmit={handleCreate} className="card p-4 mb-4 grid grid-cols-2 gap-3 text-xs">
          <div className="flex flex-col gap-1">
            <label htmlFor="new-username" className="text-slate-400">{t('settings.users.usernameRequired')}</label>
            <input id="new-username" name="new-username" className="input" required
              value={form.username} onChange={e => setForm(f => ({ ...f, username: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor="new-email" className="text-slate-400">{t('settings.users.email')}</label>
            <input id="new-email" name="new-email" type="email" className="input"
              value={form.email} onChange={e => setForm(f => ({ ...f, email: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor="new-displayname" className="text-slate-400">{t('settings.users.displayName')}</label>
            <input id="new-displayname" name="new-displayname" className="input"
              value={form.display_name} onChange={e => setForm(f => ({ ...f, display_name: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor="new-role" className="text-slate-400">{t('settings.users.role')}</label>
            <select id="new-role" name="new-role" className="input"
              value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value as 'admin' | 'viewer' | 'api' }))}>
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
              <option value="api">{t('settings.users.roleApiServiceAccount')}</option>
            </select>
          </div>
          {form.role !== 'api' && <>
            <div className="flex flex-col gap-1">
              <label htmlFor="new-pw" className="text-slate-400">{t('settings.users.passwordRequired')}</label>
              <input id="new-pw" name="new-pw" type="password" className="input" required minLength={8}
                value={form.password} onChange={e => setForm(f => ({ ...f, password: e.target.value }))} />
            </div>
            <div className="flex flex-col gap-1">
              <label htmlFor="new-pw2" className="text-slate-400">{t('settings.users.passwordRepeatRequired')}</label>
              <input id="new-pw2" name="new-pw2" type="password" className="input" required
                value={form.password2} onChange={e => setForm(f => ({ ...f, password2: e.target.value }))} />
            </div>
          </>}
          {form.role === 'api' && (
            <p className="col-span-2 text-indigo-400/80 text-xs bg-indigo-950/30 rounded px-3 py-2 border border-indigo-800/40">
              {t('settings.users.apiUserHint')}
            </p>
          )}
          {formErr && <p className="col-span-2 text-red-400 text-xs">{formErr}</p>}
          <div className="col-span-2 flex justify-end gap-2">
            <button type="button" className="btn-ghost text-xs" onClick={() => setShowNew(false)}>{t('common.cancel')}</button>
            <button type="submit" className="btn-primary text-xs" disabled={saving}>
              {saving ? t('settings.users.savingShort') : t('settings.users.createUser')}
            </button>
          </div>
        </form>
      )}

      {/* Benutzertabelle */}
      <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead className="cyjan-table-head">
          <tr className="text-left">
            <th>{t('settings.users.colUser')}</th>
            <th>{t('settings.users.email')}</th>
            <th>{t('settings.users.role')}</th>
            <th>{t('settings.users.colSource')}</th>
            <th>{t('settings.users.colLastLogin')}</th>
            <th>{t('settings.users.colActive')}</th>
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
                        <input className="input w-full" placeholder={t('settings.users.newPasswordPlaceholder')} type="password"
                          value={editData.password ?? ''}
                          onChange={e => setEditData(d => ({ ...d, password: e.target.value }))} />
                        <input className="input w-full" placeholder={t('settings.users.repeatPlaceholder')} type="password"
                          value={editData.password2 ?? ''}
                          onChange={e => setEditData(d => ({ ...d, password2: e.target.value }))} />
                      </div>
                    )}
                  </td>
                  <td className="py-2 pr-3">
                    <input className="input w-full" placeholder={t('settings.users.email')} type="email"
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
                      <button className="btn-ghost text-xs" onClick={() => { setEditId(null); setEditData({}); setFormErr(''); }}>{t('common.cancel')}</button>
                      <button className="btn-primary text-xs" disabled={saving} onClick={() => handleUpdate(u.id)}>
                        {saving ? '…' : t('common.save')}
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
                      title={u.active ? t('settings.users.activeToggleOn') : t('settings.users.activeToggleOff')}
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
                          title={t('settings.users.tokenButtonTitle')}
                        >
                          Token
                        </button>
                      )}
                      <button className="btn-ghost text-xs"
                        onClick={() => { setEditId(u.id); setEditData({}); setFormErr(''); }}>
                        {t('common.edit')}
                      </button>
                      <button className="text-xs text-red-500 hover:text-red-400 px-2 py-1 rounded hover:bg-red-950/30 transition-colors"
                        onClick={() => setConfirmUser(u)}>
                        {t('common.delete')}
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
          message={t('settings.users.deleteConfirm', { username: confirmUser.username })}
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
  const { t } = useTranslation();
  const [done, setDone] = useState(false);
  return (
    <button type="button"
      className="text-[10px] px-1.5 py-0.5 rounded border border-slate-700 text-slate-500 hover:text-slate-300 transition-colors"
      onClick={() => { navigator.clipboard.writeText(value); setDone(true); setTimeout(() => setDone(false), 2000); }}>
      {done ? t('settings.users.copied') : t('settings.users.copy')}
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
  const { t } = useTranslation();
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
      flash('ok', t('settings.saml.importedOk'));
    } catch (e: unknown) {
      setXmlError(e instanceof Error ? e.message : t('settings.saml.parseError'));
    }
  }

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true);
    try { await saveSamlConfig(cfg); flash('ok', t('settings.saml.savedOk')); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : t('common.errorGeneric')); }
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

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;

  return (
    <form onSubmit={handleSave} className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">SAML / SSO</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-purple-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-purple-300 font-medium' : 'text-slate-500'}>
            {t('settings.saml.enabled')}
          </span>
        </label>
      </div>

      {/* ── IdP-Metadaten XML importieren ────────────────────────────────────── */}
      <div className="rounded border border-slate-700/60 bg-slate-900/50 p-3 space-y-2">
        <p className="text-xs font-medium text-slate-300">{t('settings.saml.importIdpMetadata')}</p>
        <p className="text-[11px] text-slate-500">
          {t('settings.saml.importIdpHint')}
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
          {t('settings.saml.parseXml')}
        </button>
      </div>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>

        {/* ── IdP-Felder ───────────────────────────────────────────────────── */}
        <div>
          <p className="text-xs text-slate-400 font-medium mb-2">{t('settings.saml.idpHeading')}</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            {inp(t('settings.saml.idpEntityId'),   'idp_entity_id', 'http://10.180.18.66/saml-idp/…')}
            {inp(t('settings.saml.idpSsoUrl'), 'idp_sso_url', 'http://10.180.18.66/…/login/')}
            {inp(t('settings.saml.idpSloUrl'),    'idp_slo_url',  'http://10.180.18.66/…/logout/')}
          </div>
          <div className="mt-3 flex flex-col gap-1">
            <div className="flex items-center justify-between">
              <label className="text-xs text-slate-400">{t('settings.saml.idpCert')}</label>
              <button type="button" className="text-[10px] text-slate-500 hover:text-slate-300"
                onClick={() => setShowCert(v => !v)}>
                {showCert ? t('settings.saml.hide') : t('settings.saml.show')}
              </button>
            </div>
            {showCert
              ? <textarea className="input text-[11px] font-mono w-full h-20 resize-none"
                  value={cfg.idp_x509_cert}
                  onChange={e => setCfg(c => ({ ...c, idp_x509_cert: e.target.value }))} />
              : <p className="text-[11px] text-slate-600 font-mono truncate">
                  {cfg.idp_x509_cert ? `${cfg.idp_x509_cert.slice(0, 60)}…` : t('settings.saml.notSet')}
                </p>
            }
          </div>
        </div>

        {/* ── SP-Felder ────────────────────────────────────────────────────── */}
        <div>
          <p className="text-xs text-slate-400 font-medium mb-2">{t('settings.saml.spHeading')}</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
            <div className="flex flex-col gap-1">
              <label className="text-xs text-slate-400">{t('settings.saml.spEntityId')}</label>
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
            {inp(t('settings.saml.acsUrl'),  'acs_url',  'http://192.168.1.230/api/auth/saml/acs')}
            {inp(t('settings.saml.slsUrl'), 'slo_url',  'http://192.168.1.230/api/auth/saml/sls')}
          </div>

          {/* SP-Info-Box mit Copy-Buttons */}
          {cfg.sp_entity_id && (
            <div className="mt-3 rounded border border-slate-700/40 bg-slate-900/60 divide-y divide-slate-800 text-[11px] font-mono">
              {[
                [t('settings.saml.spEntityId'),    cfg.sp_entity_id],
                [t('settings.saml.acsUrl'), cfg.acs_url],
                [t('settings.saml.slsUrl'), cfg.slo_url],
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
              {t('settings.saml.downloadSpMetadata')}
            </a>
          )}
        </div>

        {/* ── Attribut-Mapping ─────────────────────────────────────────────── */}
        <div>
          <p className="text-xs text-slate-500 mb-2">
            {t('settings.saml.attrMappingHint')}
          </p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {inp(t('settings.saml.attrUsername'),  'attribute_username',     'uid')}
            {inp(t('settings.saml.attrEmail'),        'attribute_email',        'email')}
            {inp(t('settings.saml.attrDisplayName'),   'attribute_display_name', 'displayName')}
          </div>
        </div>

        <div className="flex flex-col gap-1 max-w-xs">
          <label className="text-xs text-slate-400">{t('settings.saml.defaultRole')}</label>
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
          {saving ? t('settings.users.savingShort') : t('settings.saml.saveButton')}
        </button>
      </div>
    </form>
  );
}

// ── MLStatusSection ───────────────────────────────────────────────────────────

function fmtDuration(secs: number, t: (k: string, v?: Record<string, unknown>) => string): string {
  if (secs < 60)    return t('settings.mlStatus.durSec', { n: secs });
  if (secs < 3600)  return t('settings.mlStatus.durMin', { n: Math.round(secs / 60) });
  if (secs < 86400) return t('settings.mlStatus.durHour', { n: Math.round(secs / 3600) });
  return t('settings.mlStatus.durDay', { n: Math.round(secs / 86400) });
}

function fmtTs(ts: number): string {
  return new Date(ts * 1000).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

function PhaseIndicator({ phase }: { phase: MLStatus['phase'] }) {
  const { t } = useTranslation();
  const cfg = {
    passthrough: { dot: 'bg-slate-500',  text: 'text-slate-400',  label: t('settings.mlStatus.phasePassthrough') },
    learning:    { dot: 'bg-yellow-500 animate-pulse', text: 'text-yellow-400', label: t('settings.mlStatus.phaseLearning') },
    active:      { dot: 'bg-green-500',  text: 'text-green-400',  label: t('settings.mlStatus.phaseActive') },
  }[phase];
  return (
    <span className={`flex items-center gap-1.5 font-medium ${cfg.text}`}>
      <span className={`w-2 h-2 rounded-full ${cfg.dot}`} />
      {cfg.label}
    </span>
  );
}

type TFn = (k: string, v?: Record<string, unknown>) => string;

function buildParamDocs(t: TFn) {
  return [
    {
      key: 'alert_threshold' as const,
      label: t('settings.mlConfig.params.alertThreshold.label'),
      min: 0.50, max: 0.95, step: 0.01,
      fmt: (v: number) => v.toFixed(2),
      hint: t('settings.mlConfig.params.alertThreshold.hint'),
      presets: [
        { label: t('settings.mlConfig.params.alertThreshold.presets.sensitive.label'),     value: 0.60, desc: t('settings.mlConfig.params.alertThreshold.presets.sensitive.desc') },
        { label: t('settings.mlConfig.params.alertThreshold.presets.balanced.label'),   value: 0.65, desc: t('settings.mlConfig.params.alertThreshold.presets.balanced.desc') },
        { label: t('settings.mlConfig.params.alertThreshold.presets.precise.label'),     value: 0.75, desc: t('settings.mlConfig.params.alertThreshold.presets.precise.desc') },
        { label: t('settings.mlConfig.params.alertThreshold.presets.conservative.label'), value: 0.85, desc: t('settings.mlConfig.params.alertThreshold.presets.conservative.desc') },
      ],
    },
    {
      key: 'contamination' as const,
      label: 'Contamination',
      min: 0.001, max: 0.2, step: 0.001,
      fmt: (v: number) => `${(v * 100).toFixed(1)} %`,
      hint: t('settings.mlConfig.params.contamination.hint'),
      presets: [
        { label: 'OT/SCADA',  value: 0.005, desc: t('settings.mlConfig.params.contamination.presets.otScada.desc') },
        { label: t('settings.mlConfig.params.contamination.presets.standard.label'),  value: 0.010, desc: t('settings.mlConfig.params.contamination.presets.standard.desc') },
        { label: t('settings.mlConfig.params.contamination.presets.mixed.label'), value: 0.030, desc: t('settings.mlConfig.params.contamination.presets.mixed.desc') },
        { label: t('settings.mlConfig.params.contamination.presets.largeIt.label'),  value: 0.050, desc: t('settings.mlConfig.params.contamination.presets.largeIt.desc') },
      ],
    },
    {
      key: 'bootstrap_min_samples' as const,
      label: t('settings.mlConfig.params.bootstrap.label'),
      min: 100, max: 50000, step: 100,
      fmt: (v: number) => v.toLocaleString(),
      hint: t('settings.mlConfig.params.bootstrap.hint'),
      presets: [
        { label: t('settings.mlConfig.params.bootstrap.presets.small.label'),   value: 500,   desc: t('settings.mlConfig.params.bootstrap.presets.small.desc') },
        { label: t('settings.mlConfig.params.bootstrap.presets.medium.label'),  value: 2000,  desc: t('settings.mlConfig.params.bootstrap.presets.medium.desc') },
        { label: t('settings.mlConfig.params.bootstrap.presets.large.label'),    value: 10000, desc: t('settings.mlConfig.params.bootstrap.presets.large.desc') },
        { label: t('settings.mlConfig.params.bootstrap.presets.veryLarge.label'), value: 50000, desc: t('settings.mlConfig.params.bootstrap.presets.veryLarge.desc') },
      ],
    },
    {
      key: 'partial_fit_interval' as const,
      label: t('settings.mlConfig.params.partialFit.label'),
      min: 50, max: 5000, step: 50,
      fmt: (v: number) => t('settings.mlConfig.params.partialFit.fmt', { n: v.toLocaleString() }),
      hint: t('settings.mlConfig.params.partialFit.hint'),
      presets: [
        { label: t('settings.mlConfig.params.partialFit.presets.reactive.label'),   value: 100,  desc: t('settings.mlConfig.params.partialFit.presets.reactive.desc') },
        { label: t('settings.mlConfig.params.partialFit.presets.standard.label'),  value: 200,  desc: '' },
        { label: t('settings.mlConfig.params.partialFit.presets.stable.label'),    value: 1000, desc: t('settings.mlConfig.params.partialFit.presets.stable.desc') },
      ],
    },
  ];
}

// ── ML-Übersicht: Single-Pane-of-Glass für alle drei ML-Komponenten ─────────
//
// Zeigt Status + Quick-Action-Links für IsolationForest, rule-tuner und
// Suppression nebeneinander. Damit der User nicht durch drei Seiten klicken
// muss, um zu sehen ob alles im erwarteten Zustand ist. Das Pipeline-
// Diagramm darunter spiegelt docs/ML_ENGINE.md Section 0.
function MLOverviewSettings({ onNavigate }: { onNavigate: (id: SectionId) => void }) {
  const { t } = useTranslation();
  const [mlStatus, setMlStatus] = useState<MLStatus | null>(null);
  const [tunerStatus, setTunerStatus] = useState<MlTuningStatus | null>(null);
  const [learnedCount, setLearnedCount] = useState<{ manual: number; ml: number } | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    const reload = () => {
      Promise.all([
        fetchMLStatus().catch(() => null),
        fetchMlStatus().catch(() => null),
        fetchLearnedPatterns().catch(() => null),
      ]).then(([m, t, lp]) => {
        if (cancelled) return;
        setMlStatus(m);
        setTunerStatus(t);
        if (lp) {
          setLearnedCount({
            manual: lp.patterns.filter(p => p.source === 'manual').length,
            ml:     lp.patterns.filter(p => p.source === 'learned').length,
          });
        }
        setError('');
      }).catch(e => setError(String(e)));
    };
    reload();
    const id = window.setInterval(reload, 15_000);
    return () => { cancelled = true; window.clearInterval(id); };
  }, []);

  // Phase-Farben für IsolationForest
  const ifColor = !mlStatus ? 'text-slate-500'
    : mlStatus.phase === 'active'      ? 'text-emerald-300 border-emerald-700/40 bg-emerald-900/20'
    : mlStatus.phase === 'learning'    ? 'text-cyan-300 border-cyan-700/40 bg-cyan-900/20'
    :                                    'text-slate-400 border-slate-700/40 bg-slate-800/40';

  // Tuner-Farben (gleiche Skala wie in der Card im Regel-Anpassungs-Tab)
  const tnState = tunerStatus?.state.state ?? 'idle';
  const tnColor = tnState === 'training' ? 'text-cyan-300 border-cyan-700/40 bg-cyan-900/20'
    : tnState === 'tuning'  ? 'text-emerald-300 border-emerald-700/40 bg-emerald-900/20'
    : tnState === 'paused'  ? 'text-amber-300 border-amber-700/40 bg-amber-900/20'
    :                         'text-slate-400 border-slate-700/40 bg-slate-800/40';

  let trainingRest = '';
  if (tnState === 'training' && tunerStatus?.state.training_until) {
    const ms = new Date(tunerStatus.state.training_until).getTime() - Date.now();
    if (ms > 0) {
      const h = Math.floor(ms / 3_600_000);
      const m = Math.floor((ms % 3_600_000) / 60_000);
      trainingRest = h > 0 ? `${h}h ${m}m` : `${m}m`;
    } else {
      trainingRest = t('settings.mlOverview.tuner.remainingNow');
    }
  }

  // Pipeline-Diagramm: sprachgesteuerte SVG-Komponente (MlFlowDiagram).
  // Ersetzt das frühere ml-flow.png — Texte kommen aus i18n, Diagramm
  // skaliert mit dem Container. Fallback-Liste (5-Pfad-Aufzählung) bleibt
  // darunter sichtbar als Screenreader-Beschreibung der Pfad-Semantik.
  const flowItems: { idx: string; pathClass: string; text: string }[] = [
    { idx: '1', pathClass: 'text-cyan-300',    text: 'source=ml (IsolationForest) → Suppression skip · ML-Retrain via feedback-Topic' },
    { idx: '2', pathClass: 'text-emerald-300', text: 'signature heuristic + metric: → Suppression skip · rule-tuner verwaltet Threshold · Auto-FP wenn Pattern floodet' },
    { idx: '3', pathClass: 'text-violet-300',  text: 'signature heuristic, no metric: → Suppression aktiv · pattern-only rules (SCAN_005, ANOMALY_*)' },
    { idx: '4', pathClass: 'text-violet-300',  text: 'signature SURICATA:* → Suppression aktiv · _suricata_overrides.json statisch' },
    { idx: '5', pathClass: 'text-slate-400',   text: 'source=external (IRMA/ASSET::*) → Suppression skip · externe Aussagen, kein Detection-Noise' },
  ];

  return (
    <div className="space-y-4">
      <div>
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.mlOverview.title')}</h2>
        <p className="text-xs text-slate-500 mt-1">{t('settings.mlOverview.intro')}</p>
      </div>
      {error && <p className="text-xs text-red-400">{error}</p>}

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
        {/* ── Card 1: IsolationForest ────────────────────────────────────── */}
        <div className={`rounded-lg border p-3 space-y-2 ${ifColor}`}>
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider">{t('settings.mlOverview.anomaly.title')}</h3>
            <span className="text-[10px] font-mono opacity-70">{t('settings.mlOverview.anomaly.subtitle')}</span>
          </div>
          {mlStatus ? (
            <>
              <div className="text-lg font-medium">{mlStatus.phase_label || mlStatus.phase}</div>
              <div className="text-[10px] space-y-0.5 text-slate-400">
                <div>{t('settings.mlOverview.anomaly.bootstrap')} <span className="text-slate-200 tabular-nums">{mlStatus.bootstrap.current_flows.toLocaleString()}</span> / {mlStatus.bootstrap.required.toLocaleString()} ({mlStatus.bootstrap.progress_pct}%)</div>
                <div>{t('settings.mlOverview.anomaly.alerts24h')} <span className="text-slate-200 tabular-nums">{mlStatus.stats_24h.ml_alerts}</span> · {t('settings.mlOverview.anomaly.filterRate')} {mlStatus.stats_24h.filter_rate_pct}%</div>
                <div>{t('settings.mlOverview.anomaly.threshold')} <span className="text-slate-200 tabular-nums">{mlStatus.stats_24h.alert_threshold.toFixed(2)}</span></div>
              </div>
              <p className="text-[10px] leading-relaxed text-slate-400">
                <Trans i18nKey="settings.mlOverview.anomaly.description"
                  components={{ strong: <strong />, code: <code className="text-cyan-300" /> }} />
              </p>
            </>
          ) : (
            <p className="text-xs text-slate-500">{t('settings.mlOverview.loading')}</p>
          )}
          <button
            onClick={() => onNavigate('ml-status')}
            className="w-full text-[11px] px-2 py-1 rounded border border-slate-700 hover:border-slate-500 hover:text-slate-200 text-slate-400 transition-colors"
          >
            {t('settings.mlOverview.configure')}
          </button>
        </div>

        {/* ── Card 2: rule-tuner ─────────────────────────────────────────── */}
        <div className={`rounded-lg border p-3 space-y-2 ${tnColor}`}>
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider">{t('settings.mlOverview.tuner.title')}</h3>
            <span className="text-[10px] font-mono opacity-70">{t('settings.mlOverview.tuner.subtitle')}</span>
          </div>
          {tunerStatus ? (
            <>
              <div className="text-lg font-medium">
                {tnState}
                {trainingRest && <span className="ml-2 text-xs opacity-70">{t('settings.mlOverview.tuner.remaining', { value: trainingRest })}</span>}
              </div>
              <div className="text-[10px] space-y-0.5 text-slate-400">
                <div>{t('settings.mlOverview.tuner.samplesTotal')} <span className="text-slate-200 tabular-nums">{tunerStatus.total_samples.toLocaleString()}</span></div>
                <div>{t('settings.mlOverview.tuner.lastWrite')} <span className="text-slate-200">{tunerStatus.state.last_tuning_at ? new Date(tunerStatus.state.last_tuning_at).toLocaleString() : '–'}</span></div>
                <div>{t('settings.mlOverview.tuner.quantileBlacklist', {
                  quantile: (tunerStatus.config.quantile * 100).toFixed(1).replace(/\.0$/, ''),
                  count:    tunerStatus.config.blacklist.length,
                })}</div>
              </div>
              <p className="text-[10px] leading-relaxed text-slate-400">
                <Trans i18nKey="settings.mlOverview.tuner.description" components={{ strong: <strong /> }} />
              </p>
            </>
          ) : (
            <p className="text-xs text-slate-500">{t('settings.mlOverview.loading')}</p>
          )}
          <button
            onClick={() => onNavigate('rules-overrides')}
            className="w-full text-[11px] px-2 py-1 rounded border border-slate-700 hover:border-slate-500 hover:text-slate-200 text-slate-400 transition-colors"
          >
            {t('settings.mlOverview.configureInRules')}
          </button>
        </div>

        {/* ── Card 3: Suppression ────────────────────────────────────────── */}
        <div className="rounded-lg border border-violet-700/40 bg-violet-900/20 text-violet-300 p-3 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold uppercase tracking-wider">{t('settings.mlOverview.suppression.title')}</h3>
            <span className="text-[10px] font-mono opacity-70">{t('settings.mlOverview.suppression.subtitle')}</span>
          </div>
          {learnedCount ? (
            <>
              <div className="text-lg font-medium">{t('settings.mlOverview.suppression.patternsTotal', { count: learnedCount.manual + learnedCount.ml })}</div>
              <div className="text-[10px] space-y-0.5 text-slate-400">
                <div>{t('settings.mlOverview.suppression.manualLayer')} <span className="text-slate-200 tabular-nums">{learnedCount.manual}</span></div>
                <div>{t('settings.mlOverview.suppression.mlLayer')} <span className="text-slate-200 tabular-nums">{learnedCount.ml}</span></div>
              </div>
              <p className="text-[10px] leading-relaxed text-slate-400">
                <Trans i18nKey="settings.mlOverview.suppression.description"
                  components={{ strong: <strong />, code: <code className="text-amber-300" /> }} />
              </p>
            </>
          ) : (
            <p className="text-xs text-slate-500">{t('settings.mlOverview.loading')}</p>
          )}
          <button
            onClick={() => onNavigate('ml-learned')}
            className="w-full text-[11px] px-2 py-1 rounded border border-slate-700 hover:border-slate-500 hover:text-slate-200 text-slate-400 transition-colors"
          >
            {t('settings.mlOverview.viewPatterns')}
          </button>
        </div>
      </div>

      {/* ── Pipeline-Diagramm ─────────────────────────────────────────────── */}
      <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-4 space-y-3">
        <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider">
          {t('settings.mlOverview.diagram.title')}
        </h3>
        <MlFlowDiagram />
        <ul className="text-[10px] text-slate-400 space-y-1 leading-relaxed pl-1">
          {flowItems.map(it => (
            <li key={it.idx} className="flex gap-2">
              <span className={`font-mono shrink-0 ${it.pathClass}`}>{it.idx}.</span>
              <span>{it.text}</span>
            </li>
          ))}
        </ul>
        <p className="text-[10px] text-slate-500">
          <Trans
            i18nKey="settings.mlOverview.diagram.footer"
            components={{
              a: (
                <a
                  href="https://github.com/JxxKal/ids/blob/main/docs/ML_ENGINE.md"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-cyan-300 underline hover:text-cyan-200 font-mono"
                />
              ),
            }}
          />
        </p>
      </div>
    </div>
  );
}

function MLStatusDisplay() {
  const { t } = useTranslation();
  const [status,  setStatus]  = useState<MLStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(() => {
    fetchMLStatus()
      .then(setStatus)
      .catch(() => setError(t('settings.mlStatus.loadError')))
      .finally(() => setLoading(false));
  }, [t]);

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;
  if (error)   return <p className="text-red-400 text-sm">{error}</p>;
  if (!status) return null;

  const { phase, phase_label, model, bootstrap, stats_24h, top_anomaly_features } = status;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.mlStatus.title')}</h2>
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
          <p>{t('settings.mlStatus.bannerPassthrough')}</p>
        )}
        {phase === 'learning' && (
          <p>{t('settings.mlStatus.bannerLearning')}</p>
        )}
        {phase === 'active' && (
          <p>{t('settings.mlStatus.bannerActive')}</p>
        )}
      </div>

      {/* ── Lernfortschritt (nur wenn noch kein Modell) ──────────────── */}
      {phase === 'passthrough' && (
        <div>
          <div className="flex justify-between text-xs text-slate-400 mb-1.5">
            <span>{t('settings.mlStatus.phasePassthrough')}</span>
            <span>{t('settings.mlStatus.flowsProgress', { current: bootstrap.current_flows.toLocaleString(), required: bootstrap.required.toLocaleString() })}</span>
          </div>
          <div className="h-2 bg-slate-800 rounded-full overflow-hidden">
            <div
              className="h-full bg-cyan-500 rounded-full transition-all"
              style={{ width: `${bootstrap.progress_pct}%` }}
            />
          </div>
          <div className="flex justify-between text-[10px] text-slate-600 mt-1">
            <span>{t('settings.mlStatus.percentComplete', { pct: bootstrap.progress_pct })}</span>
            {bootstrap.estimated_remaining_s != null && (
              <span>{t('settings.mlStatus.remaining', { duration: fmtDuration(bootstrap.estimated_remaining_s, t) })}</span>
            )}
            {bootstrap.estimated_remaining_s == null && (
              <span>{t('settings.mlStatus.estimateUnavailable')}</span>
            )}
          </div>
        </div>
      )}

      {/* ── Modell-Details ───────────────────────────────────────────── */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
        {[
          { label: t('settings.mlStatus.trainingSamples'),  value: model.n_samples.toLocaleString() },
          { label: t('settings.mlStatus.attackSamples'),     value: model.n_attack > 0 ? model.n_attack.toLocaleString() : '—' },
          { label: 'Contamination',      value: `${(model.contamination * 100).toFixed(1)} %` },
          { label: t('settings.mlStatus.lastTraining'),   value: model.trained_at ? fmtTs(model.trained_at) : '—' },
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
          <p className="text-xs font-medium text-slate-400 mb-2">{t('settings.mlStatus.last24h')}</p>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
            {[
              { label: t('settings.mlStatus.flowsAnalyzed'),  value: stats_24h.flows_total.toLocaleString() },
              { label: t('settings.mlStatus.mlAlerts'),          value: stats_24h.ml_alerts.toLocaleString() },
              {
                label: t('settings.mlStatus.filterRate'),
                value: stats_24h.flows_total > 0
                  ? `${stats_24h.filter_rate_pct.toFixed(3)} %`
                  : '—',
              },
              { label: t('settings.mlStatus.scoreThreshold'),  value: stats_24h.alert_threshold.toFixed(2) },
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
            {t('settings.mlStatus.featureDeviationsTitle')} <span className="font-normal text-slate-600">{t('settings.mlStatus.featureDeviationsSubtitle')}</span>
          </p>
          <div className="space-y-2">
            {top_anomaly_features.map(f => {
              const isHigh = f.deviation_pct > 0;
              const absDev = Math.abs(f.deviation_pct);
              const barW   = Math.min(100, absDev / 5);  // 500% = volle Breite
              // Lesbare Anzeige: bei kleinen Abweichungen (< 100 %) als
              // Prozent, sonst als Faktor (z.B. 9105 % → 91× höher). Roh-
              // 5-stellige Prozente sind kognitiv schwer einzuordnen.
              let devText: string;
              if (absDev < 100) {
                devText = `${absDev.toFixed(0)} %`;
              } else {
                const factor = isHigh
                  ? 1 + absDev / 100
                  : 1 / (1 - absDev / 100);  // -90 % → 1/0.1 = 10×
                devText = factor >= 10 ? `${factor.toFixed(0)}×` : `${factor.toFixed(1)}×`;
              }
              return (
                <div key={f.name} className="text-xs"
                     title={t('settings.mlStatus.deviationTooltip', { pct: f.deviation_pct })}>
                  <div className="flex items-center justify-between mb-0.5">
                    <span className="text-slate-300">{f.label}</span>
                    <span className={`font-mono ${isHigh ? 'text-orange-400' : 'text-blue-400'}`}>
                      {isHigh ? '↑' : '↓'} {devText}
                    </span>
                  </div>
                  <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                    <div
                      className={`h-full rounded-full ${isHigh ? 'bg-orange-500' : 'bg-cyan-500'}`}
                      style={{ width: `${barW}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[10px] text-slate-600 mt-0.5">
                    <span>{t('settings.mlStatus.normalLabel')}: {f.avg_normal.toFixed(3)} {f.unit}</span>
                    <span>{t('settings.mlStatus.inAlerts')}: {f.avg_in_alerts.toFixed(3)} {f.unit}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {phase === 'active' && stats_24h.ml_alerts === 0 && (
        <p className="text-xs text-slate-600 italic">
          {t('settings.mlStatus.noAlerts24h')}
        </p>
      )}
    </div>
  );
}

// ══════════════════════════════════════════════════════════════════════════════
// DatabaseMaintenance – Übersicht / Cleanup / Vacuum / Retention / Backup / Audit
// ══════════════════════════════════════════════════════════════════════════════

function fmtSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function fmtDate(iso: string | null): string {
  if (!iso) return '–';
  return new Date(iso).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });
}

function ActionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-4 space-y-3">
      <h3 className="text-sm font-semibold text-slate-200">{title}</h3>
      {children}
    </div>
  );
}

function PasswordInput({ value, onChange, placeholder }: {
  value: string; onChange: (v: string) => void; placeholder?: string;
}) {
  const { t } = useTranslation();
  return (
    <input
      type="password"
      value={value}
      onChange={e => onChange(e.target.value)}
      placeholder={placeholder ?? t('settings.dbMaint.adminPasswordPlaceholder')}
      autoComplete="off"
      className="cyjan-input text-xs w-full"
    />
  );
}

function DatabaseMaintenance() {
  const { t } = useTranslation();
  const [stats,       setStats]       = useState<DbStatsResponse | null>(null);
  const [loading,     setLoading]     = useState(true);
  const [error,       setError]       = useState('');
  const [audit,       setAudit]       = useState<MaintenanceAuditEntry[] | null>(null);

  const reload = () => {
    fetchDbStats().then(setStats).catch(e => setError(String(e.message || e))).finally(() => setLoading(false));
    fetchMaintenanceAudit(30).then(setAudit).catch(() => {});
  };

  useEffect(() => {
    reload();
    const ti = setInterval(reload, 30_000);
    return () => clearInterval(ti);
  }, []);

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;
  if (error)   return <p className="text-red-400 text-sm">{t('common.error', { message: error })}</p>;
  if (!stats)  return null;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.dbMaint.title')}</h2>
        <p className="text-xs text-slate-500 mt-1">
          {t('settings.dbMaint.intro')}
        </p>
      </div>

      {/* ── 1. Übersicht ─────────────────────────────────────────────────── */}
      <ActionCard title={t('settings.dbMaint.dbSizeTotal', { size: fmtSize(stats.db_size_bytes) })}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead className="text-[10px] text-slate-500 uppercase">
              <tr className="text-left">
                <th className="px-2 py-1.5">{t('settings.dbMaint.colTable')}</th>
                <th className="px-2 py-1.5 text-right">{t('settings.dbMaint.colRows')}</th>
                <th className="px-2 py-1.5 text-right">{t('settings.dbMaint.colSize')}</th>
                <th className="px-2 py-1.5">{t('settings.dbMaint.colOldest')}</th>
                <th className="px-2 py-1.5">{t('settings.dbMaint.colNewest')}</th>
              </tr>
            </thead>
            <tbody>
              {stats.tables.map(tbl => (
                <tr key={tbl.name} className="border-t border-slate-800/50">
                  <td className="px-2 py-1.5 font-mono text-slate-300">{tbl.name}</td>
                  <td className="px-2 py-1.5 text-right tabular-nums text-slate-300">{tbl.rows.toLocaleString('de-DE')}</td>
                  <td className="px-2 py-1.5 text-right tabular-nums text-slate-500">{fmtSize(tbl.size_bytes)}</td>
                  <td className="px-2 py-1.5 text-slate-600 font-mono">{fmtDate(tbl.oldest)}</td>
                  <td className="px-2 py-1.5 text-slate-600 font-mono">{fmtDate(tbl.newest)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {stats.hypertables.length > 0 && (
          <p className="text-[11px] text-slate-600 font-mono">
            {t('settings.dbMaint.hypertablesLabel')}: {stats.hypertables.map(h => t('settings.dbMaint.hypertableEntry', { name: h.name, chunks: h.chunks, size: fmtSize(h.size_bytes) })).join(' · ')}
          </p>
        )}
      </ActionCard>

      {/* ── 2. Cleanup ───────────────────────────────────────────────────── */}
      <CleanupSection onDone={reload} />

      {/* ── 3. Vacuum ────────────────────────────────────────────────────── */}
      <VacuumSection onDone={reload} />

      {/* ── 4. Retention ─────────────────────────────────────────────────── */}
      <RetentionSection stats={stats} onDone={reload} />

      {/* ── 5. Backup / Restore ──────────────────────────────────────────── */}
      <BackupRestoreSection onDone={reload} />

      {/* ── 6. Audit-Log ─────────────────────────────────────────────────── */}
      <ActionCard title={t('settings.dbMaint.auditTitle')}>
        {!audit || audit.length === 0 ? (
          <p className="text-slate-600 text-xs">{t('settings.dbMaint.noAudit')}</p>
        ) : (
          <div className="overflow-x-auto max-h-64 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="text-[10px] text-slate-500 uppercase sticky top-0 bg-slate-900/90">
                <tr className="text-left">
                  <th className="px-2 py-1.5">{t('settings.dbMaint.colTime')}</th>
                  <th className="px-2 py-1.5">User</th>
                  <th className="px-2 py-1.5">{t('settings.dbMaint.colAction')}</th>
                  <th className="px-2 py-1.5">{t('settings.dbMaint.colStatus')}</th>
                  <th className="px-2 py-1.5 text-right">{t('settings.dbMaint.colDuration')}</th>
                </tr>
              </thead>
              <tbody>
                {audit.map(a => (
                  <tr key={a.id} className="border-t border-slate-800/50">
                    <td className="px-2 py-1.5 font-mono text-slate-500">{fmtDate(a.ts)}</td>
                    <td className="px-2 py-1.5 text-slate-300">{a.username}</td>
                    <td className="px-2 py-1.5 font-mono text-cyan-300" title={JSON.stringify(a.params)}>{a.action}</td>
                    <td className="px-2 py-1.5">
                      {a.success ? (
                        <span className="text-green-400">✓</span>
                      ) : (
                        <span className="text-red-400" title={a.error_msg || ''}>✗ {a.error_msg?.slice(0, 60)}</span>
                      )}
                    </td>
                    <td className="px-2 py-1.5 text-right tabular-nums text-slate-500">{a.duration_ms} ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </ActionCard>
    </div>
  );
}

// ── Cleanup-Sektion ───────────────────────────────────────────────────────────

function CleanupSection({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [target,   setTarget]   = useState<'alerts' | 'flows' | 'training_samples' | 'test_runs' | 'all'>('alerts');
  const [days,     setDays]     = useState('30');
  const [onlyTest, setOnlyTest] = useState(false);
  const [password, setPassword] = useState('');
  const [busy,     setBusy]     = useState(false);
  const [msg,      setMsg]      = useState('');
  const [msgType,  setMsgType]  = useState<'ok' | 'err'>('ok');

  const needsConfirm = target === 'all';
  const [confirmText, setConfirmText] = useState('');

  async function run() {
    setBusy(true); setMsg('');
    try {
      const body: Parameters<typeof cleanupDb>[0] = { password, target };
      if (days && target !== 'all') body.older_than_days = parseInt(days, 10);
      if (onlyTest && target === 'alerts') body.only_test = true;
      const r = await cleanupDb(body);
      setMsgType('ok');
      setMsg(t('settings.dbMaint.cleanupResult', { rows: r.deleted.toLocaleString('de-DE'), ms: r.duration_ms }));
      setPassword(''); setConfirmText('');
      onDone();
    } catch (e) {
      setMsgType('err');
      setMsg(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  const canRun = password.length > 0 && !busy && (!needsConfirm || confirmText === 'DELETE CYJAN');

  return (
    <ActionCard title={t('settings.dbMaint.cleanupTitle')}>
      <p className="text-xs text-slate-500">
        {t('settings.dbMaint.cleanupHint')}
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <label className="text-[10px] text-slate-500 uppercase">{t('settings.dbMaint.target')}</label>
          <select value={target} onChange={e => setTarget(e.target.value as typeof target)}
                  className="cyjan-input text-xs block mt-1">
            <option value="alerts">Alerts</option>
            <option value="flows">Flows</option>
            <option value="training_samples">{t('settings.dbMaint.targetTraining')}</option>
            <option value="test_runs">{t('settings.dbMaint.targetTestRuns')}</option>
            <option value="all">{t('settings.dbMaint.targetAll')}</option>
          </select>
        </div>
        {target !== 'all' && (
          <div>
            <label className="text-[10px] text-slate-500 uppercase">{t('settings.dbMaint.olderThanDays')}</label>
            <input type="number" value={days} onChange={e => setDays(e.target.value)}
                   min="0" max="36500"
                   placeholder={t('settings.dbMaint.olderThanPlaceholder')}
                   className="cyjan-input text-xs block mt-1 w-28" />
          </div>
        )}
        {target === 'alerts' && (
          <label className="flex items-center gap-1.5 text-xs text-slate-400 pb-1.5">
            <input type="checkbox" checked={onlyTest} onChange={e => setOnlyTest(e.target.checked)}
                   className="accent-cyan-500" />
            {t('settings.dbMaint.onlyTest')}
          </label>
        )}
      </div>

      {needsConfirm && (
        <div className="rounded border border-red-800/50 bg-red-950/30 px-3 py-2">
          <p className="text-xs text-red-300 mb-2">
            {t('settings.dbMaint.factoryResetWarn1')} <strong>{t('settings.dbMaint.factoryResetAll')}</strong> {t('settings.dbMaint.factoryResetWarn2')}
          </p>
          <input type="text" value={confirmText} onChange={e => setConfirmText(e.target.value)}
                 placeholder="DELETE CYJAN"
                 className="cyjan-input text-xs w-48" />
        </div>
      )}

      <div className="flex items-center gap-2">
        <PasswordInput value={password} onChange={setPassword} />
        <button disabled={!canRun} onClick={run}
                className="px-3 py-1.5 rounded text-xs font-medium bg-red-700 hover:bg-red-600 text-white disabled:opacity-40 disabled:cursor-not-allowed transition-colors whitespace-nowrap">
          {busy ? '…' : t('common.delete')}
        </button>
      </div>

      {msg && (
        <p className={`text-xs ${msgType === 'ok' ? 'text-green-400' : 'text-red-400'}`}>{msg}</p>
      )}
    </ActionCard>
  );
}

// ── Vacuum-Sektion ────────────────────────────────────────────────────────────

function VacuumSection({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [full,     setFull]     = useState(false);
  const [password, setPassword] = useState('');
  const [busy,     setBusy]     = useState(false);
  const [msg,      setMsg]      = useState('');
  const [msgType,  setMsgType]  = useState<'ok' | 'err'>('ok');

  async function run() {
    setBusy(true); setMsg('');
    try {
      const r = await vacuumDb({ password, full, analyze: true });
      setMsgType('ok'); setMsg(t('settings.dbMaint.vacuumDone', { sql: r.sql, ms: r.duration_ms }));
      setPassword(''); onDone();
    } catch (e) {
      setMsgType('err'); setMsg(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ActionCard title="VACUUM / ANALYZE">
      <p className="text-xs text-slate-500">
        {t('settings.dbMaint.vacuumHint')}
      </p>
      <label className="flex items-center gap-1.5 text-xs text-slate-400">
        <input type="checkbox" checked={full} onChange={e => setFull(e.target.checked)}
               className="accent-cyan-500" />
        {t('settings.dbMaint.vacuumFull')}
      </label>
      <div className="flex items-center gap-2">
        <PasswordInput value={password} onChange={setPassword} />
        <button disabled={!password || busy} onClick={run}
                className="px-3 py-1.5 rounded text-xs font-medium bg-cyan-700 hover:bg-cyan-600 text-white disabled:opacity-40 disabled:cursor-not-allowed">
          {busy ? '…' : t('settings.dbMaint.run')}
        </button>
      </div>
      {msg && <p className={`text-xs ${msgType === 'ok' ? 'text-green-400' : 'text-red-400'}`}>{msg}</p>}
    </ActionCard>
  );
}

// ── Retention-Sektion ─────────────────────────────────────────────────────────

function RetentionSection({ stats, onDone }: { stats: DbStatsResponse; onDone: () => void }) {
  const { t } = useTranslation();
  const [selected, setSelected] = useState(stats.hypertables[0]?.name ?? '');
  const [days,     setDays]     = useState('90');
  const [password, setPassword] = useState('');
  const [busy,     setBusy]     = useState(false);
  const [msg,      setMsg]      = useState('');
  const [msgType,  setMsgType]  = useState<'ok' | 'err'>('ok');

  async function apply(removeInstead: boolean) {
    setBusy(true); setMsg('');
    try {
      const r = await setRetentionPolicy({
        password,
        hypertable: selected,
        days:       removeInstead ? null : parseInt(days, 10),
      });
      setMsgType('ok'); setMsg(r.message);
      setPassword(''); onDone();
    } catch (e) {
      setMsgType('err'); setMsg(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ActionCard title={t('settings.dbMaint.retentionTitle')}>
      <p className="text-xs text-slate-500">
        {t('settings.dbMaint.retentionHint', { active: stats.retention.length === 0 ? t('settings.dbMaint.retentionNone') : stats.retention.map(p => p.hypertable).join(', ') })}
      </p>
      <div className="flex flex-wrap items-end gap-3">
        <div>
          <label className="text-[10px] text-slate-500 uppercase">Hypertable</label>
          <select value={selected} onChange={e => setSelected(e.target.value)}
                  className="cyjan-input text-xs block mt-1">
            {stats.hypertables.map(h => (
              <option key={h.name} value={h.name}>{h.name}</option>
            ))}
          </select>
        </div>
        <div>
          <label className="text-[10px] text-slate-500 uppercase">{t('settings.dbMaint.days')}</label>
          <input type="number" value={days} onChange={e => setDays(e.target.value)}
                 min="1" max="36500"
                 className="cyjan-input text-xs block mt-1 w-24" />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <PasswordInput value={password} onChange={setPassword} />
        <button disabled={!password || !selected || busy} onClick={() => apply(false)}
                className="px-3 py-1.5 rounded text-xs font-medium bg-cyan-700 hover:bg-cyan-600 text-white disabled:opacity-40">
          {t('settings.dbMaint.setPolicy')}
        </button>
        <button disabled={!password || !selected || busy} onClick={() => apply(true)}
                className="px-3 py-1.5 rounded text-xs font-medium bg-slate-700 hover:bg-slate-600 text-white disabled:opacity-40">
          {t('settings.dbMaint.remove')}
        </button>
      </div>
      {msg && <p className={`text-xs ${msgType === 'ok' ? 'text-green-400' : 'text-red-400'}`}>{msg}</p>}
    </ActionCard>
  );
}

// ── Backup / Restore-Sektion ──────────────────────────────────────────────────

function BackupRestoreSection({ onDone }: { onDone: () => void }) {
  const { t } = useTranslation();
  const [restorePw,   setRestorePw]   = useState('');
  const [restoreFile, setRestoreFile] = useState<File | null>(null);
  const [busy,        setBusy]        = useState(false);
  const [msg,         setMsg]         = useState('');
  const [msgType,     setMsgType]     = useState<'ok' | 'err'>('ok');

  async function downloadBackup() {
    const token = localStorage.getItem('ids_token');
    const url   = backupDbUrl();
    // fetch mit Auth und als Blob speichern
    try {
      const r = await fetch(url, { headers: token ? { Authorization: `Bearer ${token}` } : {} });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const blob = await r.blob();
      const link = document.createElement('a');
      link.href = URL.createObjectURL(blob);
      const cd = r.headers.get('content-disposition') || '';
      const fn = /filename="([^"]+)"/.exec(cd)?.[1] ?? 'cyjan-backup.sql.gz';
      link.download = fn;
      link.click();
      URL.revokeObjectURL(link.href);
      setMsgType('ok'); setMsg(t('settings.dbMaint.backupDownloaded', { filename: fn }));
    } catch (e) {
      setMsgType('err'); setMsg(String((e as Error).message));
    }
  }

  async function doRestore() {
    if (!restoreFile) return;
    setBusy(true); setMsg('');
    try {
      const r = await restoreDb(restorePw, restoreFile);
      setMsgType('ok'); setMsg(t('settings.dbMaint.restoreSuccess', { mb: (r.bytes/1024/1024).toFixed(1), ms: r.duration_ms }));
      setRestorePw(''); setRestoreFile(null); onDone();
    } catch (e) {
      setMsgType('err'); setMsg(String((e as Error).message));
    } finally {
      setBusy(false);
    }
  }

  return (
    <ActionCard title="Backup / Restore">
      <p className="text-xs text-slate-500">
        {t('settings.dbMaint.backupHint1')}
        <strong className="text-amber-300"> {t('settings.dbMaint.backupHintWarn')}</strong>
      </p>
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={downloadBackup}
                className="px-3 py-1.5 rounded text-xs font-medium bg-cyan-700 hover:bg-cyan-600 text-white">
          {t('settings.dbMaint.downloadBackup')}
        </button>
      </div>
      <div className="border-t border-slate-800 pt-3 space-y-2">
        <p className="text-xs text-slate-400">{t('settings.dbMaint.restoreLabel')}</p>
        <div className="flex flex-wrap items-center gap-2">
          <input type="file" accept=".sql,.sql.gz,.gz"
                 onChange={e => setRestoreFile(e.target.files?.[0] ?? null)}
                 className="text-xs text-slate-400 file:mr-2 file:px-2 file:py-1 file:rounded file:border-0 file:bg-slate-700 file:text-slate-200" />
          <PasswordInput value={restorePw} onChange={setRestorePw} />
          <button disabled={!restoreFile || !restorePw || busy} onClick={doRestore}
                  className="px-3 py-1.5 rounded text-xs font-medium bg-red-700 hover:bg-red-600 text-white disabled:opacity-40">
            {busy ? '…' : t('settings.dbMaint.import')}
          </button>
        </div>
      </div>
      {msg && <p className={`text-xs ${msgType === 'ok' ? 'text-green-400' : 'text-red-400'}`}>{msg}</p>}
    </ActionCard>
  );
}

function MLLearnedPatterns() {
  const { t } = useTranslation();
  const [patterns, setPatterns] = useState<LearnedPattern[] | null>(null);
  const [cfg,      setCfg]      = useState<{ window_days: number; min_hours: number; z_threshold: number } | null>(null);
  const [loading,  setLoading]  = useState(true);
  const [error,    setError]    = useState('');

  useEffect(() => {
    let alive = true;
    const load = () => fetchLearnedPatterns()
      .then(r => { if (alive) { setPatterns(r.patterns); setCfg(r.config); setLoading(false); } })
      .catch(() => { if (alive) { setError(t('settings.mlLearned.loadError')); setLoading(false); } });
    load();
    const ti = setInterval(load, 30_000);
    return () => { alive = false; clearInterval(ti); };
  }, [t]);

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;
  if (error)   return <p className="text-red-400 text-sm">{error}</p>;

  const activeCount = patterns?.filter(p => p.suppressed).length ?? 0;
  const spikeCount  = patterns?.filter(p => !p.suppressed).length ?? 0;

  return (
    <div className="space-y-5">
      <div>
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.mlLearned.title')}</h2>
        <p className="text-xs text-slate-500 mt-1">
          {t('settings.mlLearned.intro1')}{' '}
          <span className="text-slate-300">{t('settings.mlLearned.daysSpan', { days: cfg?.window_days })}</span>{' '}
          {t('settings.mlLearned.intro2')}{' '}
          (z-Score &lt; <span className="text-slate-300">{cfg?.z_threshold}</span>).
        </p>
        <p className="text-xs text-slate-600 mt-1">
          {t('settings.mlLearned.spikeIntro1')} <strong>{t('settings.mlLearned.spikeFpStrong')}</strong>{' '}
          {t('settings.mlLearned.spikeIntro2')}
        </p>
      </div>

      {/* Summary */}
      {patterns && patterns.length > 0 && (
        <div className="flex gap-3 text-xs">
          <div className="flex-1 rounded-lg border border-green-800/40 bg-green-950/20 px-3 py-2">
            <div className="text-green-400 text-[11px] uppercase tracking-wider font-mono">{t('settings.mlLearned.activeSuppressed')}</div>
            <div className="text-green-300 text-lg font-semibold tabular-nums">{activeCount}</div>
            <div className="text-slate-600 text-[10px]">{t('settings.mlLearned.activeSuppressedSub')}</div>
          </div>
          <div className="flex-1 rounded-lg border border-amber-800/40 bg-amber-950/20 px-3 py-2">
            <div className="text-amber-400 text-[11px] uppercase tracking-wider font-mono">{t('settings.mlLearned.spikeBreak')}</div>
            <div className="text-amber-300 text-lg font-semibold tabular-nums">{spikeCount}</div>
            <div className="text-slate-600 text-[10px]">{t('settings.mlLearned.spikeBreakSub')}</div>
          </div>
        </div>
      )}

      {!patterns || patterns.length === 0 ? (
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/30 px-4 py-6 text-center">
          <p className="text-slate-500 text-sm">{t('settings.mlLearned.noBaselines')}</p>
          <p className="text-slate-600 text-xs mt-1">
            {t('settings.mlLearned.noBaselinesHint', { hours: cfg?.min_hours })}
          </p>
        </div>
      ) : (
        <div className="rounded-lg border border-slate-700/50 overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-slate-800/50">
              <tr className="text-left text-[11px] text-slate-500">
                <th className="px-3 py-2">{t('settings.mlLearned.colStatus')}</th>
                <th className="px-3 py-2" title={t('settings.mlLearned.sourceColTitle')}>{t('settings.mlLearned.colSource')}</th>
                <th className="px-3 py-2">{t('settings.mlLearned.colRule')}</th>
                <th className="px-3 py-2">{t('settings.mlLearned.colSrcDst')}</th>
                <th className="px-3 py-2 text-right" title={t('settings.mlLearned.baselineColTitle')}>{t('settings.mlLearned.colBaseline')}</th>
                <th className="px-3 py-2 text-right" title={t('settings.mlLearned.dataColTitle')}>{t('settings.mlLearned.colData')}</th>
                <th className="px-3 py-2 text-right" title={t('settings.mlLearned.recentColTitle')}>{t('settings.mlLearned.colRecent')}</th>
                <th className="px-3 py-2 text-right" title={t('settings.mlLearned.zColTitle')}>z-Score</th>
              </tr>
            </thead>
            <tbody>
              {patterns.map(p => {
                const zClass = p.z_score >= 3 ? 'text-red-400'
                             : p.z_score >= 2 ? 'text-amber-400'
                             : p.z_score >= 1 ? 'text-slate-300'
                             : 'text-green-400';
                return (
                  <tr key={`${p.rule_id}|${p.src_ip}|${p.dst_ip}`}
                      className="border-t border-slate-800 hover:bg-slate-800/30">
                    <td className="px-3 py-2">
                      {p.suppressed ? (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-green-950/60 text-green-300 border border-green-800/50 font-mono">
                          ✓ suppressed
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-amber-950/60 text-amber-300 border border-amber-800/50 font-mono">
                          ⚠ spike
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2">
                      {p.source === 'manual' ? (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-blue-950/60 text-blue-300 border border-blue-800/50 font-mono"
                              title={t('settings.mlLearned.manualTitle')}>
                          manual
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] bg-slate-800/60 text-slate-400 border border-slate-700/50 font-mono"
                              title={t('settings.mlLearned.learnedTitle')}>
                          learned
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-cyan-300 font-mono">{p.rule_id}</td>
                    <td className="px-3 py-2 font-mono text-slate-300">
                      <span>{p.src_ip}</span>
                      <span className="text-slate-600 mx-1">↔</span>
                      <span>{p.dst_ip}</span>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-300 font-mono">
                      {p.mean_h.toFixed(1)}
                      <span className="text-slate-600"> ± {p.std_h.toFixed(1)}</span>
                    </td>
                    <td className="px-3 py-2 text-right tabular-nums text-slate-500">{p.hours_with_data} h</td>
                    <td className={`px-3 py-2 text-right tabular-nums font-mono ${p.recent_1h > p.mean_h + 2*p.std_h ? 'text-amber-300' : 'text-slate-300'}`}>
                      {p.recent_1h}
                    </td>
                    <td className={`px-3 py-2 text-right tabular-nums font-mono font-semibold ${zClass}`}>
                      {p.z_score >= 99 ? '∞' : p.z_score.toFixed(2)}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      <p className="text-[10px] text-slate-700 font-mono">
        {t('settings.mlLearned.refreshFooter')}
      </p>
    </div>
  );
}

function MLFilterConfig() {
  const { t } = useTranslation();
  const [cfg,      setCfg]      = useState<MLConfig | null>(null);
  const [cfgDraft, setCfgDraft] = useState<MLConfig | null>(null);
  const [saving,   setSaving]   = useState(false);
  const [saveMsg,  setSaveMsg]  = useState('');
  const [retraining, setRetraining] = useState(false);
  const PARAM_DOCS = buildParamDocs(t);

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
      setSaveMsg('err:' + (err instanceof Error ? err.message : t('common.errorGeneric')));
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
      setSaveMsg('err:' + (err instanceof Error ? err.message : t('common.errorGeneric')));
    } finally {
      setRetraining(false);
    }
  }

  if (!cfgDraft) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.mlConfig.title')}</h2>
        <div className="flex items-center gap-2">
          {saveMsg === 'ok'          && <span className="text-xs text-green-400">{t('settings.saml.savedOk')}</span>}
          {saveMsg === 'retrain'     && <span className="text-xs text-blue-400">{t('settings.mlConfig.retrainTriggered')}</span>}
          {saveMsg.startsWith('err:')&& <span className="text-xs text-red-400">{saveMsg.slice(4)}</span>}
          <button className="btn-ghost text-xs" disabled={retraining} onClick={handleRetrain}>
            {retraining ? t('settings.mlConfig.triggering') : t('settings.mlConfig.retrainNow')}
          </button>
          <button
            className="btn-primary text-xs"
            disabled={saving || !cfg || JSON.stringify(cfgDraft) === JSON.stringify(cfg)}
            onClick={handleSaveConfig}
          >
            {saving ? t('settings.users.savingShort') : t('common.save')}
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
  const { t } = useTranslation();
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
      setNewErr(err instanceof Error ? err.message : t('common.errorGeneric'));
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
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.rules.sourcesTitle')}</h2>
        <div className="flex items-center gap-2">
          <button onClick={handleTriggerUpdate} disabled={updating || !!status?.requested} className="btn-primary text-xs">
            {status?.requested ? t('settings.rules.updateRunning') : updating ? '…' : t('settings.rules.startUpdate')}
          </button>
          <button className="btn-ghost text-xs" onClick={() => { setShowAdd(v => !v); setNewErr(''); }}>
            {showAdd ? t('common.cancel') : t('settings.rules.addSource')}
          </button>
        </div>
      </div>

      {status && (
        <p className="text-xs text-slate-500">
          {status.requested
            ? t('settings.rules.updateRequested', { ts: fmtTs(status.requested_at) })
            : status.last_updated
              ? t('settings.rules.lastUpdated', { ts: fmtTs(status.last_updated) })
              : t('settings.rules.noUpdateYet')}
        </p>
      )}

      {showAdd && (
        <form onSubmit={handleAddSource} className="card p-3 flex flex-wrap gap-2 items-end text-xs">
          <div className="flex flex-col gap-1 flex-1 min-w-[160px]">
            <label className="text-slate-400">{t('settings.rules.fieldName')}</label>
            <input className="input" required value={newName} onChange={e => setNewName(e.target.value)} placeholder={t('settings.rules.namePlaceholder')} />
          </div>
          <div className="flex flex-col gap-1 flex-[2] min-w-[260px]">
            <label className="text-slate-400">{t('settings.rules.fieldUrl')}</label>
            <input className="input" required type="url" value={newUrl} onChange={e => setNewUrl(e.target.value)} placeholder="https://example.com/my.rules" />
          </div>
          {newErr && <p className="w-full text-red-400">{newErr}</p>}
          <button type="submit" className="btn-primary text-xs">{t('common.add')}</button>
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
              title={src.enabled ? t('settings.rules.enabled') : t('settings.rules.disabled')}
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
                title={t('settings.rules.removeSource')}>✕</button>
            )}
          </div>
        ))}
      </div>

      {confirmSrc && (
        <ConfirmDialog
          message={t('settings.rules.removeSourceConfirm', { name: confirmSrc.name })}
          confirmLabel={t('settings.rules.removeLabel')}
          onConfirm={() => { const s = confirmSrc; setConfirmSrc(null); handleDeleteSource(s); }}
          onCancel={() => setConfirmSrc(null)}
        />
      )}

      <SuricataOfflineImport />
    </div>
  );
}

// ── Offline-Import (für Maschinen ohne Internet) ──────────────────────────────
function SuricataOfflineImport() {
  const { t } = useTranslation();
  const inputRef = useRef<HTMLInputElement>(null);
  const [busy,    setBusy]    = useState(false);
  const [result,  setResult]  = useState<{ ok: boolean; msg: string; files?: string[]; rules?: number } | null>(null);

  async function handleFile(f: File) {
    if (!f) return;
    setBusy(true);
    setResult(null);
    try {
      const r = await importSuricataRules(f);
      const main = t('settings.rules.offlineImportResult', { rules: r.rules_count.toLocaleString('de-DE'), files: r.files_imported.length });
      setResult({
        ok:    true,
        msg:   r.note ? `${main} ${r.note}` : `${main} ${t('settings.rules.suricataReload', { reload: r.reload })}`,
        files: r.files_imported,
        rules: r.rules_count,
      });
    } catch (e) {
      setResult({ ok: false, msg: e instanceof Error ? e.message : String(e) });
    } finally {
      setBusy(false);
      if (inputRef.current) inputRef.current.value = '';
    }
  }

  return (
    <div className="card p-3 space-y-2 mt-4 border-cyan-700/40 bg-cyan-950/10">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div>
          <h3 className="text-xs font-semibold text-slate-200">{t('settings.rules.offlineImportTitle')}</h3>
          <p className="text-[11px] text-slate-500 mt-0.5">
            {t('settings.rules.offlineImportHint1')} <code className="font-mono">*.rules</code>{t('settings.rules.offlineImportHint2')} <code className="font-mono">SIGUSR2</code> {t('settings.rules.offlineImportHint3')}
          </p>
        </div>
        <input
          ref={inputRef}
          type="file"
          accept=".rules,.tar.gz,.tgz,application/gzip,application/x-tar"
          onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f); }}
          disabled={busy}
          className="text-[11px] text-slate-300 file:mr-2 file:px-3 file:py-1 file:rounded file:border-0 file:bg-cyan-700 file:text-white file:cursor-pointer hover:file:bg-cyan-600 file:text-[11px] file:font-medium"
        />
      </div>

      {busy && (
        <p className="text-[11px] text-slate-400">{t('settings.rules.uploading')}</p>
      )}

      {result && (
        <div className={`text-[11px] rounded border px-2.5 py-1.5 ${
          result.ok
            ? 'border-green-700/50 bg-green-950/30 text-green-300'
            : 'border-red-700/50 bg-red-950/30 text-red-300'
        }`}>
          <p>{result.ok ? '✓ ' : '⚠ '}{result.msg}</p>
          {result.files && result.files.length > 0 && (
            <ul className="mt-1 ml-4 list-disc text-slate-400">
              {result.files.slice(0, 12).map(f => (
                <li key={f} className="font-mono text-[10px]">{f}</li>
              ))}
              {result.files.length > 12 && (
                <li className="text-slate-500 text-[10px]">{t('settings.rules.andMore', { n: result.files.length - 12 })}</li>
              )}
            </ul>
          )}
        </div>
      )}
    </div>
  );
}

// ── Eigene Signaturen: Datei-Editor ───────────────────────────────────────────
// Zwei-Spalten-UX: links die Datei-Liste mit Größe + Mtime + Built-in-Marker,
// rechts der Inhalt im Textarea. Speichern triggert serverseitig
// `suricata -T`; bei Syntax-Fehler kommt 422 mit dem Suricata-Diagnose-Tail
// zurück und das Frontend zeigt's rot über dem Editor an.
function RuleFileEditor() {
  const { t } = useTranslation();
  const [files,    setFiles]    = useState<RuleFileMeta[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [content,  setContent]  = useState<string>('');
  const [orig,     setOrig]     = useState<string>('');
  const [busy,     setBusy]     = useState(false);
  const [error,    setError]    = useState<string | null>(null);
  const [info,     setInfo]     = useState<string | null>(null);
  const [confirmDel, setConfirmDel] = useState<RuleFileMeta | null>(null);
  const [creating, setCreating] = useState(false);
  const [newName,  setNewName]  = useState('');
  // Filter + Custom-First-Sort: bei 70+ emerging-Files ist die Custom-Datei
  // ohne Suche praktisch unauffindbar.
  const [search, setSearch] = useState('');
  const [showBuiltin, setShowBuiltin] = useState(true);

  // Sortierung: Custom zuerst (alphabetisch), dann builtin (alphabetisch).
  // Plus optionaler Substring-Filter auf den Dateinamen.
  const filteredFiles = useMemo(() => {
    const q = search.trim().toLowerCase();
    return [...files]
      .filter(f => showBuiltin || !f.builtin)
      .filter(f => !q || f.name.toLowerCase().includes(q))
      .sort((a, b) => {
        if (a.builtin !== b.builtin) return a.builtin ? 1 : -1;
        return a.name.localeCompare(b.name);
      });
  }, [files, search, showBuiltin]);

  const dirty = content !== orig;

  async function refresh() {
    setBusy(true);
    try { setFiles(await fetchRuleFiles()); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setBusy(false); }
  }

  useEffect(() => { refresh(); }, []);

  async function open(name: string) {
    if (dirty && !confirm(t('settings.rules.discardChanges'))) return;
    setError(null); setInfo(null);
    setBusy(true);
    try {
      const f = await fetchRuleFile(name);
      setSelected(name);
      setContent(f.content);
      setOrig(f.content);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function save() {
    if (!selected) return;
    setError(null); setInfo(null); setBusy(true);
    try {
      const r = await saveRuleFile(selected, content);
      setOrig(content);
      setInfo(
        t('settings.rules.editorSaved', {
          rules: r.rules_count.toLocaleString('de-DE'),
          test: r.test_ok ? '✓' : t('settings.rules.testSkipped'),
          reload: r.reload,
        }) + (r.note ? ` · ${r.note}` : '')
      );
      await refresh();
    } catch (e) {
      // 422-Antwort von save: detail = { message, test_output }
      const raw = e instanceof Error ? e.message : String(e);
      const m = raw.match(/422[^:]*:\s*(.*)$/s);
      if (m) {
        try {
          const detail = JSON.parse(m[1]).detail;
          setError(`${detail?.message ?? t('settings.rules.validationFailed')}\n\n${detail?.test_output ?? ''}`);
        } catch { setError(raw); }
      } else { setError(raw); }
    } finally {
      setBusy(false);
    }
  }

  async function doDelete(meta: RuleFileMeta) {
    setBusy(true); setError(null); setInfo(null);
    try {
      await deleteRuleFile(meta.name);
      if (selected === meta.name) {
        setSelected(null); setContent(''); setOrig('');
      }
      setInfo(t('settings.rules.fileDeleted', { name: meta.name }));
      await refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  function startCreate() {
    if (dirty && !confirm(t('settings.rules.discardChanges'))) return;
    setCreating(true); setNewName(''); setError(null); setInfo(null);
  }
  function cancelCreate() {
    setCreating(false); setNewName('');
  }
  function commitCreate() {
    const trimmed = newName.trim();
    const name = trimmed.endsWith('.rules') ? trimmed : `${trimmed}.rules`;
    if (!/^[A-Za-z0-9._-]+\.rules$/.test(name)) {
      setError(t('settings.rules.invalidFilename'));
      return;
    }
    setSelected(name);
    setContent(`# ${name}\n# ${t('settings.rules.newFileHeader1')}\n# ${t('settings.rules.newFileHeader2')}\n\n`);
    setOrig('');
    setCreating(false); setNewName('');
  }

  const fmtSize = (b: number) => b < 1024 ? `${b} B` : b < 1024*1024 ? `${(b/1024).toFixed(1)} KB` : `${(b/1024/1024).toFixed(1)} MB`;
  const fmtTs   = (ts: number) => new Date(ts*1000).toLocaleString('de-DE', { dateStyle: 'short', timeStyle: 'short' });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.rules.editorTitle')}</h2>
        <div className="flex items-center gap-2">
          <button className="btn-ghost text-xs" onClick={refresh} disabled={busy}>{t('settings.rules.refresh')}</button>
          <button className="btn-primary text-xs" onClick={startCreate} disabled={busy || creating}>{t('settings.rules.newFile')}</button>
        </div>
      </div>

      <p className="text-[11px] text-slate-500">
        {t('settings.rules.editorIntro')}
      </p>

      {creating && (
        <div className="card p-3 flex items-end gap-2">
          <div className="flex-1">
            <label className="text-[11px] text-slate-400">{t('settings.rules.filenameLabel')}</label>
            <input
              className="input w-full text-xs"
              autoFocus
              value={newName}
              onChange={e => setNewName(e.target.value)}
              placeholder="my-custom"
              onKeyDown={e => { if (e.key === 'Enter') commitCreate(); if (e.key === 'Escape') cancelCreate(); }}
            />
          </div>
          <button className="btn-primary text-xs" onClick={commitCreate}>{t('settings.rules.create')}</button>
          <button className="btn-ghost text-xs"   onClick={cancelCreate}>{t('common.cancel')}</button>
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-[260px_1fr] gap-3">
        {/* Datei-Liste */}
        <div className="space-y-1.5">
          <input
            type="search"
            className="input w-full text-xs"
            placeholder={t('settings.rules.editorSearchPlaceholder')}
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <label className="flex items-center gap-1.5 text-[10px] text-slate-500 px-1">
            <input
              type="checkbox"
              className="accent-cyan-500"
              checked={showBuiltin}
              onChange={e => setShowBuiltin(e.target.checked)}
            />
            <span>{t('settings.rules.editorShowBuiltin')}</span>
            <span className="ml-auto tabular-nums">
              {t('settings.rules.editorShowingCount', { shown: filteredFiles.length, total: files.length })}
            </span>
          </label>
          <div className="space-y-1 max-h-[440px] overflow-y-auto pr-1">
          {filteredFiles.length === 0 && !busy && (
            <p className="text-[11px] text-slate-500 italic px-2 py-3">{t('settings.rules.noFiles')}</p>
          )}
          {filteredFiles.map(f => (
            <button
              key={f.name}
              type="button"
              onClick={() => open(f.name)}
              className={`w-full text-left px-2.5 py-2 rounded border text-[11px] transition-colors ${
                selected === f.name
                  ? 'bg-cyan-950/30 border-cyan-700/60 text-slate-100'
                  : f.builtin
                    ? 'bg-slate-900/30 border-slate-800/40 text-slate-400'
                    : 'bg-slate-800/40 border-slate-700/50 text-slate-200 hover:border-slate-600'
              }`}
            >
              <div className="flex items-center gap-1.5">
                <span className="font-mono truncate flex-1">{f.name}</span>
                {f.builtin && <span className="px-1 py-0.5 text-[9px] rounded bg-slate-700/40 text-slate-500 border border-slate-600/30">built-in</span>}
              </div>
              <div className="flex items-center gap-3 text-[10px] text-slate-500 mt-0.5">
                <span>{t('settings.rules.rulesCount', { n: f.rules.toLocaleString('de-DE') })}</span>
                <span>{fmtSize(f.size)}</span>
                <span className="ml-auto">{fmtTs(f.modified)}</span>
              </div>
            </button>
          ))}
          </div>
        </div>

        {/* Editor-Spalte */}
        <div className="space-y-2">
          {!selected ? (
            <p className="text-[11px] text-slate-500 italic px-3 py-6 text-center">
              {t('settings.rules.selectFileHint')}
            </p>
          ) : (
            <>
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-xs text-slate-200">{selected}</span>
                {dirty && <span className="text-[10px] text-amber-400">{t('settings.rules.unsaved')}</span>}
                <div className="ml-auto flex items-center gap-2">
                  <button
                    type="button"
                    className="btn-primary text-xs"
                    disabled={!dirty || busy || files.find(f => f.name === selected)?.builtin}
                    onClick={save}
                  >
                    {busy ? '…' : t('common.save')}
                  </button>
                  <button
                    type="button"
                    className="btn-ghost text-xs"
                    disabled={busy || !files.find(f => f.name === selected) || files.find(f => f.name === selected)?.builtin}
                    onClick={() => {
                      const f = files.find(x => x.name === selected);
                      if (f) setConfirmDel(f);
                    }}
                  >
                    {t('common.delete')}
                  </button>
                </div>
              </div>

              {error && (
                <pre className="text-[11px] text-red-300 bg-red-950/30 border border-red-700/50 rounded px-3 py-2 whitespace-pre-wrap font-mono max-h-48 overflow-auto">{error}</pre>
              )}
              {info && (
                <p className="text-[11px] text-green-300 bg-green-950/30 border border-green-700/50 rounded px-3 py-2">{info}</p>
              )}

              <textarea
                className="w-full h-[480px] bg-slate-900/60 border border-slate-700/60 rounded p-3 font-mono text-xs text-slate-200 resize-y focus:outline-none focus:border-cyan-700"
                spellCheck={false}
                value={content}
                onChange={e => setContent(e.target.value)}
                disabled={files.find(f => f.name === selected)?.builtin}
                placeholder='alert tcp any any -> any 80 (msg:"Example"; sid:1000001; rev:1;)'
              />

              {files.find(f => f.name === selected)?.builtin && (
                <p className="text-[11px] text-amber-400 italic">
                  {t('settings.rules.builtinReadonly')}
                </p>
              )}
            </>
          )}
        </div>
      </div>

      {confirmDel && (
        <ConfirmDialog
          message={t('settings.rules.deleteFileConfirm', { name: confirmDel.name, rules: confirmDel.rules.toLocaleString('de-DE') })}
          confirmLabel={t('common.delete')}
          onConfirm={() => { const m = confirmDel; setConfirmDel(null); doDelete(m); }}
          onCancel={() => setConfirmDel(null)}
        />
      )}
    </div>
  );
}

function RulesList() {
  const { t } = useTranslation();
  const [rules,    setRules]    = useState<Rule[]>([]);
  const [total,    setTotal]    = useState(0);
  const [search,   setSearch]   = useState('');
  const [offset,   setOffset]   = useState(0);
  const [loading,  setLoading]  = useState(false);
  const [overrides,        setOverrides]        = useState<Record<string, SuricataOverrideEntry>>({});
  const [originalOverrides, setOriginal]        = useState<Record<string, SuricataOverrideEntry>>({});
  const [info, setInfo]   = useState('');
  const [error, setError] = useState('');
  const [saving, setSaving] = useState(false);
  const LIMIT = 100;

  useEffect(() => {
    setLoading(true);
    fetchRules({ search, limit: LIMIT, offset })
      .then(r => { setRules(r.rules); setTotal(r.total); })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, [search, offset]);

  // Overrides werden nur einmal geladen – nicht pro Page-Wechsel
  useEffect(() => {
    fetchSuricataOverrides()
      .then(r => { setOverrides(r.overrides); setOriginal(r.overrides); })
      .catch(e => setError(t('settings.rules.overridesLoadError', { message: e instanceof Error ? e.message : String(e) })));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const dirty = useMemo(() =>
    JSON.stringify(overrides) !== JSON.stringify(originalOverrides),
  [overrides, originalOverrides]);

  const updateOverride = (sid: number | null, patch: Partial<SuricataOverrideEntry>) => {
    if (sid == null) return;
    const key = String(sid);
    setOverrides(prev => {
      const cur = prev[key] ?? {};
      const next: SuricataOverrideEntry = { ...cur, ...patch };
      const out = { ...prev };
      // Wenn wieder Default (enabled=true UND severity=null), Eintrag löschen
      if ((next.enabled === true || next.enabled == null) && next.severity == null) {
        delete out[key];
      } else {
        out[key] = next;
      }
      return out;
    });
    setInfo('');
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setInfo('');
    try {
      const r = await saveSuricataOverrides(overrides);
      setOverrides(r.overrides);
      setOriginal(r.overrides);
      setInfo(t('settings.rules.overridesSaved'));
    } catch (e) {
      setError(t('settings.rules.overridesSaveError', { message: e instanceof Error ? e.message : String(e) }));
    } finally {
      setSaving(false);
    }
  };

  const pages = Math.ceil(total / LIMIT);
  const page  = Math.floor(offset / LIMIT);

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="text-sm font-semibold text-slate-200">
          {t('settings.rules.activeRules')}
          {total > 0 && <span className="ml-2 text-slate-500 font-normal">{total.toLocaleString()}</span>}
        </h2>
        <input
          className="input text-xs w-56"
          placeholder={t('settings.rules.searchPlaceholder')}
          value={search}
          onChange={e => { setSearch(e.target.value); setOffset(0); }}
        />
      </div>

      <p className="text-[11px] text-slate-500 leading-relaxed">
        {t('settings.rules.overrideHint')}
      </p>

      {error && <p className="text-xs text-red-400">{error}</p>}

      {loading ? (
        <p className="text-slate-500 text-xs">{t('common.loading')}</p>
      ) : rules.length === 0 ? (
        <p className="text-slate-600 text-xs">
          {total === 0 ? t('settings.rules.noRulesLoaded') : t('settings.rules.noResults')}
        </p>
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead className="border-b border-slate-800">
                <tr className="text-left text-slate-500">
                  <th className="pb-2 pr-3 w-20">SID</th>
                  <th className="pb-2 pr-3">{t('settings.rules.colDescription')}</th>
                  <th className="pb-2 pr-3 w-28">Classtype</th>
                  <th className="pb-2 pr-3 w-16">{t('settings.rules.colAction')}</th>
                  <th className="pb-2 pr-3 w-16">{t('settings.rules.colStatus')}</th>
                  <th className="pb-2 pr-3 w-32">{t('settings.rules.colSeverityOverride')}</th>
                  <th className="pb-2 pr-3 w-12 text-center">{t('settings.rules.colEnabled')}</th>
                  <th className="pb-2 w-40">{t('settings.rules.colFile')}</th>
                </tr>
              </thead>
              <tbody>
                {rules.map((r, i) => {
                  const sidKey = r.sid != null ? String(r.sid) : null;
                  const ov: SuricataOverrideEntry = (sidKey && overrides[sidKey]) || {};
                  const ovDisabled = ov.enabled === false;
                  const sevValue: string = ov.severity ?? 'default';
                  const hasChange = ov.severity != null;
                  return (
                    <tr key={`${r.sid}-${i}`} className={`border-b border-slate-800/40 hover:bg-slate-800/20 ${!r.enabled || ovDisabled ? 'opacity-40' : ''}`}>
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
                          {r.enabled ? t('settings.rules.statusActive') : t('settings.rules.statusOff')}
                        </span>
                      </td>
                      <td className="py-1.5 pr-3">
                        <select
                          className={`input text-xs w-28 ${hasChange ? 'border-amber-600 text-amber-200' : ''}`}
                          value={sevValue}
                          disabled={r.sid == null}
                          onChange={e => {
                            const v = e.target.value;
                            updateOverride(r.sid, { severity: v === 'default' ? null : (v as SuricataOverrideEntry['severity']) });
                          }}
                        >
                          <option value="default">{t('settings.rules.severityDefault')}</option>
                          <option value="critical">critical</option>
                          <option value="high">high</option>
                          <option value="medium">medium</option>
                          <option value="low">low</option>
                        </select>
                      </td>
                      <td className="py-1.5 pr-3 text-center">
                        <input
                          type="checkbox"
                          className="accent-cyan-500"
                          checked={ov.enabled !== false}
                          disabled={r.sid == null}
                          onChange={e => updateOverride(r.sid, { enabled: e.target.checked ? null : false })}
                        />
                      </td>
                      <td className="py-1.5 font-mono text-slate-600 text-[10px] truncate">{r.file}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>

          <div className="flex items-center justify-between gap-3 pt-2 flex-wrap">
            {pages > 1 ? (
              <div className="flex items-center gap-2 text-xs text-slate-500">
                <button className="btn-ghost text-xs disabled:opacity-30" disabled={page === 0}
                  onClick={() => setOffset(Math.max(0, offset - LIMIT))}>{t('settings.rules.prev')}</button>
                <span>{page + 1} / {pages}</span>
                <button className="btn-ghost text-xs disabled:opacity-30" disabled={page >= pages - 1}
                  onClick={() => setOffset(offset + LIMIT)}>{t('settings.rules.next')}</button>
              </div>
            ) : <span />}
            <div className="flex items-center gap-2">
              {info && <span className="text-[11px] text-green-400">{info}</span>}
              <button
                onClick={() => { setOverrides(originalOverrides); setInfo(''); }}
                disabled={!dirty || saving}
                className="btn-ghost text-xs disabled:opacity-30"
              >
                {t('settings.rules.overridesReset')}
              </button>
              <button
                onClick={handleSave}
                disabled={!dirty || saving}
                className="btn-primary text-xs disabled:opacity-50 whitespace-nowrap"
              >
                {saving ? '…' : t('settings.rules.overridesSave')}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

// ── SslSettings ───────────────────────────────────────────────────────────────

type SslMode = 'upload' | 'self-signed' | 'acme';
type UploadFormat = 'pem' | 'pfx';

function SslStatusBadge({ status }: { status: SslStatus }) {
  const { t } = useTranslation();
  if (!status.active || status.mode === 'none')
    return <span className="px-2 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">{t('settings.ssl.noTls')}</span>;
  const expiry = status.not_after ? new Date(status.not_after) : null;
  const daysLeft = expiry ? Math.ceil((expiry.getTime() - Date.now()) / 86400000) : null;
  const color = daysLeft == null ? 'green' : daysLeft < 14 ? 'red' : daysLeft < 30 ? 'yellow' : 'green';
  return (
    <span className={`px-2 py-0.5 text-[10px] rounded border ${
      color === 'green' ? 'bg-green-950/40 text-green-300 border-green-700/40' :
      color === 'yellow' ? 'bg-yellow-950/40 text-yellow-300 border-yellow-700/40' :
      'bg-red-950/40 text-red-300 border-red-700/40'
    }`}>
      {t('settings.ssl.tlsActive')} {daysLeft != null ? `· ${daysLeft}d` : ''}
    </span>
  );
}

function SslSettings() {
  const { t } = useTranslation();
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
      flash('ok', t('settings.ssl.hostnameSaved'));
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : t('common.errorGeneric'));
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
          if (!pfxFile) { flash('err', t('settings.ssl.pfxRequired')); setSaving(false); return; }
          s = await uploadSslPfx(pfxFile, pfxPassword);
        } else {
          if (!certFile || !keyFile) { flash('err', t('settings.ssl.certKeyRequired')); setSaving(false); return; }
          s = await uploadSslCert(certFile, keyFile, caFile ?? undefined);
        }
      } else if (mode === 'self-signed') {
        if (!ss.common_name) { flash('err', t('settings.ssl.cnRequired')); setSaving(false); return; }
        s = await applySslSelfSigned(ss);
      } else {
        if (!acme.email || acme.domains.length === 0) { flash('err', t('settings.ssl.emailDomainRequired')); setSaving(false); return; }
        s = await applySslAcme(acme);
      }
      setStatus(s);
      flash('ok', t('settings.ssl.savedOk'));
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : t('common.errorGeneric'));
    } finally {
      setSaving(false);
    }
  }

  const TAB_LABEL: Record<SslMode, string> = {
    'upload':      t('settings.ssl.tabUpload'),
    'self-signed': t('settings.ssl.tabSelfSigned'),
    'acme':        t('settings.ssl.tabAcme'),
  };

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.ssl.title')}</h2>
        {status && <SslStatusBadge status={status} />}
      </div>

      {/* Hostname */}
      <div className="rounded border border-slate-700/60 bg-slate-900/40 p-3 space-y-2">
        <p className="text-xs font-medium text-slate-300">{t('settings.ssl.serverHostname')}</p>
        <p className="text-[11px] text-slate-500">
          nginx <code className="font-mono text-slate-400">server_name</code> – {t('settings.ssl.serverHostnameHint')}
        </p>
        <div className="flex gap-2">
          <input
            className="input text-xs font-mono flex-1"
            placeholder={t('settings.ssl.hostnamePlaceholder')}
            value={hostname}
            onChange={e => setHostname(e.target.value)}
          />
          <button type="button" className="btn-ghost text-xs shrink-0"
            disabled={hostnameSaving}
            onClick={handleSaveHostname}>
            {hostnameSaving ? t('settings.users.savingShort') : t('common.save')}
          </button>
        </div>
      </div>

      {/* Aktuelles Zertifikat */}
      {status?.active && status.mode !== 'none' && (
        <div className="rounded-lg border border-slate-700/60 bg-slate-800/30 px-4 py-3 text-xs space-y-1">
          <p className="text-slate-400 font-medium">{t('settings.ssl.activeCert')}</p>
          {status.subject  && <p className="text-slate-300">Subject: <span className="font-mono">{status.subject}</span></p>}
          {status.issuer   && <p className="text-slate-500">Issuer: <span className="font-mono">{status.issuer}</span></p>}
          {status.not_after && <p className="text-slate-500">{t('settings.ssl.validUntil')}: {new Date(status.not_after).toLocaleDateString('de-DE')}</p>}
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
                {f === 'pem' ? t('settings.ssl.pemFiles') : 'PFX / PKCS#12'}
              </button>
            ))}
          </div>

          {uploadFormat === 'pem' ? (
            <>
              <p className="text-slate-500">{t('settings.ssl.pemHint')}</p>
              {[
                { label: t('settings.ssl.certFile'), set: setCertFile, accept: '.pem,.crt,.cer' },
                { label: t('settings.ssl.keyFile'), set: setKeyFile, accept: '.pem,.key' },
                { label: t('settings.ssl.caChain'), set: setCaFile, accept: '.pem,.crt,.cer' },
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
                {t('settings.ssl.pfxHint')}
              </p>
              <div className="flex flex-col gap-1">
                <label className="text-slate-400">{t('settings.ssl.pfxFile')}</label>
                <input type="file" accept=".pfx,.p12"
                  className="block text-slate-300 file:mr-3 file:py-1 file:px-3 file:rounded file:border-0 file:text-xs file:bg-slate-700 file:text-slate-200 hover:file:bg-slate-600 cursor-pointer"
                  onChange={e => setPfxFile(e.target.files?.[0] ?? null)} />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-slate-400">{t('settings.ssl.pfxPassword')}</label>
                <input className="input font-mono" type="password"
                  placeholder={t('settings.ssl.pfxPasswordPlaceholder')}
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
          <p className="text-slate-500">{t('settings.ssl.selfSignedHint')}</p>
          <div className="grid grid-cols-2 gap-3">
            <div className="flex flex-col gap-1 col-span-2">
              <label className="text-slate-400">{t('settings.ssl.commonName')}</label>
              <input className="input" placeholder="ids.local oder 192.168.1.79"
                value={ss.common_name} onChange={e => setSs(s => ({ ...s, common_name: e.target.value }))} />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">{t('settings.ssl.validityDays')}</label>
              <input className="input" type="number" min={1} max={3650}
                value={ss.days} onChange={e => setSs(s => ({ ...s, days: parseInt(e.target.value) || 365 }))} />
            </div>
            <div className="flex flex-col gap-1">
              <label className="text-slate-400">{t('settings.ssl.country')}</label>
              <input className="input" maxLength={2} placeholder="DE"
                value={ss.country ?? ''} onChange={e => setSs(s => ({ ...s, country: e.target.value }))} />
            </div>
            <div className="flex flex-col gap-1 col-span-2">
              <label className="text-slate-400">{t('settings.ssl.organization')}</label>
              <input className="input" placeholder="Cyjan IDS"
                value={ss.org ?? ''} onChange={e => setSs(s => ({ ...s, org: e.target.value }))} />
            </div>
          </div>
        </div>
      )}

      {/* ACME */}
      {mode === 'acme' && (
        <div className="space-y-3 text-xs">
          <p className="text-slate-500">{t('settings.ssl.acmeHint')}</p>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.ssl.emailRequired')}</label>
            <input className="input" type="email" placeholder="admin@example.com"
              value={acme.email} onChange={e => setAcme(a => ({ ...a, email: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.ssl.domainsRequired')}</label>
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
                {t('common.add')}
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
            <label className="text-slate-400">{t('settings.ssl.acmeDirUrl')}</label>
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
          {saving ? t('settings.ssl.applying') : t('settings.ssl.apply')}
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
  const { t } = useTranslation();
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
    try { await saveSyslogConfig(cfg); flash('ok', t('settings.saml.savedOk')); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : t('common.errorGeneric')); }
    finally { setSaving(false); }
  }

  async function handleTest() {
    if (!cfg.host) { flash('err', t('settings.syslog.enterHostFirst')); return; }
    setTesting(true);
    try {
      const r = await testSyslog({ host: cfg.host, port: cfg.port, protocol: cfg.protocol, format: cfg.format });
      flash('ok', r.message);
    } catch (err: unknown) { flash('err', err instanceof Error ? err.message : t('settings.syslog.testFailed')); }
    finally { setTesting(false); }
  }

  return (
    <form onSubmit={handleSave} className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.syslog.title')}</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-cyan-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
            {t('settings.syslog.exportEnabled')}
          </span>
        </label>
      </div>

      <p className="text-xs text-slate-500">
        {t('settings.syslog.intro')}
      </p>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 text-xs">
          <div className="flex flex-col gap-1 col-span-2">
            <label className="text-slate-400">{t('settings.syslog.hostLabel')}</label>
            <input className="input" placeholder={t('settings.syslog.hostPlaceholder')}
              value={cfg.host} onChange={e => setCfg(c => ({ ...c, host: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.syslog.port')}</label>
            <input className="input" type="number" min={1} max={65535}
              value={cfg.port} onChange={e => setCfg(c => ({ ...c, port: parseInt(e.target.value) || 514 }))} />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.syslog.protocol')}</label>
            <select className="input" value={cfg.protocol}
              onChange={e => setCfg(c => ({ ...c, protocol: e.target.value as 'udp' | 'tcp' }))}>
              <option value="udp">UDP</option>
              <option value="tcp">TCP</option>
            </select>
          </div>
        </div>

        <div className="grid grid-cols-2 gap-3 text-xs">
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.syslog.format')}</label>
            <select className="input" value={cfg.format}
              onChange={e => setCfg(c => ({ ...c, format: e.target.value as SyslogConfig['format'] }))}>
              <option value="rfc5424">{t('settings.syslog.formatRfc')}</option>
              <option value="cef">CEF (ArcSight / QRadar)</option>
              <option value="leef">LEEF (IBM QRadar)</option>
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.syslog.minSeverity')}</label>
            <select className="input" value={cfg.min_severity}
              onChange={e => setCfg(c => ({ ...c, min_severity: e.target.value as SyslogConfig['min_severity'] }))}>
              <option value="low">{t('settings.syslog.sevLow')}</option>
              <option value="medium">{t('settings.syslog.sevMedium')}</option>
              <option value="high">{t('settings.syslog.sevHigh')}</option>
              <option value="critical">{t('settings.syslog.sevCritical')}</option>
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
            {testing ? t('settings.syslog.testing') : t('settings.syslog.testConnection')}
          </button>
          <button type="submit" className="btn-primary text-xs" disabled={saving}>
            {saving ? t('settings.users.savingShort') : t('common.save')}
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
  const { t } = useTranslation();
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
    try { await saveItopConfig(cfg); flash('ok', t('settings.saml.savedOk')); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : t('common.errorGeneric')); }
    finally { setSaving(false); }
  }

  async function handleTest() {
    setTesting(true);
    try {
      const r = await testItopConnection();
      flash('ok', t('settings.itop.connectedOk', { orgs: r.organisations.join(', ') || t('settings.itop.noneParens') }));
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : t('settings.itop.connectionFailed'));
    } finally { setTesting(false); }
  }

  async function handleSync() {
    setSyncing(true);
    setSync(null);
    try {
      await triggerItopSync();
      startPolling();
    } catch (err: unknown) {
      flash('err', err instanceof Error ? err.message : t('settings.itop.startError'));
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
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.itop.title')}</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-cyan-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-cyan-300 font-medium' : 'text-slate-500'}>{t('settings.itop.active')}</span>
        </label>
      </div>

      <p className="text-xs text-slate-500">
        {t('settings.itop.intro1')} <span className="text-slate-300 font-mono">{t('settings.itop.knownNetworks')}</span> {t('settings.itop.intro2')} <span className="text-slate-300 font-mono">{t('settings.itop.hosts')}</span> {t('settings.itop.intro3')} <span className="text-slate-300 font-mono">trust_source = cmdb</span>.
      </p>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">

          <div className="flex flex-col gap-1 sm:col-span-3">
            <label className="text-slate-400">{t('settings.itop.itopUrl')}</label>
            <input className="input font-mono"
              placeholder="https://itop.firma.de"
              value={cfg.base_url}
              onChange={e => setCfg(c => ({ ...c, base_url: e.target.value }))} />
            <span className="text-[10px] text-slate-600">
              {t('settings.itop.baseUrlHint')}
            </span>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.itop.userRequired')}</label>
            <input className="input font-mono" autoComplete="off"
              value={cfg.user}
              onChange={e => setCfg(c => ({ ...c, user: e.target.value }))} />
          </div>

          <div className="flex flex-col gap-1 sm:col-span-2">
            <label className="text-slate-400">{t('settings.itop.passwordRequired')}</label>
            <div className="flex gap-2">
              <input className="input font-mono flex-1"
                type={showPw ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder={cfg.password ? '••••••••' : t('settings.itop.empty')}
                value={cfg.password}
                onChange={e => setCfg(c => ({ ...c, password: e.target.value }))} />
              <button type="button" className="btn-ghost text-xs"
                onClick={() => setShowPw(v => !v)}>
                {showPw ? t('settings.saml.hide') : t('settings.saml.show')}
              </button>
            </div>
          </div>

          <div className="flex flex-col gap-1 sm:col-span-2">
            <label className="text-slate-400">{t('settings.itop.orgFilter')}</label>
            <input className="input font-mono"
              placeholder={t('settings.itop.orgFilterPlaceholder')}
              value={cfg.org_filter}
              onChange={e => setCfg(c => ({ ...c, org_filter: e.target.value }))} />
            <span className="text-[10px] text-slate-600">
              {t('settings.itop.orgFilterHint')}
            </span>
          </div>

          <div className="flex items-end gap-2 pb-1">
            <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
              <input type="checkbox" className="accent-cyan-500"
                checked={cfg.ssl_verify}
                onChange={e => setCfg(c => ({ ...c, ssl_verify: e.target.checked }))} />
              <span className={cfg.ssl_verify ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
                {t('settings.itop.verifySsl')}
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
            {testing ? t('settings.syslog.testing') : t('settings.syslog.testConnection')}
          </button>
          <button type="button" className="btn-ghost text-xs"
            disabled={syncing || !cfg.enabled}
            onClick={handleSync}>
            {syncing ? t('settings.itop.syncing') : t('settings.itop.syncNow')}
          </button>
        </div>
        <div className="flex items-center gap-3">
          {msg?.type === 'ok'  && <span className="text-xs text-green-400">{msg.text}</span>}
          {msg?.type === 'err' && <span className="text-xs text-red-400">{msg.text}</span>}
          <button type="submit" className="btn-primary text-xs" disabled={saving}>
            {saving ? t('settings.users.savingShort') : t('common.save')}
          </button>
        </div>
      </div>

      {/* Sync-Status */}
      {sync && sync.phase !== 'idle' && (
        <div className="mt-2 rounded border border-slate-700 bg-slate-900/60 p-3 space-y-2">
          <div className="flex items-center justify-between text-xs">
            <span className={`font-mono font-medium ${phaseColor[sync.phase] ?? 'text-slate-400'}`}>
              {sync.phase === 'running' ? t('settings.itop.phaseRunning') : sync.phase === 'done' ? t('settings.itop.phaseDone') : sync.phase === 'error' ? t('common.errorGeneric') : sync.phase}
            </span>
            {sync.finished_at && (
              <span className="text-slate-600">{new Date(sync.finished_at).toLocaleTimeString()}</span>
            )}
          </div>

          {sync.phase === 'done' && sync.stats && (
            <div className="flex gap-4 text-xs text-slate-400">
              <span>{t('settings.itop.networks')}: <span className="text-slate-200">{sync.stats.networks_upserted ?? 0}</span></span>
              <span>{t('settings.itop.hostsLabel')}: <span className="text-slate-200">{sync.stats.hosts_upserted ?? 0}</span></span>
              {(sync.stats.networks_errors ?? 0) + (sync.stats.hosts_errors ?? 0) > 0 && (
                <span className="text-amber-400">
                  {t('common.errorGeneric')}: {(sync.stats.networks_errors ?? 0) + (sync.stats.hosts_errors ?? 0)}
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
  const { t } = useTranslation();
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
    try { await saveIrmaConfig(cfg); flash('ok', t('settings.irma.savedOk')); }
    catch (err: unknown) { flash('err', err instanceof Error ? err.message : t('common.errorGeneric')); }
    finally { setSaving(false); }
  }

  return (
    <form onSubmit={handleSave} className="space-y-5">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.irma.title')}</h2>
        <label className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input type="checkbox" className="accent-cyan-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))} />
          <span className={cfg.enabled ? 'text-cyan-300 font-medium' : 'text-slate-500'}>
            {t('settings.itop.active')}
          </span>
        </label>
      </div>

      <p className="text-xs text-slate-500">
        {t('settings.irma.intro1')} <span className="text-violet-300 font-mono">external</span>{t('settings.irma.intro2')}
      </p>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50' : ''}`}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3 text-xs">
          <div className="flex flex-col gap-1 sm:col-span-3">
            <label className="text-slate-400">{t('settings.irma.baseUrl')}</label>
            <input className="input font-mono"
              placeholder="https://10.133.168.115/rest"
              value={cfg.base_url}
              onChange={e => setCfg(c => ({ ...c, base_url: e.target.value }))} />
            <span className="text-[10px] text-slate-600">{t('settings.irma.baseUrlHint')}</span>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.itop.userRequired')}</label>
            <input className="input font-mono" autoComplete="off"
              value={cfg.user}
              onChange={e => setCfg(c => ({ ...c, user: e.target.value }))} />
          </div>
          <div className="flex flex-col gap-1 sm:col-span-2">
            <label className="text-slate-400">{t('settings.itop.passwordRequired')}</label>
            <div className="flex gap-2">
              <input
                className="input font-mono flex-1"
                type={showPw ? 'text' : 'password'}
                autoComplete="new-password"
                placeholder={cfg.password ? '••••••••' : t('settings.itop.empty')}
                value={cfg.password}
                onChange={e => setCfg(c => ({ ...c, password: e.target.value }))}
              />
              <button type="button"
                onClick={() => setShowPw(v => !v)}
                className="btn-ghost text-xs">
                {showPw ? t('settings.saml.hide') : t('settings.saml.show')}
              </button>
            </div>
          </div>

          <div className="flex flex-col gap-1">
            <label className="text-slate-400">{t('settings.irma.pollInterval')}</label>
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
                {t('settings.irma.verifyCert')}
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
            {saving ? t('settings.users.savingShort') : t('common.save')}
          </button>
        </div>
      </div>
    </form>
  );
}

// ── NetworkInterfaces ─────────────────────────────────────────────────────────

function StateDot({ state }: { state: string }) {
  const up = state === 'up';
  return (
    <span
      className={`inline-block w-2 h-2 rounded-full mr-1.5 flex-shrink-0 ${up ? 'bg-green-400' : 'bg-red-500'}`}
      title={state}
    />
  );
}

const ROLE_COLOR: Record<NonNullable<InterfaceInfo['role']>, string> = {
  management: 'bg-blue-900/40 text-blue-300 border-blue-700/50',
  sniffer:    'bg-purple-900/40 text-purple-300 border-purple-700/50',
};

function NetworkInterfaces() {
  const { t } = useTranslation();
  const ROLE_LABEL: Record<NonNullable<InterfaceInfo['role']>, string> = {
    management: t('settings.interfaces.roleManagement'),
    sniffer:    t('settings.interfaces.roleSniffer'),
  };
  const [ifaces,    setIfaces]    = useState<InterfaceInfo[]>([]);
  const [loading,   setLoading]   = useState(true);
  const [applying,  setApplying]  = useState<string | null>(null); // iface name being applied
  const [confirm,   setConfirm]   = useState<{ role: 'sniffer' | 'management'; iface: string } | null>(null);
  const [notice,    setNotice]    = useState<{ type: 'ok' | 'warn' | 'err'; msg: string } | null>(null);
  const [error,     setError]     = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try { setIfaces(await getInterfaces()); }
    catch (e) { setError(e instanceof Error ? e.message : String(e)); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function applyRole(role: 'sniffer' | 'management', iface: string) {
    setConfirm(null);
    setApplying(iface);
    setNotice(null);
    try {
      const res = await setInterfaceRole(role, iface);
      if (role === 'sniffer') {
        setNotice({ type: 'ok', msg: t('settings.interfaces.snifferSwitched', { iface }) });
        // Nach 6 s neu laden damit UI aktuellen Stand zeigt
        setTimeout(() => { load(); setNotice(null); }, 6000);
      } else {
        setNotice({ type: 'warn', msg: res.note ?? t('settings.interfaces.mgmtSaved', { iface }) });
        load();
      }
    } catch (e) {
      setNotice({ type: 'err', msg: e instanceof Error ? e.message : String(e) });
    } finally {
      setApplying(null);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">{t('settings.interfaces.title')}</h2>
        <button type="button" onClick={load} className="cyjan-btn-secondary text-xs px-2 py-1" disabled={loading}>
          {loading ? t('settings.interfaces.loadingShort') : t('settings.rules.refreshLabel')}
        </button>
      </div>

      {notice && (
        <div className={`text-xs px-3 py-2 rounded border ${
          notice.type === 'ok'   ? 'bg-green-950/40 border-green-700/50 text-green-300' :
          notice.type === 'warn' ? 'bg-yellow-950/40 border-yellow-700/50 text-yellow-300' :
                                   'bg-red-950/40 border-red-700/50 text-red-300'
        }`}>{notice.msg}</div>
      )}
      {error && <p className="text-xs text-red-400">{error}</p>}
      {!loading && ifaces.length === 0 && !error && (
        <p className="text-xs text-slate-500">{t('settings.interfaces.noneFound')}</p>
      )}

      <div className="space-y-2">
        {ifaces.map(iface => {
          // `roles` ist die neue Liste; `role` der Legacy-Einzelwert. Single-
          // NIC-Setups (Mgmt = Sniffer) lieferten unter dem alten Modell still
          // nur eine Rolle, jetzt sind beide Badges sichtbar.
          const roles = iface.roles ?? (iface.role ? [iface.role] : []);
          const isSniffer    = roles.includes('sniffer');
          const isManagement = roles.includes('management');
          return (
          <div
            key={iface.name}
            className={`rounded border p-3 text-xs transition-colors ${
              roles.length > 0 ? 'border-slate-600/80 bg-slate-800/60' : 'border-slate-700/50 bg-slate-900/40'
            }`}
          >
            {/* Header row */}
            <div className="flex items-center gap-2 mb-2.5">
              <StateDot state={iface.operstate} />
              <span className="font-mono font-semibold text-slate-100 text-sm">{iface.name}</span>
              {roles.map(r => (
                <span key={r} className={`px-1.5 py-0.5 rounded border text-[10px] ${ROLE_COLOR[r]}`}>
                  {ROLE_LABEL[r]}
                </span>
              ))}
              <span className={`ml-auto font-mono text-[10px] ${iface.operstate === 'up' ? 'text-green-400' : 'text-red-400'}`}>
                {iface.operstate.toUpperCase()}
              </span>
            </div>

            {/* Info row */}
            <div className="grid grid-cols-2 gap-x-4 gap-y-0.5 text-slate-400 mb-3">
              <div>
                <span className="text-slate-500">MAC </span>
                <span className="font-mono">{iface.mac || '—'}</span>
              </div>
              <div>
                <span className="text-slate-500">IP </span>
                {iface.addresses.length > 0
                  ? iface.addresses.map(a => (
                      <span key={a} className="font-mono text-slate-200 mr-2">{a}</span>
                    ))
                  : <span className="italic text-slate-600">
                      {isSniffer && !isManagement ? t('settings.interfaces.noneExpected') : t('settings.interfaces.none')}
                    </span>
                }
              </div>
            </div>

            {/* Action buttons */}
            {confirm?.iface === iface.name ? (
              <div className="flex items-center gap-2 pt-2 border-t border-slate-700/50">
                <span className="text-slate-400 flex-1">
                  {confirm.role === 'sniffer'
                    ? t('settings.interfaces.confirmSniffer', { iface: iface.name })
                    : t('settings.interfaces.confirmMgmt', { iface: iface.name })
                  }
                </span>
                <button
                  type="button"
                  onClick={() => applyRole(confirm.role, iface.name)}
                  className="cyjan-btn text-xs px-3 py-1"
                  disabled={!!applying}
                >
                  {applying === iface.name ? t('settings.interfaces.loadingShort') : t('settings.interfaces.yesSet')}
                </button>
                <button
                  type="button"
                  onClick={() => setConfirm(null)}
                  className="cyjan-btn-secondary text-xs px-3 py-1"
                >
                  {t('common.cancel')}
                </button>
              </div>
            ) : (
              <div className="flex gap-2 pt-2 border-t border-slate-700/40">
                <button
                  type="button"
                  disabled={isSniffer || !!applying}
                  onClick={() => setConfirm({ role: 'sniffer', iface: iface.name })}
                  className="cyjan-btn-secondary text-[11px] px-2 py-1 disabled:opacity-40 disabled:cursor-default"
                >
                  {t('settings.interfaces.setAsSniffer')}
                </button>
                <button
                  type="button"
                  disabled={isManagement || !!applying}
                  onClick={() => setConfirm({ role: 'management', iface: iface.name })}
                  className="cyjan-btn-secondary text-[11px] px-2 py-1 disabled:opacity-40 disabled:cursor-default"
                >
                  {t('settings.interfaces.setAsMgmt')}
                </button>
              </div>
            )}
          </div>
          );
        })}
      </div>

      <p className="text-[11px] text-slate-600">
        {t('settings.interfaces.footerHint')}
      </p>
    </div>
  );
}

// ── SystemUpdate ──────────────────────────────────────────────────────────────

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
  const { t } = useTranslation();
  const PHASE_LABEL: Record<SystemUpdateStatus['phase'], string> = {
    idle:       t('settings.update.phaseIdle'),
    extracting: t('settings.update.phaseExtracting'),
    loading:    t('settings.update.phaseLoading'),
    building:   t('settings.update.phaseBuilding'),
    restarting: t('settings.update.phaseRestarting'),
    done:       t('settings.update.phaseDone'),
    error:      t('common.errorGeneric'),
  };
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

  async function handleStart(force: boolean = false) {
    if (!file) return;
    setError(null);
    setUploading(true);
    setRestarting(false);
    try {
      await startSystemUpdate(file, pullImages, force);
      setStatus(s => ({ ...s, phase: 'extracting', log: [], progress: 0, started_at: new Date().toISOString() }));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setUploading(false);
    }
  }

  // Erkennt 400-Antworten vom Backend-Version-Check ('Downgrade abgelehnt'
  // oder 'kein Update notwendig') — nur dort macht der Force-Button Sinn.
  // Andere 4xx-/5xx-Errors (Validierung, Netzwerkschwund, Disk-Full)
  // sollen NICHT mit force erneut probieren.
  const errorAllowsForce = !!(error && /^400:/.test(error)
    && /(Downgrade|kein Update notwendig)/i.test(error));

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
          <h2 className="text-base font-semibold text-slate-100 mb-1">{t('settings.update.title')}</h2>
          <p className="text-sm text-slate-400">
            {t('settings.update.intro1')}
            <code className="text-xs bg-slate-800 px-1 rounded">.env</code>
            {t('settings.update.intro2')}
          </p>
        </div>
        {status.version && (
          <a
            href="https://github.com/JxxKal/ids/releases"
            target="_blank"
            rel="noreferrer"
            className="ml-6 shrink-0 flex flex-col items-end gap-0.5 group"
            title={t('settings.update.openReleases')}
          >
            <span className="text-[10px] uppercase tracking-wide text-slate-500">{t('settings.update.installedVersion')}</span>
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
            {file ? file.name : t('settings.update.chooseZip')}
          </span>
        </label>

        <button
          type="button"
          onClick={() => handleStart(false)}
          disabled={!file || isRunning || uploading}
          className="flex items-center gap-2 px-4 py-1.5 rounded text-sm font-medium
                     bg-cyan-700 hover:bg-cyan-600 text-white
                     disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
        >
          <Upload size={14} />
          {uploading ? t('settings.update.uploading') : t('settings.update.startUpdate')}
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
          {t('settings.update.pullImages')}
          <span className="ml-1 text-slate-600 text-xs">{t('settings.update.pullImagesHint')}</span>
        </span>
      </label>

      {error && (
        <div className="mt-3 space-y-2">
          <p className="text-sm text-red-400">{error}</p>
          {errorAllowsForce && (
            <button
              type="button"
              onClick={() => handleStart(true)}
              disabled={uploading || !file}
              className="px-3 py-1.5 rounded text-xs font-medium border border-amber-700/60 bg-amber-950/30 text-amber-200 hover:bg-amber-900/40 hover:text-amber-100 transition-colors disabled:opacity-50"
              title={t('settings.update.forceTitle')}
            >
              {t('settings.update.forceButton')}
            </button>
          )}
        </div>
      )}

      {/* Stack-Neustart */}
      <div className="mt-6 pt-5 border-t border-slate-700/60">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div>
            <p className="text-sm font-medium text-slate-200">{t('settings.update.restartStack')}</p>
            <p className="text-xs text-slate-500 mt-0.5">
              {t('settings.update.restartHint')}
            </p>
          </div>
          {confirmRestart ? (
            <div className="flex items-center gap-2">
              <span className="text-xs text-amber-300">{t('settings.update.confirmRestart')}</span>
              <button
                type="button"
                onClick={handleRestart}
                className="px-3 py-1 rounded text-xs font-medium bg-red-700 hover:bg-red-600 text-white transition-colors"
              >
                {t('settings.update.yesRestart')}
              </button>
              <button
                type="button"
                onClick={() => setConfirmRestart(false)}
                className="px-3 py-1 rounded text-xs font-medium bg-slate-700 hover:bg-slate-600 text-slate-300 transition-colors"
              >
                {t('common.cancel')}
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
              {t('settings.update.restart')}
            </button>
          )}
        </div>
      </div>

      {/* Restarting-Banner */}
      {restarting && (
        <div className="mt-4 flex items-center gap-2 rounded border border-amber-700/40 bg-amber-950/30 px-3 py-2">
          <span className="h-2 w-2 rounded-full bg-amber-400 animate-pulse shrink-0" />
          <span className="text-xs text-amber-300">
            {t('settings.update.apiRestarting')}
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

// ── SystemHealth ──────────────────────────────────────────────────────────────

function fmtBytes(bps: number | null): string {
  if (bps === null) return '…';
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbps`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbps`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(0)} Kbps`;
  return `${bps} bps`;
}

function GaugeBar({ pct, warn = 70, crit = 85 }: { pct: number | null; warn?: number; crit?: number }) {
  const { t } = useTranslation();
  if (pct === null) return <span className="text-slate-600 text-xs font-mono">{t('settings.systemHealth.calculating')}</span>;
  const bar = pct >= crit ? 'bg-red-500' : pct >= warn ? 'bg-amber-500' : 'bg-green-500';
  const txt = pct >= crit ? 'text-red-300' : pct >= warn ? 'text-amber-300' : 'text-green-300';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-slate-800 rounded-full overflow-hidden">
        <div className={`${bar} h-full rounded-full transition-all duration-500`} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
      <span className={`text-xs font-mono w-14 text-right tabular-nums ${txt}`}>{pct.toFixed(1)} %</span>
    </div>
  );
}

function StatRow({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[160px_1fr] items-center gap-3 py-2 border-b border-slate-800/50 last:border-0">
      <span className="text-[11px] text-slate-500 uppercase tracking-wider font-mono">{label}</span>
      <div>{children}</div>
    </div>
  );
}

function SystemHealth() {
  const { t } = useTranslation();
  const [stats,   setStats]   = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error,   setError]   = useState('');

  useEffect(() => {
    let alive = true;
    const load = () => {
      fetchSystemStats()
        .then(d => { if (alive) { setStats(d); setError(''); setLoading(false); } })
        .catch(() => { if (alive) { setError(t('settings.systemHealth.unavailable')); setLoading(false); } });
    };
    load();
    const ti = setInterval(load, 5000);
    return () => { alive = false; clearInterval(ti); };
  }, [t]);

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;
  if (error)   return <p className="text-red-400 text-sm">{error}</p>;
  if (!stats)  return null;

  const { cpu_pct, mem, disk, net, sniffer, iface } = stats;
  const dropWarn = sniffer.drop_pct !== null && sniffer.drop_pct > 1;
  const dropCrit = sniffer.drop_pct !== null && sniffer.drop_pct > 5;

  return (
    <div className="space-y-6">
      <h2 className="text-sm font-semibold text-slate-200">{t('settings.systemHealth.title')}</h2>

      {/* Warnbanner bei Paketverlusten */}
      {dropWarn && (
        <div className={`rounded-lg border px-4 py-3 text-xs ${
          dropCrit
            ? 'bg-red-950/40 border-red-700/50 text-red-300'
            : 'bg-amber-950/40 border-amber-700/50 text-amber-300'
        }`}>
          <p className="font-semibold mb-0.5">
            {dropCrit ? t('settings.systemHealth.dropCritBanner') : t('settings.systemHealth.dropWarnBanner')}
          </p>
          <p className="text-slate-400">
            {t('settings.systemHealth.dropRateMsg', { pct: sniffer.drop_pct?.toFixed(2) })}
          </p>
        </div>
      )}

      {/* Host */}
      <section>
        <p className="text-[11px] text-slate-500 uppercase tracking-wider font-mono mb-3">Host</p>
        <div className="space-y-1">
          <StatRow label="CPU">
            <GaugeBar pct={cpu_pct} />
          </StatRow>
          <StatRow label={`RAM (${mem.used_mb >= 1024 ? (mem.used_mb/1024).toFixed(1)+'GB' : mem.used_mb+'MB'} / ${mem.total_mb >= 1024 ? (mem.total_mb/1024).toFixed(0)+'GB' : mem.total_mb+'MB'})`}>
            <GaugeBar pct={mem.pct} />
          </StatRow>
          <StatRow label={`Disk (${disk.used_gb} GB / ${disk.total_gb} GB)`}>
            <GaugeBar pct={disk.pct} crit={90} />
          </StatRow>
        </div>
      </section>

      {/* Sniffer-Interface */}
      <section>
        <p className="text-[11px] text-slate-500 uppercase tracking-wider font-mono mb-3">
          {t('settings.systemHealth.snifferInterface')} {iface && <span className="text-cyan-600 normal-case">({iface})</span>}
        </p>
        {net ? (
          <div className="space-y-1">
            <StatRow label={t('settings.systemHealth.rxRate')}>
              <span className="text-slate-200 text-xs font-mono">{fmtBytes(net.rx_bps)}</span>
            </StatRow>
            <StatRow label={t('settings.systemHealth.txRate')}>
              <span className="text-slate-200 text-xs font-mono">{fmtBytes(net.tx_bps)}</span>
            </StatRow>
            <StatRow label={t('settings.systemHealth.rxPackets')}>
              <span className="text-slate-200 text-xs font-mono">{net.rx_pps !== null ? net.rx_pps.toLocaleString() : '…'} pps</span>
            </StatRow>
            <StatRow label={t('settings.systemHealth.ifDropsCum')}>
              <span className={`text-xs font-mono ${net.rx_dropped > 0 ? 'text-amber-300' : 'text-slate-400'}`}>
                {net.rx_dropped.toLocaleString()}
              </span>
            </StatRow>
          </div>
        ) : (
          <p className="text-slate-600 text-xs">{t('settings.systemHealth.noSnifferIface')}</p>
        )}
      </section>

      {/* Sniffer-Prozess */}
      <section>
        <p className="text-[11px] text-slate-500 uppercase tracking-wider font-mono mb-3">{t('settings.systemHealth.snifferProcess')}</p>
        <div className="space-y-1">
          <StatRow label={t('settings.systemHealth.captured')}>
            <span className="text-slate-200 text-xs font-mono">{sniffer.pps !== null ? `${sniffer.pps.toFixed(0)} pps` : '…'}</span>
          </StatRow>
          <StatRow label={t('settings.systemHealth.dropRate')}>
            <span className={`text-xs font-mono font-semibold ${
              dropCrit ? 'text-red-300' : dropWarn ? 'text-amber-300' : 'text-green-400'
            }`}>
              {sniffer.drop_pct !== null ? `${sniffer.drop_pct.toFixed(2)} %` : '…'}
            </span>
          </StatRow>
          <StatRow label={t('settings.systemHealth.totalCaptured')}>
            <span className="text-slate-400 text-xs font-mono">{sniffer.total_captured.toLocaleString()}</span>
          </StatRow>
          <StatRow label={t('settings.systemHealth.totalDropped')}>
            <span className={`text-xs font-mono ${sniffer.total_dropped > 0 ? 'text-amber-400' : 'text-slate-400'}`}>
              {sniffer.total_dropped.toLocaleString()}
            </span>
          </StatRow>
          <StatRow label={t('settings.systemHealth.kafkaErrors')}>
            <span className={`text-xs font-mono ${sniffer.kafka_errors > 0 ? 'text-red-400' : 'text-slate-400'}`}>
              {sniffer.kafka_errors}
            </span>
          </StatRow>
        </div>
      </section>

      <p className="text-[10px] text-slate-700 font-mono">{t('settings.systemHealth.refreshFooter')}</p>
    </div>
  );
}

// ── RuleOverridesSettings ───────────────────────────────────────────────────

const SEVERITY_OPTIONS: ('default' | 'critical' | 'high' | 'medium' | 'low')[] =
  ['default', 'critical', 'high', 'medium', 'low'];

function SeverityCell({
  rule, override, onChange,
}: {
  rule: SigRuleEntry;
  override: SigRuleOverride;
  onChange: (sev: SigRuleOverride['severity']) => void;
}) {
  const value = override.severity ?? 'default';
  const hasChange = override.severity != null;
  return (
    <select
      className={`input text-xs w-32 ${hasChange ? 'border-amber-600 text-amber-200' : ''}`}
      value={value}
      onChange={e => {
        const v = e.target.value;
        onChange(v === 'default' ? null : (v as SigRuleOverride['severity']));
      }}
    >
      {SEVERITY_OPTIONS.map(s => (
        <option key={s} value={s}>
          {s === 'default' ? `${rule.severity_default} (default)` : s}
        </option>
      ))}
    </select>
  );
}

// ── ML-Tuning-Card (Phase 5) ──────────────────────────────────────────────
//
// Status (state, Restzeit, sample-count) + Start/Pause/Resume + minimale
// Trainings-Konfig (window_s, blacklist). Wird oben in der RuleOverrides-
// Settings-Section gerendert. Polling alle 15s damit der State live mitwandert,
// sobald rule-tuner den training→tuning-Übergang macht.
function MlTuningCard({ ruleIds }: { ruleIds: string[] }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<MlTuningStatus | null>(null);
  const [error, setError]   = useState<string>('');
  const [busy, setBusy]     = useState(false);
  // Eingabe-Felder (in Stunden für UX, intern Sekunden)
  const [windowH, setWindowH] = useState<string>('10');
  const [blacklist, setBlacklist] = useState<string>('');

  const reload = () => {
    fetchMlStatus()
      .then(s => {
        setStatus(s);
        // Beim ersten Load die Felder aus der Config vorbefüllen.
        // window_s sind Sekunden; in Stunden anzeigen mit max. 2 Nachkommastellen,
        // damit Sub-Stunden-Werte (z.B. 60s aus einem Test) nicht zu '0' gerundet
        // werden und der User nicht denkt, das Feld sei kaputt.
        setWindowH(prev => {
          if (prev !== '10') return prev;  // user hat schon getippt — nicht überschreiben
          const hrs = (s.config.window_s ?? 36000) / 3600;
          return hrs >= 1 ? String(Math.round(hrs)) : hrs.toFixed(2);
        });
        setBlacklist(prev => prev === '' ? (s.config.blacklist ?? []).join(',') : prev);
      })
      .catch(e => setError(e instanceof Error ? e.message : String(e)));
  };

  useEffect(() => {
    reload();
    const id = window.setInterval(reload, 15_000);
    return () => window.clearInterval(id);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (!status) {
    return (
      <div className="bg-slate-900/40 border border-slate-700/40 rounded p-3 text-xs text-slate-500">
        {t('settings.ruleOverrides.mlTuning.loading')}{error ? ` … ${error}` : '…'}
      </div>
    );
  }

  const st = status.state.state;
  const stColor =
    st === 'training' ? 'text-cyan-300 bg-cyan-900/30 border-cyan-700/40'
  : st === 'tuning'   ? 'text-emerald-300 bg-emerald-900/30 border-emerald-700/40'
  : st === 'paused'   ? 'text-amber-300 bg-amber-900/30 border-amber-700/40'
  :                     'text-slate-400 bg-slate-800/40 border-slate-700/40';

  // Restzeit beim Training berechnen
  let trainingRest = '';
  if (st === 'training' && status.state.training_until) {
    const ms = new Date(status.state.training_until).getTime() - Date.now();
    if (ms > 0) {
      const h = Math.floor(ms / 3_600_000);
      const m = Math.floor((ms % 3_600_000) / 60_000);
      trainingRest = h > 0 ? `${h}h ${m}m` : `${m}m`;
    } else {
      trainingRest = t('settings.ruleOverrides.mlTuning.remainingNow');
    }
  }

  const lastTuning = status.state.last_tuning_at
    ? new Date(status.state.last_tuning_at).toLocaleString()
    : '–';

  const handleStart = async () => {
    setBusy(true); setError('');
    try {
      const wh = parseFloat(windowH);
      const blArr = blacklist.split(',').map(s => s.trim()).filter(Boolean);
      const payload: Record<string, unknown> = {};
      if (Number.isFinite(wh) && wh > 0) payload.window_s = Math.round(wh * 3600);
      payload.blacklist = blArr;
      const next = await startMlTraining(payload);
      setStatus(next);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally { setBusy(false); }
  };

  const handlePause  = async () => { setBusy(true); setError(''); try { setStatus(await pauseMlTuning()); } catch(e) { setError(String(e)); } finally { setBusy(false); } };
  const handleResume = async () => { setBusy(true); setError(''); try { setStatus(await resumeMlTuning()); } catch(e) { setError(String(e)); } finally { setBusy(false); } };

  return (
    <div className="bg-slate-900/40 border border-slate-700/40 rounded p-3 space-y-2">
      <div className="flex items-center gap-3 flex-wrap">
        <span className="text-xs font-semibold text-slate-300 uppercase tracking-wider">{t('settings.ruleOverrides.mlTuning.title')}</span>
        <span className={`text-[10px] font-mono px-2 py-0.5 rounded border ${stColor}`}>
          {st}
          {trainingRest && ` · ${t('settings.ruleOverrides.mlTuning.remaining', { value: trainingRest })}`}
        </span>
        <span className="text-[10px] text-slate-500">
          {t('settings.ruleOverrides.mlTuning.samples')} <span className="text-slate-300 tabular-nums">{status.total_samples.toLocaleString()}</span>
        </span>
        <span className="text-[10px] text-slate-500">
          {t('settings.ruleOverrides.mlTuning.lastTuning')} <span className="text-slate-400">{lastTuning}</span>
        </span>
      </div>

      <p className="text-[10px] text-slate-500 leading-relaxed">
        {t('settings.ruleOverrides.mlTuning.intro')}
      </p>

      <div className="flex gap-2 items-end flex-wrap">
        <label className="text-[10px] text-slate-400">
          <div>{t('settings.ruleOverrides.mlTuning.windowLabel')}</div>
          <input
            type="number"
            min={0.1}
            step="0.5"
            className="input text-xs w-20 font-mono"
            value={windowH}
            onChange={e => setWindowH(e.target.value)}
            disabled={busy}
          />
        </label>
        <label className="text-[10px] text-slate-400 flex-1 min-w-48">
          <div>{t('settings.ruleOverrides.mlTuning.blacklistLabel')}</div>
          <input
            type="text"
            className="input text-xs w-full font-mono"
            value={blacklist}
            placeholder={t('settings.ruleOverrides.mlTuning.blacklistPlaceholder')}
            onChange={e => setBlacklist(e.target.value)}
            disabled={busy}
            list="ml-blacklist-rules"
          />
          <datalist id="ml-blacklist-rules">
            {ruleIds.map(rid => <option key={rid} value={rid} />)}
          </datalist>
        </label>
        <div className="flex gap-1">
          {(st === 'idle' || st === 'paused' || st === 'tuning' || st === 'training') && (
            <button className="btn-primary text-xs" onClick={handleStart} disabled={busy}>
              {st === 'training' ? t('settings.ruleOverrides.mlTuning.btnRestart') : t('settings.ruleOverrides.mlTuning.btnStart')}
            </button>
          )}
          {(st === 'training' || st === 'tuning') && (
            <button className="btn-ghost text-xs" onClick={handlePause} disabled={busy}>{t('settings.ruleOverrides.mlTuning.btnPause')}</button>
          )}
          {st === 'paused' && (
            <button className="btn-primary text-xs" onClick={handleResume} disabled={busy}>{t('settings.ruleOverrides.mlTuning.btnResume')}</button>
          )}
        </div>
      </div>
      {error && <p className="text-[10px] text-red-400">{error}</p>}
    </div>
  );
}

// Helper: Param-Override hat zwei Formen — Skalar (manueller Wert) ODER
// Object {value, value_internal, source, ml} (vom rule-tuner gesetzt).
// extractValue normalisiert auf eine Zahl für Anzeige+Edit.
function extractParamValue(
  ov: number | SigRuleParamOverride | null | undefined,
): number | undefined {
  if (ov == null) return undefined;
  if (typeof ov === 'number') return ov;
  if (typeof ov === 'object' && typeof ov.value === 'number') return ov.value;
  return undefined;
}

function getParamSource(
  ov: number | SigRuleParamOverride | null | undefined,
): 'manual' | 'ml' | null {
  if (ov == null) return null;
  if (typeof ov === 'number') return 'manual';  // Skalar = impliziter manual-Lock
  if (typeof ov === 'object' && (ov.source === 'manual' || ov.source === 'ml')) return ov.source;
  return null;
}

function getParamValueInternal(
  ov: number | SigRuleParamOverride | null | undefined,
): number | null {
  if (ov && typeof ov === 'object' && typeof ov.value_internal === 'number') return ov.value_internal;
  return null;
}

function RuleOverridesSettings() {
  const { t } = useTranslation();
  const [rules, setRules]               = useState<SigRuleEntry[]>([]);
  const [overrides, setOverrides]       = useState<Record<string, SigRuleOverride>>({});
  const [originalOverrides, setOriginal] = useState<Record<string, SigRuleOverride>>({});
  const [search, setSearch]             = useState('');
  const [filter, setFilter]             = useState<'all' | 'enabled' | 'disabled' | 'changed'>('all');
  const [expanded, setExpanded]         = useState<Record<string, boolean>>({});
  // Roh-Text der aktuell editierten Parameter-Felder (key: `${rule_id}.${param_name}`).
  // Verhindert, dass beim Leeren des Inputs der Override sofort auf null zurückfällt
  // und das Feld dadurch wieder den Default anzeigt — der Edit-State lebt lokal,
  // bis das Feld blurred oder ein gültiger Wert eingegeben wird.
  const [editingParam, setEditingParam] = useState<Record<string, string>>({});
  const [error, setError]               = useState('');
  const [info, setInfo]                 = useState('');
  const [loading, setLoading]           = useState(true);
  const [saving, setSaving]             = useState(false);

  const load = () => {
    setLoading(true);
    Promise.all([fetchSigRules(), fetchSigRulesOverrides()])
      .then(([rs, ov]) => {
        setRules(rs);
        setOverrides(ov.overrides);
        setOriginal(ov.overrides);
      })
      .catch(e => setError(t('settings.ruleOverrides.loadError', { message: e instanceof Error ? e.message : String(e) })))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, []);

  const dirty = useMemo(() => {
    return JSON.stringify(overrides) !== JSON.stringify(originalOverrides);
  }, [overrides, originalOverrides]);

  const isEmptyOverride = (ov: SigRuleOverride) =>
    (ov.enabled === true || ov.enabled == null)
    && ov.severity == null
    && (!ov.parameters || Object.keys(ov.parameters).length === 0);

  const updateOverride = (rid: string, patch: Partial<SigRuleOverride>) => {
    setOverrides(prev => {
      const cur = prev[rid] ?? {};
      const next: SigRuleOverride = { ...cur, ...patch };
      const out = { ...prev };
      if (isEmptyOverride(next)) {
        delete out[rid];
      } else {
        out[rid] = next;
      }
      return out;
    });
    setInfo('');
  };

  // Schwellwert pro Rule+Parameter. Wenn der Wert wieder dem Default
  // entspricht, wird der Param-Eintrag entfernt — leere parameters-Map räumt
  // updateOverride später auf.
  const updateParam = (rule: SigRuleEntry, name: string, value: number | null) => {
    setOverrides(prev => {
      const cur = prev[rule.id] ?? {};
      const curParams = { ...(cur.parameters ?? {}) };
      const def = rule.parameters_default[name];
      if (value == null || Number.isNaN(value) || value === def) {
        delete curParams[name];
      } else {
        curParams[name] = value;
      }
      const next: SigRuleOverride = {
        ...cur,
        parameters: Object.keys(curParams).length > 0 ? curParams : undefined,
      };
      const out = { ...prev };
      if (isEmptyOverride(next)) {
        delete out[rule.id];
      } else {
        out[rule.id] = next;
      }
      return out;
    });
    setInfo('');
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setInfo('');
    try {
      const r = await saveSigRulesOverrides(overrides);
      setOverrides(r.overrides);
      setOriginal(r.overrides);
      setInfo(t('settings.ruleOverrides.saved'));
      // Reload rule list damit "Effective Severity"-Spalte stimmt
      const rs = await fetchSigRules();
      setRules(rs);
    } catch (e) {
      setError(t('settings.ruleOverrides.saveError', { message: e instanceof Error ? e.message : String(e) }));
    } finally {
      setSaving(false);
    }
  };

  const handleResetAll = () => {
    if (!confirm(t('settings.ruleOverrides.resetAllConfirm'))) return;
    setOverrides({});
  };

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return rules.filter(r => {
      const ov = overrides[r.id] ?? {};
      const isDisabled = ov.enabled === false;
      const hasParamOverride = ov.parameters && Object.keys(ov.parameters).length > 0;
      const hasChange  = ov.enabled === false || (ov.severity != null) || hasParamOverride;
      if (filter === 'enabled'  && isDisabled) return false;
      if (filter === 'disabled' && !isDisabled) return false;
      if (filter === 'changed'  && !hasChange) return false;
      if (q) {
        const hay = `${r.id} ${r.name} ${r.description} ${r.tags.join(' ')}`.toLowerCase();
        if (!hay.includes(q)) return false;
      }
      return true;
    });
  }, [rules, overrides, search, filter]);

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <h2 className="text-sm font-semibold text-slate-200">
          {t('settings.ruleOverrides.title')}
          <span className="ml-2 text-slate-500 font-normal">{rules.length}</span>
        </h2>
        <div className="flex items-center gap-2">
          <input
            className="input text-xs w-64"
            placeholder={t('settings.ruleOverrides.search')}
            value={search}
            onChange={e => setSearch(e.target.value)}
          />
          <select
            className="input text-xs w-32"
            value={filter}
            onChange={e => setFilter(e.target.value as typeof filter)}
          >
            <option value="all">{t('settings.ruleOverrides.filterAll')}</option>
            <option value="enabled">{t('settings.ruleOverrides.filterEnabled')}</option>
            <option value="disabled">{t('settings.ruleOverrides.filterDisabled')}</option>
            <option value="changed">{t('settings.ruleOverrides.filterChanged')}</option>
          </select>
        </div>
      </div>

      <p className="text-xs text-slate-500 leading-relaxed">{t('settings.ruleOverrides.intro')}</p>

      <MlTuningCard ruleIds={rules.map(r => r.id)} />

      <div className="text-[11px] text-slate-400 leading-relaxed bg-slate-900/40 border border-slate-700/40 rounded px-3 py-2">
        <Trans
          i18nKey="settings.ruleOverrides.scopeNote"
          values={{ count: rules.length }}
          components={{ strong: <strong className="text-slate-200" />, em: <em className="text-cyan-400 not-italic" /> }}
        />
      </div>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <div className="overflow-x-auto rounded-lg border border-slate-700/50">
        <table className="w-full text-xs">
          <thead className="bg-slate-900/60 border-b border-slate-700/50">
            <tr className="text-left text-slate-500">
              <th className="px-3 py-2">{t('settings.ruleOverrides.columns.id')}</th>
              <th className="px-3 py-2">{t('settings.ruleOverrides.columns.name')}</th>
              <th className="px-3 py-2 w-32">{t('settings.ruleOverrides.columns.default')}</th>
              <th className="px-3 py-2 w-40">{t('settings.ruleOverrides.columns.severity')}</th>
              <th className="px-3 py-2 w-16 text-center">{t('settings.ruleOverrides.columns.enabled')}</th>
              <th className="px-3 py-2">{t('settings.ruleOverrides.columns.file')}</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={6} className="text-center text-slate-600 py-6">{t('settings.ruleOverrides.noRules')}</td></tr>
            ) : filtered.map(r => {
              const ov = overrides[r.id] ?? {};
              const isOpen = !!expanded[r.id];
              // Phase 5: Row-Level Provenance-Indikator. Wenn IRGENDEIN
              // Param dieser Rule ml-source ODER manuellen Override hat,
              // zeigen wir das im Header — sonst muss der User aufklappen
              // um zu sehen ob eine Heuristik vom Tuner angefasst wurde.
              const ovParams = ov.parameters || {};
              let mlParamCount = 0;
              let manualParamCount = 0;
              for (const v of Object.values(ovParams)) {
                if (typeof v === 'object' && v !== null) {
                  if ((v as { source?: string }).source === 'ml') mlParamCount++;
                  else manualParamCount++;
                } else if (typeof v === 'number') {
                  manualParamCount++;
                }
              }
              return (
                <Fragment key={r.id}>
                  <tr
                    className={`border-b border-slate-800/40 cursor-pointer hover:bg-slate-800/20 ${ov.enabled === false ? 'opacity-50' : ''}`}
                    onClick={() => setExpanded(p => ({ ...p, [r.id]: !p[r.id] }))}
                  >
                    <td className="px-3 py-2 font-mono text-slate-300 whitespace-nowrap">
                      <span className="text-slate-600 mr-1">{isOpen ? '▾' : '▸'}</span>
                      {r.id}
                      {!r.builtin && <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-cyan-900/40 text-cyan-300 border border-cyan-700/40">CUSTOM</span>}
                      {mlParamCount > 0 && (
                        <span
                          className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-emerald-900/40 text-emerald-300 border border-emerald-700/40"
                          title={t('settings.ruleOverrides.badges.rowMlTooltip', { count: mlParamCount })}
                        >
                          {t('settings.ruleOverrides.badges.rowMlLabel', { count: mlParamCount })}
                        </span>
                      )}
                      {manualParamCount > 0 && (
                        <span
                          className="ml-1.5 text-[9px] px-1 py-0.5 rounded bg-amber-900/40 text-amber-300 border border-amber-700/40"
                          title={t('settings.ruleOverrides.badges.rowManualTooltip', { count: manualParamCount })}
                        >
                          {t('settings.ruleOverrides.badges.rowManualLabel', { count: manualParamCount })}
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-2 text-slate-300">{r.name}</td>
                    <td className="px-3 py-2 text-slate-500 font-mono">{r.severity_default}</td>
                    <td className="px-3 py-2" onClick={e => e.stopPropagation()}>
                      <SeverityCell
                        rule={r}
                        override={ov}
                        onChange={sev => updateOverride(r.id, { severity: sev })}
                      />
                    </td>
                    <td className="px-3 py-2 text-center" onClick={e => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        className="accent-cyan-500"
                        checked={ov.enabled !== false}
                        onChange={e => updateOverride(r.id, { enabled: e.target.checked ? null : false })}
                      />
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-600 text-[10px] truncate max-w-xs">{r.file}</td>
                  </tr>
                  {isOpen && (
                    <tr className="bg-slate-900/40 border-b border-slate-800/40">
                      <td colSpan={6} className="px-3 py-3 text-xs">
                        <p className="text-slate-400 mb-1">{r.description || '–'}</p>
                        {r.tags.length > 0 && (
                          <p className="text-[10px] text-slate-500 mb-2">
                            <span className="text-slate-600">{t('settings.ruleOverrides.tagsLabel')}</span>{' '}
                            {r.tags.map(tg => (
                              <span key={tg} className="inline-block px-1.5 py-0.5 mr-1 rounded bg-slate-800 border border-slate-700 text-slate-300 font-mono">{tg}</span>
                            ))}
                          </p>
                        )}
                        {Object.keys(r.parameters_schema).length > 0 && (
                          <div className="mt-2 border-t border-slate-800/60 pt-2">
                            <p className="text-[11px] font-semibold text-slate-300 mb-1">
                              {t('settings.ruleOverrides.thresholdsLabel')}
                            </p>
                            <p className="text-[10px] text-slate-500 mb-2">
                              {t('settings.ruleOverrides.thresholdsHint')}
                            </p>
                            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                              {Object.entries(r.parameters_schema).map(([pname, schema]) => {
                                const ovRaw = overrides[r.id]?.parameters?.[pname];
                                const ov = extractParamValue(ovRaw);
                                const ovSource = getParamSource(ovRaw);
                                const ovInternal = getParamValueInternal(ovRaw);
                                const eff = ov ?? r.parameters_default[pname] ?? schema.default;
                                const isOverridden = ov != null;
                                const rangeHint = schema.min != null && schema.max != null
                                  ? `${schema.min}–${schema.max}`
                                  : schema.min != null ? `≥ ${schema.min}`
                                  : schema.max != null ? `≤ ${schema.max}` : '';
                                const editKey = `${r.id}.${pname}`;
                                const displayValue = editKey in editingParam
                                  ? editingParam[editKey]
                                  : (Number.isFinite(eff) ? String(eff) : '');
                                return (
                                  <div key={pname} className="bg-slate-900/60 border border-slate-700/40 rounded px-2 py-1.5">
                                    <label className="block text-[10px] text-slate-400 mb-1">
                                      <span className="font-mono text-slate-300">{pname}</span>
                                      {schema.metric && (
                                        <span
                                          className="ml-1 inline-block text-[9px] px-1 py-0.5 rounded bg-slate-800 border border-slate-700 text-slate-400"
                                          title={t('settings.ruleOverrides.badges.tunableTooltip', { metric: schema.metric })}
                                        >
                                          {t('settings.ruleOverrides.badges.tunable')}
                                        </span>
                                      )}
                                      {ovSource === 'ml' && (
                                        <span
                                          className="ml-1 inline-block text-[9px] px-1 py-0.5 rounded bg-emerald-900/40 border border-emerald-700/40 text-emerald-300"
                                          title={t('settings.ruleOverrides.badges.mlTooltip')}
                                        >
                                          {t('settings.ruleOverrides.badges.ml')}
                                        </span>
                                      )}
                                      {ovSource === 'manual' && (
                                        <span
                                          className="ml-1 inline-block text-[9px] px-1 py-0.5 rounded bg-amber-900/40 border border-amber-700/40 text-amber-300"
                                          title={t('settings.ruleOverrides.badges.manualTooltip')}
                                        >
                                          {t('settings.ruleOverrides.badges.manual')}
                                        </span>
                                      )}
                                      {schema.label && <span className="ml-1 text-slate-500">— {schema.label}</span>}
                                    </label>
                                    <div className="flex items-center gap-2">
                                      <input
                                        type="number"
                                        step={schema.type === 'float' ? 'any' : '1'}
                                        min={schema.min ?? undefined}
                                        max={schema.max ?? undefined}
                                        className={`input text-xs w-32 font-mono ${isOverridden ? 'border-amber-600 text-amber-200' : ''}`}
                                        value={displayValue}
                                        onChange={e => {
                                          const raw = e.target.value;
                                          // Roh-Text immer halten — sonst rastet das Feld
                                          // beim Leeren auf den Default zurück.
                                          setEditingParam(prev => ({ ...prev, [editKey]: raw }));
                                          if (raw === '' || raw === '-') return;
                                          const n = schema.type === 'float' ? parseFloat(raw) : parseInt(raw, 10);
                                          if (Number.isFinite(n)) updateParam(r, pname, n);
                                        }}
                                        onBlur={() => {
                                          // Edit-State auflösen: beim nächsten Render gewinnt
                                          // wieder der canonisch formatierte eff-Wert.
                                          setEditingParam(prev => {
                                            if (!(editKey in prev)) return prev;
                                            const { [editKey]: _, ...rest } = prev;
                                            return rest;
                                          });
                                        }}
                                      />
                                      <button
                                        type="button"
                                        className="btn-ghost text-[10px] disabled:opacity-30"
                                        disabled={!isOverridden}
                                        onClick={() => {
                                          updateParam(r, pname, null);
                                          setEditingParam(prev => {
                                            if (!(editKey in prev)) return prev;
                                            const { [editKey]: _, ...rest } = prev;
                                            return rest;
                                          });
                                        }}
                                        title={t('settings.ruleOverrides.thresholdReset')}
                                      >
                                        ↺
                                      </button>
                                    </div>
                                    <p className="text-[9px] text-slate-600 mt-0.5 font-mono">
                                      default: {r.parameters_default[pname] ?? schema.default}
                                      {rangeHint && ` · range: ${rangeHint}`}
                                      {ovInternal != null && (
                                        <span className="ml-1 text-emerald-400">· {t('settings.ruleOverrides.badges.internalLabel')}: {ovInternal}</span>
                                      )}
                                    </p>
                                  </div>
                                );
                              })}
                            </div>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-3 pt-2">
        <span className="text-[10px] text-slate-600">{t('settings.ruleOverrides.applyHint')}</span>
        <div className="flex items-center gap-2">
          {info && <span className="text-[11px] text-green-400">{info}</span>}
          <button
            onClick={handleResetAll}
            disabled={Object.keys(overrides).length === 0}
            className="btn-ghost text-xs disabled:opacity-30"
          >
            {t('settings.ruleOverrides.resetAll')}
          </button>
          <button
            onClick={() => { setOverrides(originalOverrides); setInfo(''); }}
            disabled={!dirty || saving}
            className="btn-ghost text-xs disabled:opacity-30"
          >
            {t('settings.ruleOverrides.reset')}
          </button>
          <button
            onClick={handleSave}
            disabled={!dirty || saving}
            className="btn-primary text-xs disabled:opacity-50 whitespace-nowrap"
          >
            {saving ? '…' : t('settings.ruleOverrides.save')}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── RemoteTapsSettings ──────────────────────────────────────────────────────
//
// Master-seitige Verwaltung der Remote-Capture-Knoten. Listet die in der
// taps-Tabelle bekannten Knoten auf, bietet einen "Pairing-Token erzeugen"-
// Button (Modal mit Name/Site/TTL → Token wird genau einmal angezeigt) und
// einen Revoke-Action pro Tap. Die eigentliche Pair-Mechanik passiert dann
// am Tap-Wizard, der den Token plus Master-API-URL gegen den Pairing-Endpoint
// einlöst.

function RemoteTapsSettings() {
  const { t, i18n } = useTranslation();
  const [taps, setTaps] = useState<RemoteTap[] | null>(null);
  const [loadErr, setLoadErr] = useState<string>('');
  const [showAdd, setShowAdd] = useState(false);
  const [newToken, setNewToken] = useState<RemoteTapPairingToken | null>(null);
  const [revokeTarget, setRevokeTarget] = useState<RemoteTap | null>(null);
  const [revokeBusy, setRevokeBusy] = useState(false);
  const [tokenCopied, setTokenCopied] = useState(false);
  // Auto-Pairing: Pending-Liste + Audit-Log
  const [pending, setPending] = useState<PendingTap[]>([]);
  const [showAudit, setShowAudit] = useState(false);
  const [audit, setAudit] = useState<TapAuditEntry[]>([]);
  const [busy, setBusy] = useState<string | null>(null);  // pending_id wenn approve/reject läuft

  async function reload() {
    try {
      const [tapsList, pendingList] = await Promise.all([fetchTaps(), fetchPendingTaps()]);
      setTaps(tapsList);
      setPending(pendingList);
      setLoadErr('');
    } catch (exc) {
      setLoadErr(t('settings.remoteTaps.loadError', { message: String(exc) }));
    }
  }

  async function loadAudit() {
    try {
      setAudit(await fetchTapAuditLog(200));
    } catch (exc) {
      setLoadErr(t('settings.remoteTaps.loadError', { message: String(exc) }));
    }
  }

  async function doApprove(p: PendingTap) {
    setBusy(p.id);
    try {
      await approvePendingTap(p.id, {});
      await reload();
    } catch (exc) {
      alert(`Approve failed: ${exc}`);
    } finally {
      setBusy(null);
    }
  }
  async function doReject(p: PendingTap) {
    setBusy(p.id);
    try {
      await rejectPendingTap(p.id);
      await reload();
    } catch (exc) {
      alert(`Reject failed: ${exc}`);
    } finally {
      setBusy(null);
    }
  }

  useEffect(() => { void reload(); }, []);
  // Periodisches Refresh für last_seen + alerts_received-Spalten.
  useEffect(() => {
    const id = window.setInterval(() => { void reload(); }, 15_000);
    return () => window.clearInterval(id);
  }, []);

  function fmtRelative(iso: string | null | undefined): string {
    if (!iso) return t('settings.remoteTaps.never');
    const t0 = new Date(iso).getTime();
    if (Number.isNaN(t0)) return '–';
    const diff = (Date.now() - t0) / 1000;
    if (diff < 60)  return `${Math.round(diff)} s`;
    if (diff < 3600) return `${Math.round(diff / 60)} min`;
    if (diff < 86400) return `${Math.round(diff / 3600)} h`;
    return `${Math.round(diff / 86400)} d`;
  }

  function fmtAbs(iso: string): string {
    return new Date(iso).toLocaleString(i18n.resolvedLanguage ?? 'de');
  }

  async function copyToken() {
    if (!newToken) return;
    let ok = false;
    // Moderne Clipboard-API funktioniert nur auf HTTPS / localhost. Master-
    // Frontend läuft typisch über HTTP im LAN, dann fällt das schon im
    // Permissions-Check durch. Daher zuerst die alte execCommand-Methode
    // probieren – die funktioniert ohne Secure-Context.
    try {
      const ta = document.createElement('textarea');
      ta.value = newToken.token;
      // außerhalb des Viewports parken, sonst scrollt manche Browser
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      ta.style.top = '0';
      ta.setAttribute('readonly', '');
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      // execCommand ist deprecated aber als Fallback einer der wenigen
      // verlässlichen Wege auf HTTP. Auf modernen Browsern weiterhin
      // verfügbar.
      ok = document.execCommand('copy');
      document.body.removeChild(ta);
    } catch {
      ok = false;
    }
    if (!ok && navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(newToken.token);
        ok = true;
      } catch { ok = false; }
    }
    if (ok) {
      setTokenCopied(true);
      window.setTimeout(() => setTokenCopied(false), 2500);
    }
    // Wenn beide Wege fehlschlagen: Token ist sichtbar, User kann manuell
    // markieren+kopieren. Kein Datenverlust.
  }

  async function doRevoke() {
    if (!revokeTarget) return;
    setRevokeBusy(true);
    try {
      await revokeTap(revokeTarget.id);
      setRevokeTarget(null);
      await reload();
    } catch (exc) {
      alert(t('settings.remoteTaps.revokeError', { message: String(exc) }));
    } finally {
      setRevokeBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-sm font-semibold text-slate-200">{t('settings.remoteTaps.title')}</h2>
          <p className="text-xs text-slate-400 mt-1 max-w-3xl">{t('settings.remoteTaps.intro')}</p>
        </div>
        <button
          onClick={() => setShowAdd(true)}
          className="px-3 py-1.5 rounded text-xs font-medium bg-cyan-600/30 text-cyan-100 border border-cyan-500/50 hover:bg-cyan-600/40 whitespace-nowrap"
        >
          + {t('settings.remoteTaps.addBtn')}
        </button>
      </div>

      {loadErr && <div className="text-xs text-red-400">{loadErr}</div>}

      {/* ── Pending Auto-Pair-Anfragen ─────────────────────────────────── */}
      {pending.length > 0 && (
        <div className="rounded-lg border border-amber-500/40 bg-amber-900/10 p-3 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-amber-300 uppercase tracking-wider">
              {t('settings.remoteTaps.pending.title', { count: pending.length })}
            </h3>
            <span className="text-[10px] font-mono text-amber-400/70">{t('settings.remoteTaps.pending.subtitle')}</span>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-slate-400 border-b border-amber-700/30">
                  <th className="text-left px-2 py-1.5">{t('settings.remoteTaps.pending.colName')}</th>
                  <th className="text-left px-2 py-1.5">{t('settings.remoteTaps.pending.colSourceIp')}</th>
                  <th className="text-left px-2 py-1.5">{t('settings.remoteTaps.pending.colHostname')}</th>
                  <th className="text-left px-2 py-1.5">{t('settings.remoteTaps.pending.colVersion')}</th>
                  <th className="text-left px-2 py-1.5">{t('settings.remoteTaps.pending.colFingerprint')}</th>
                  <th className="text-left px-2 py-1.5">{t('settings.remoteTaps.pending.colAnnouncedAt')}</th>
                  <th className="text-right px-2 py-1.5">{t('settings.remoteTaps.pending.colActions')}</th>
                </tr>
              </thead>
              <tbody>
                {pending.map(p => (
                  <tr key={p.id} className="border-b border-amber-700/20">
                    <td className="px-2 py-1.5 font-mono text-cyan-300">{p.name}</td>
                    <td className="px-2 py-1.5 font-mono text-slate-300">{p.source_ip}</td>
                    <td className="px-2 py-1.5 text-slate-300">{p.hostname || '–'}</td>
                    <td className="px-2 py-1.5 font-mono text-slate-400">{p.version || '–'}</td>
                    <td className="px-2 py-1.5 font-mono text-slate-500" title={p.fingerprint}>
                      {p.fingerprint.slice(0, 12)}…
                    </td>
                    <td className="px-2 py-1.5 font-mono text-slate-400" title={fmtAbs(p.announced_at)}>
                      {fmtRelative(p.announced_at)}
                    </td>
                    <td className="px-2 py-1.5 text-right space-x-1">
                      <button
                        type="button"
                        disabled={busy === p.id}
                        onClick={() => doApprove(p)}
                        className="px-2 py-1 rounded text-[11px] bg-green-900/30 text-green-300 border border-green-700/40 hover:bg-green-900/50 disabled:opacity-50"
                      >
                        {busy === p.id ? '…' : t('settings.remoteTaps.pending.approve')}
                      </button>
                      <button
                        type="button"
                        disabled={busy === p.id}
                        onClick={() => doReject(p)}
                        className="px-2 py-1 rounded text-[11px] bg-red-900/30 text-red-300 border border-red-700/40 hover:bg-red-900/50 disabled:opacity-50"
                      >
                        {busy === p.id ? '…' : t('settings.remoteTaps.pending.reject')}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="flex items-center gap-2">
        <button
          type="button"
          onClick={() => { setShowAudit(s => !s); if (!showAudit) void loadAudit(); }}
          className="px-2 py-1 rounded text-[11px] border border-slate-700 text-slate-400 hover:text-slate-200 hover:border-slate-500"
        >
          {showAudit ? t('settings.remoteTaps.audit.hide') : t('settings.remoteTaps.audit.show')}
        </button>
        {showAudit && (
          <button
            type="button"
            onClick={() => void loadAudit()}
            className="text-[11px] text-cyan-400 hover:text-cyan-200"
          >
            ↻ {t('settings.remoteTaps.audit.refresh')}
          </button>
        )}
      </div>

      {showAudit && (
        <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-3">
          <h3 className="text-xs font-semibold text-slate-300 uppercase tracking-wider mb-2">
            {t('settings.remoteTaps.audit.title')}
          </h3>
          {audit.length === 0 ? (
            <p className="text-xs text-slate-500 italic">{t('settings.remoteTaps.audit.empty')}</p>
          ) : (
            <div className="overflow-x-auto max-h-96">
              <table className="w-full text-[11px]">
                <thead className="sticky top-0 bg-slate-900/95">
                  <tr className="text-slate-500 border-b border-slate-700/40">
                    <th className="text-left px-2 py-1">{t('settings.remoteTaps.audit.colTs')}</th>
                    <th className="text-left px-2 py-1">{t('settings.remoteTaps.audit.colEvent')}</th>
                    <th className="text-left px-2 py-1">{t('settings.remoteTaps.audit.colSourceIp')}</th>
                    <th className="text-left px-2 py-1">{t('settings.remoteTaps.audit.colName')}</th>
                    <th className="text-left px-2 py-1">{t('settings.remoteTaps.audit.colDetails')}</th>
                  </tr>
                </thead>
                <tbody>
                  {audit.map(a => {
                    const isReject = a.event.startsWith('rejected');
                    const isApprove = a.event === 'approved';
                    const evColor = isReject ? 'text-red-400' : isApprove ? 'text-green-400' : 'text-slate-400';
                    return (
                      <tr key={a.id} className="border-b border-slate-800/40">
                        <td className="px-2 py-1 font-mono text-slate-500 whitespace-nowrap">
                          {new Date(a.ts).toLocaleString(i18n.resolvedLanguage ?? 'de')}
                        </td>
                        <td className={`px-2 py-1 font-mono ${evColor}`}>{a.event}</td>
                        <td className="px-2 py-1 font-mono text-slate-400">{a.source_ip ?? '–'}</td>
                        <td className="px-2 py-1 text-slate-300">{a.name ?? '–'}</td>
                        <td className="px-2 py-1 font-mono text-slate-500 truncate max-w-md">
                          {Object.keys(a.details).length === 0 ? '' : JSON.stringify(a.details)}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {taps && taps.length === 0 && (
        <div className="text-xs text-slate-500 italic">{t('settings.remoteTaps.noTaps')}</div>
      )}

      {taps && taps.length > 0 && (
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-slate-400 border-b border-slate-700">
                <th className="text-left px-3 py-2">{t('settings.remoteTaps.colName')}</th>
                <th className="text-left px-3 py-2">{t('settings.remoteTaps.colSite')}</th>
                <th className="text-left px-3 py-2">{t('settings.remoteTaps.colStatus')}</th>
                <th className="text-left px-3 py-2">{t('settings.remoteTaps.colLastSeen')}</th>
                <th className="text-right px-3 py-2">{t('settings.remoteTaps.colAlerts')}</th>
                <th className="text-left px-3 py-2">{t('settings.remoteTaps.colCertExpires')}</th>
                <th className="text-right px-3 py-2">{t('settings.remoteTaps.colActions')}</th>
              </tr>
            </thead>
            <tbody>
              {taps.map(tap => {
                const isActive = tap.status === 'active';
                return (
                  <tr key={tap.id} className="border-b border-slate-800/60">
                    <td className="px-3 py-2 font-mono text-cyan-300">{tap.name}</td>
                    <td className="px-3 py-2 text-slate-400">{tap.site || '–'}</td>
                    <td className="px-3 py-2">
                      {isActive
                        ? <span className="px-1.5 py-0.5 text-[10px] rounded bg-green-900/50 text-green-300 border border-green-700/40">{t('settings.remoteTaps.statusActive')}</span>
                        : <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">{t('settings.remoteTaps.statusRevoked')}</span>}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-300" title={tap.last_seen ? fmtAbs(tap.last_seen) : ''}>
                      {fmtRelative(tap.last_seen)}
                    </td>
                    <td className="px-3 py-2 text-right font-mono text-slate-300">
                      {tap.alerts_received.toLocaleString()}
                    </td>
                    <td className="px-3 py-2 font-mono text-slate-400">
                      {fmtAbs(tap.cert_expires_at)}
                    </td>
                    <td className="px-3 py-2 text-right">
                      {isActive && (
                        <button
                          onClick={() => setRevokeTarget(tap)}
                          className="px-2 py-1 rounded text-[11px] bg-red-900/30 text-red-300 border border-red-700/40 hover:bg-red-900/50"
                        >
                          {t('settings.remoteTaps.revoke')}
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}

      {showAdd && (
        <CreateTapTokenModal
          onClose={() => setShowAdd(false)}
          onCreated={tok => { setNewToken(tok); setShowAdd(false); void reload(); }}
        />
      )}

      {newToken && (
        <ShowTokenModal
          token={newToken}
          copied={tokenCopied}
          onCopy={copyToken}
          onClose={() => setNewToken(null)}
        />
      )}

      {revokeTarget && (
        <ConfirmDialog
          message={`${t('settings.remoteTaps.revokeConfirmTitle')}\n\n${t('settings.remoteTaps.revokeConfirmBody', { name: revokeTarget.name })}`}
          confirmLabel={revokeBusy ? '…' : t('settings.remoteTaps.revoke')}
          onConfirm={doRevoke}
          onCancel={() => { if (!revokeBusy) setRevokeTarget(null); }}
        />
      )}
    </div>
  );
}

function CreateTapTokenModal({
  onClose, onCreated,
}: {
  onClose: () => void;
  onCreated: (tok: RemoteTapPairingToken) => void;
}) {
  const { t } = useTranslation();
  const [name, setName] = useState('');
  const [site, setSite] = useState('');
  const [ttl,  setTtl]  = useState(60);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!name.trim()) return;
    setBusy(true);
    try {
      const tok = await createTapPairingToken({
        name: name.trim(),
        site: site.trim() || undefined,
        ttl_min: ttl,
      });
      onCreated(tok);
    } catch (exc) {
      alert(t('settings.remoteTaps.createError', { message: String(exc) }));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-slate-900 border border-slate-700 rounded-lg p-5 w-[420px] max-w-[92vw] shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <h3 className="text-sm font-semibold text-slate-100 mb-3">{t('settings.remoteTaps.addModalTitle')}</h3>

        <div className="space-y-3 text-xs">
          <label className="block">
            <div className="text-slate-400 mb-1">{t('settings.remoteTaps.addNameLabel')}</div>
            <input
              autoFocus
              type="text"
              value={name}
              onChange={e => setName(e.target.value)}
              placeholder={t('settings.remoteTaps.addNamePlaceholder')}
              className="input w-full"
            />
          </label>
          <label className="block">
            <div className="text-slate-400 mb-1">{t('settings.remoteTaps.addSiteLabel')}</div>
            <input
              type="text"
              value={site}
              onChange={e => setSite(e.target.value)}
              placeholder={t('settings.remoteTaps.addSitePlaceholder')}
              className="input w-full"
            />
          </label>
          <label className="block">
            <div className="text-slate-400 mb-1">{t('settings.remoteTaps.addTtlLabel')}</div>
            <input
              type="number"
              min={5}
              max={1440}
              value={ttl}
              onChange={e => setTtl(Math.max(5, Math.min(1440, Number(e.target.value) || 60)))}
              className="input w-full"
            />
          </label>
        </div>

        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onClose} className="px-3 py-1.5 rounded text-xs text-slate-400 hover:text-slate-200">
            {t('settings.remoteTaps.addCancel')}
          </button>
          <button
            onClick={submit}
            disabled={busy || !name.trim()}
            className="px-3 py-1.5 rounded text-xs bg-cyan-600 text-white disabled:opacity-50"
          >
            {t('settings.remoteTaps.addCreate')}
          </button>
        </div>
      </div>
    </div>
  );
}

function ShowTokenModal({
  token, copied, onCopy, onClose,
}: {
  token: RemoteTapPairingToken;
  copied: boolean;
  onCopy: () => void;
  onClose: () => void;
}) {
  const { t, i18n } = useTranslation();
  const masterUrl =
    typeof window !== 'undefined'
      ? `${window.location.protocol}//${window.location.host}`
      : '';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div
        className="bg-slate-900 border border-cyan-700/60 rounded-lg p-5 w-[560px] max-w-[94vw] shadow-2xl"
        onClick={e => e.stopPropagation()}
      >
        <h3 className="text-sm font-semibold text-cyan-200 mb-3">{t('settings.remoteTaps.tokenModalTitle')}</h3>
        <p className="text-xs text-slate-300 mb-3">
          {t('settings.remoteTaps.tokenInstruction', { url: masterUrl })}
        </p>

        <div className="bg-slate-950 border border-slate-700 rounded p-3 font-mono text-[11px] text-cyan-200 break-all select-all">
          {token.token}
        </div>

        <div className="text-[11px] text-slate-500 mt-2">
          {t('settings.remoteTaps.tokenExpires', { when: new Date(token.expires_at).toLocaleString(i18n.resolvedLanguage ?? 'de') })}
        </div>

        <div className="flex justify-end gap-2 mt-4">
          <button onClick={onCopy} className="px-3 py-1.5 rounded text-xs bg-slate-700 text-slate-100 hover:bg-slate-600">
            {copied ? t('settings.remoteTaps.tokenCopied') : t('settings.remoteTaps.tokenCopy')}
          </button>
          <button onClick={onClose} className="px-3 py-1.5 rounded text-xs bg-cyan-600 text-white">
            {t('settings.remoteTaps.tokenClose')}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── EgressPrioritySettings ───────────────────────────────────────────────────

// 7 echte Klassifikations-Tupel für die Egress-View (✓✓✓ ist nicht-egress).
const BOUNDARY_TUPLES: { key: string; net: boolean; src: boolean; dst: boolean }[] = [
  { key: '000', net: false, src: false, dst: false },
  { key: '010', net: false, src: true,  dst: false },
  { key: '001', net: false, src: false, dst: true  },
  { key: '100', net: true,  src: false, dst: false },
  { key: '011', net: false, src: true,  dst: true  },
  { key: '101', net: true,  src: false, dst: true  },
  { key: '110', net: true,  src: true,  dst: false },
];

const DEFAULT_PRIORITY_MAP: Record<string, string | null> = {
  '000': 'P0',
  '010': 'P1',
  '001': 'P1',
  '100': 'P2',
  '011': 'P2',
  '101': 'P3',
  '110': 'P3',
};

function EgressPrioritySettings() {
  const { t } = useTranslation();
  const [map, setMap]               = useState<Record<string, string | null>>(DEFAULT_PRIORITY_MAP);
  const [originalMap, setOriginal]  = useState<Record<string, string | null>>(DEFAULT_PRIORITY_MAP);
  const [loading, setLoading]       = useState(true);
  const [saving, setSaving]         = useState(false);
  const [error, setError]           = useState('');
  const [info, setInfo]             = useState('');

  useEffect(() => {
    let alive = true;
    fetchBoundaryPriorityMap()
      .then(value => {
        if (!alive) return;
        if (value) {
          const merged = { ...DEFAULT_PRIORITY_MAP };
          for (const tup of BOUNDARY_TUPLES) {
            if (tup.key in value) merged[tup.key] = value[tup.key];
          }
          setMap(merged);
          setOriginal(merged);
        }
      })
      .catch(() => { /* erste Nutzung – Default bleibt */ })
      .finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, []);

  const dirty = useMemo(() => JSON.stringify(map) !== JSON.stringify(originalMap), [map, originalMap]);

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setInfo('');
    try {
      await saveBoundaryPriorityMap(map);
      setOriginal(map);
      setInfo(t('settings.egressPriorities.saved'));
    } catch (e) {
      setError(t('settings.egressPriorities.saveError', { message: e instanceof Error ? e.message : String(e) }));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-semibold text-slate-200">{t('settings.egressPriorities.title')}</h2>
      <p className="text-xs text-slate-500 leading-relaxed">{t('settings.egressPriorities.intro')}</p>

      {error && <p className="text-xs text-red-400">{error}</p>}

      <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 overflow-hidden">
        <table className="w-full text-xs">
          <thead className="bg-slate-900/60 border-b border-slate-700/50">
            <tr className="text-left text-slate-500">
              <th className="px-3 py-2">{t('settings.egressPriorities.colNet')}</th>
              <th className="px-3 py-2">{t('settings.egressPriorities.colSrc')}</th>
              <th className="px-3 py-2">{t('settings.egressPriorities.colDst')}</th>
              <th className="px-3 py-2 w-32">{t('settings.egressPriorities.colPriority')}</th>
              <th className="px-3 py-2">{t('settings.egressPriorities.colMeaning')}</th>
            </tr>
          </thead>
          <tbody>
            {BOUNDARY_TUPLES.map(tup => {
              const cur = map[tup.key];
              const def = DEFAULT_PRIORITY_MAP[tup.key];
              const changed = cur !== def;
              return (
                <tr key={tup.key} className="border-b border-slate-800/40">
                  <td className="px-3 py-2 font-mono">{tup.net ? <span className="text-green-400">✓</span> : <span className="text-red-400">✗</span>}</td>
                  <td className="px-3 py-2 font-mono">{tup.src ? <span className="text-green-400">✓</span> : <span className="text-red-400">✗</span>}</td>
                  <td className="px-3 py-2 font-mono">{tup.dst ? <span className="text-green-400">✓</span> : <span className="text-red-400">✗</span>}</td>
                  <td className="px-3 py-2">
                    <select
                      className={`input text-xs w-24 ${changed ? 'border-amber-600 text-amber-200' : ''}`}
                      value={cur ?? ''}
                      onChange={e => setMap(p => ({ ...p, [tup.key]: e.target.value || null }))}
                    >
                      <option value="">—</option>
                      <option value="P0">P0</option>
                      <option value="P1">P1</option>
                      <option value="P2">P2</option>
                      <option value="P3">P3</option>
                    </select>
                  </td>
                  <td className="px-3 py-2 text-slate-400">{t(`settings.egressPriorities.tuples.${tup.key}`)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-3">
        <span className="text-[10px] text-slate-600">{t('settings.egressPriorities.applyHint')}</span>
        <div className="flex items-center gap-2">
          {info && <span className="text-[11px] text-green-400">{info}</span>}
          <button onClick={() => { setMap(DEFAULT_PRIORITY_MAP); setInfo(''); }}
            className="btn-ghost text-xs">
            {t('settings.egressPriorities.reset')}
          </button>
          <button onClick={handleSave} disabled={!dirty || saving}
            className="btn-primary text-xs disabled:opacity-50">
            {saving ? '…' : t('common.save')}
          </button>
        </div>
      </div>
    </div>
  );
}

// ── DnsResolverSettings ─────────────────────────────────────────────────────

// Akzeptiert IPv4, IPv6 und CIDR-Notation (kein vollständiger Validator – nur
// "Plausibilitäts-Check"-Heuristik, der echte Validator sitzt im alert-manager
// via ipaddress.ip_network).
function isLikelyIpOrCidr(s: string): boolean {
  const trimmed = s.trim();
  if (!trimmed) return false;
  // IPv4 (mit oder ohne /N)
  if (/^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/.test(trimmed)) return true;
  // IPv6 (sehr grob – mind. ein Doppelpunkt + Hex/`::`/Slash)
  if (/^[0-9a-fA-F:]+(\/\d{1,3})?$/.test(trimmed) && trimmed.includes(':')) return true;
  return false;
}

function DnsResolverSettings() {
  const { t } = useTranslation();
  const [resolvers, setResolvers] = useState<string[]>([]);
  const [draft, setDraft]         = useState('');
  const [error, setError]         = useState('');
  const [info, setInfo]           = useState('');
  const [loading, setLoading]     = useState(true);
  const [saving, setSaving]       = useState(false);
  const [dirty, setDirty]         = useState(false);

  useEffect(() => {
    let alive = true;
    fetchDnsResolvers()
      .then(r => { if (alive) { setResolvers(r.resolvers); setLoading(false); } })
      .catch(e => {
        if (alive) {
          setError(t('settings.dnsResolvers.loadError', { message: e instanceof Error ? e.message : String(e) }));
          setLoading(false);
        }
      });
    return () => { alive = false; };
  }, [t]);

  const handleAdd = () => {
    setError('');
    setInfo('');
    const v = draft.trim();
    if (!isLikelyIpOrCidr(v)) {
      setError(t('settings.dnsResolvers.invalidEntry'));
      return;
    }
    if (resolvers.includes(v)) {
      setError(t('settings.dnsResolvers.duplicate'));
      return;
    }
    setResolvers(prev => [...prev, v]);
    setDraft('');
    setDirty(true);
  };

  const handleRemove = (ip: string) => {
    setResolvers(prev => prev.filter(x => x !== ip));
    setDirty(true);
    setInfo('');
  };

  const handleSave = async () => {
    setSaving(true);
    setError('');
    setInfo('');
    try {
      await saveDnsResolvers({ resolvers });
      setInfo(t('settings.dnsResolvers.saved'));
      setDirty(false);
    } catch (e) {
      setError(t('settings.dnsResolvers.saveError', { message: e instanceof Error ? e.message : String(e) }));
    } finally {
      setSaving(false);
    }
  };

  if (loading) return <p className="text-slate-500 text-sm">{t('common.loading')}</p>;

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-semibold text-slate-200">{t('settings.dnsResolvers.title')}</h2>

      <p className="text-xs text-slate-400 leading-relaxed">{t('settings.dnsResolvers.intro')}</p>
      <p className="text-[11px] text-slate-500 leading-relaxed italic">{t('settings.dnsResolvers.rationale')}</p>

      <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-4 space-y-3">
        <label className="text-xs font-medium text-slate-300 block">
          {t('settings.dnsResolvers.addLabel')}
        </label>
        <div className="flex gap-2">
          <input
            className="cyjan-input flex-1"
            placeholder={t('settings.dnsResolvers.addPlaceholder')}
            value={draft}
            onChange={e => { setDraft(e.target.value); setError(''); }}
            onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); handleAdd(); } }}
          />
          <button onClick={handleAdd} className="btn-primary text-xs whitespace-nowrap">
            {t('settings.dnsResolvers.addBtn')}
          </button>
        </div>
        {error && <p className="text-xs text-red-400">{error}</p>}

        <div className="space-y-1.5 mt-3">
          {resolvers.length === 0 ? (
            <p className="text-xs text-slate-500 italic">{t('settings.dnsResolvers.noEntries')}</p>
          ) : (
            resolvers.map(ip => (
              <div key={ip} className="flex items-center justify-between bg-slate-900/60 border border-slate-700/40 rounded px-3 py-1.5">
                <span className="font-mono text-xs text-slate-200">{ip}</span>
                <button
                  onClick={() => handleRemove(ip)}
                  className="text-slate-500 hover:text-red-400 text-xs px-2 transition-colors"
                  title={t('common.delete')}
                >
                  ✕
                </button>
              </div>
            ))
          )}
        </div>

        <div className="flex items-center justify-between gap-3 pt-2 border-t border-slate-800">
          <span className="text-[10px] text-slate-600">{t('settings.dnsResolvers.applyHint')}</span>
          <div className="flex items-center gap-2">
            {info && <span className="text-[11px] text-green-400">{info}</span>}
            <button
              onClick={handleSave}
              disabled={!dirty || saving}
              className="btn-primary text-xs disabled:opacity-50 whitespace-nowrap"
            >
              {saving ? '…' : t('settings.dnsResolvers.save')}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── Settings Navigation ───────────────────────────────────────────────────────

export type SectionId = 'general' | 'users' | 'saml' | 'ml-overview' | 'ml-status' | 'ml-config' | 'ml-learned' | 'rules-sources' | 'rules-list' | 'rules-editor' | 'rules-overrides' | 'interfaces' | 'dns-resolvers' | 'ssl' | 'syslog' | 'irma' | 'itop' | 'update' | 'system-health' | 'db-maintenance' | 'egress-priorities' | 'remote-taps' | 'thorsten';

// Labels werden zur Render-Zeit über i18n aufgelöst:
//   group:  t('settings.groups.<key>')
//   item:   t('settings.items.<id>')
interface NavItem { id: SectionId; icon: ReactNode }
interface NavGroup { key: string; items: NavItem[] }

const ICON_PROPS = { size: 14, strokeWidth: 1.8 } as const;

const NAV_GROUPS: NavGroup[] = [
  {
    key: 'general',
    items: [
      { id: 'general', icon: <Globe {...ICON_PROPS} /> },
    ],
  },
  {
    key: 'users',
    items: [
      { id: 'users', icon: <Users    {...ICON_PROPS} /> },
      { id: 'saml',  icon: <KeyRound {...ICON_PROPS} /> },
    ],
  },
  {
    key: 'ml',
    items: [
      { id: 'ml-overview', icon: <Sparkles {...ICON_PROPS} /> },
      { id: 'ml-status',   icon: <Activity {...ICON_PROPS} /> },
      { id: 'ml-config',   icon: <Sliders  {...ICON_PROPS} /> },
      { id: 'ml-learned',  icon: <Sparkles {...ICON_PROPS} /> },
    ],
  },
  {
    key: 'rules',
    items: [
      { id: 'rules-sources',   icon: <Database {...ICON_PROPS} /> },
      { id: 'rules-list',      icon: <ListTree {...ICON_PROPS} /> },
      { id: 'rules-editor',    icon: <FileText {...ICON_PROPS} /> },
      { id: 'rules-overrides', icon: <Sliders  {...ICON_PROPS} /> },
    ],
  },
  {
    key: 'system',
    items: [
      { id: 'system-health',  icon: <Activity  {...ICON_PROPS} /> },
      { id: 'interfaces',     icon: <Network   {...ICON_PROPS} /> },
      { id: 'dns-resolvers',  icon: <Server    {...ICON_PROPS} /> },
      { id: 'egress-priorities', icon: <Sliders {...ICON_PROPS} /> },
      { id: 'remote-taps',    icon: <Network   {...ICON_PROPS} /> },
      { id: 'ssl',            icon: <Lock      {...ICON_PROPS} /> },
      { id: 'syslog',         icon: <FileText  {...ICON_PROPS} /> },
      { id: 'update',         icon: <Upload    {...ICON_PROPS} /> },
      { id: 'db-maintenance', icon: <HardDrive {...ICON_PROPS} /> },
    ],
  },
  {
    key: 'integrations',
    items: [
      { id: 'irma', icon: <Plug     {...ICON_PROPS} /> },
      { id: 'itop', icon: <Database {...ICON_PROPS} /> },
    ],
  },
  {
    key: 'extra',
    items: [
      { id: 'thorsten', icon: <Sparkles {...ICON_PROPS} /> },
    ],
  },
];

// ── Allgemein: Sprache & Anzeige ──────────────────────────────────────────────

function GeneralSettings() {
  const { t, i18n } = useTranslation();
  const current = (i18n.resolvedLanguage ?? i18n.language ?? 'de').split('-')[0] as SupportedLanguage;

  function handleChange(lng: SupportedLanguage) {
    if (lng === current) return;
    void i18n.changeLanguage(lng);
  }

  return (
    <div className="space-y-4">
      <h2 className="text-sm font-semibold text-slate-200">{t('settings.general.title')}</h2>

      <div className="rounded-lg border border-slate-700/50 bg-slate-900/40 p-4 space-y-3">
        <label className="text-xs font-medium text-slate-300 block">
          {t('settings.general.languageLabel')}
        </label>
        <div className="flex gap-2">
          {SUPPORTED_LANGUAGES.map(lng => {
            const isActive = current === lng;
            return (
              <button
                key={lng}
                type="button"
                onClick={() => handleChange(lng)}
                className={`px-3 py-1.5 rounded text-xs font-medium border transition-colors ${
                  isActive
                    ? 'bg-cyan-500/15 text-cyan-200 border-cyan-600/60'
                    : 'bg-slate-900 text-slate-400 border-slate-700 hover:text-slate-200 hover:border-slate-500'
                }`}
                aria-pressed={isActive}
              >
                {t(`settings.general.languages.${lng}`)}
              </button>
            );
          })}
        </div>
        <p className="text-[11px] text-slate-500">
          {t('settings.general.languageHelp')}
        </p>
      </div>
    </div>
  );
}

interface SettingsPageProps {
  // Initial sichtbare Sub-Sektion. Wird beim ersten Render in den State
  // übernommen — spätere Wechsel innerhalb der Settings-Page laufen weiter
  // über den lokalen setActive (wir wollen die User-Klicks im Submenü nicht
  // bei jedem Tab-Wechsel resetten).
  initialSection?: SectionId;
}

export function SettingsPage({ initialSection }: SettingsPageProps = {}) {
  const { t } = useTranslation();
  const [active, setActive] = useState<SectionId>(initialSection ?? 'general');

  const isThorsten = active === 'thorsten';

  return (
    <div className="flex h-full overflow-hidden">

      {/* ── Submenu (Stil wie Hauptmenü) ─────────────────────────────────── */}
      <nav className="cyjan-settings-nav">
        {NAV_GROUPS.map(group => (
          <div key={group.key} className="cyjan-settings-nav-group">
            <div className="cyjan-settings-nav-grouplabel">{t(`settings.groups.${group.key}`)}</div>
            {group.items.map(item => (
              <button
                key={item.id}
                type="button"
                onClick={() => setActive(item.id)}
                className={`cyjan-sidebar-item ${active === item.id ? 'is-active' : ''}`}
              >
                <span className="cyjan-sidebar-icon">{item.icon}</span>
                {t(`settings.items.${item.id}`)}
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
            {active === 'general'       && <GeneralSettings />}
            {active === 'users'         && <UserManagement />}
            {active === 'saml'          && <SamlSettings />}
            {active === 'ml-overview'   && <MLOverviewSettings onNavigate={setActive} />}
            {active === 'ml-status'     && <MLStatusDisplay />}
            {active === 'ml-config'     && <MLFilterConfig />}
            {active === 'ml-learned'    && <MLLearnedPatterns />}
            {active === 'rules-sources' && <RuleSources />}
            {active === 'rules-list'    && <RulesList />}
            {active === 'rules-editor'  && <RuleFileEditor />}
            {active === 'rules-overrides' && <RuleOverridesSettings />}
            {active === 'system-health'  && <SystemHealth />}
            {active === 'db-maintenance' && <DatabaseMaintenance />}
            {active === 'interfaces'    && <NetworkInterfaces />}
            {active === 'dns-resolvers' && <DnsResolverSettings />}
            {active === 'egress-priorities' && <EgressPrioritySettings />}
            {active === 'remote-taps'   && <RemoteTapsSettings />}
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
