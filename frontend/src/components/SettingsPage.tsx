import { useEffect, useRef, useState } from 'react';
import {
  addRuleSource, createUser, deleteRuleSource, deleteUser,
  fetchMLConfig, fetchMLStatus, fetchRuleSources, fetchRuleUpdateStatus, fetchRules,
  fetchSamlConfig, fetchUsers, generateApiToken, patchRuleSource,
  saveMLConfig, saveSamlConfig, triggerMLRetrain, triggerRuleUpdate, updateUser,
} from '../api';
import type { MLConfig, MLStatus, Rule, RuleSource, SamlConfig, UpdateStatus, User } from '../types';
import { ConfirmDialog } from './ConfirmDialog';

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
        <thead className="border-b border-slate-800">
          <tr className="text-left text-slate-500">
            <th className="pb-2 pr-3">Benutzer</th>
            <th className="pb-2 pr-3">E-Mail</th>
            <th className="pb-2 pr-3">Rolle</th>
            <th className="pb-2 pr-3">Quelle</th>
            <th className="pb-2 pr-3">Letzter Login</th>
            <th className="pb-2 pr-3">Aktiv</th>
            <th className="pb-2"></th>
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

const SAML_DEFAULTS: SamlConfig = {
  enabled: false,
  idp_metadata_url: '',
  sp_entity_id: 'https://ids.local',
  acs_url: 'https://ids.local/api/auth/saml/acs',
  attribute_username: 'uid',
  attribute_email: 'email',
  attribute_display_name: 'displayName',
  default_role: 'viewer',
};

function SamlSettings() {
  const [cfg,     setCfg]     = useState<SamlConfig>(SAML_DEFAULTS);
  const [loading, setLoading] = useState(true);
  const [saving,  setSaving]  = useState(false);
  const [saved,   setSaved]   = useState(false);
  const [error,   setError]   = useState('');
  const timerRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    fetchSamlConfig()
      .then(setCfg)
      .catch(() => { /* kein SAML-Eintrag → Defaults behalten */ })
      .finally(() => setLoading(false));
    return () => { if (timerRef.current) clearTimeout(timerRef.current); };
  }, []);

  async function handleSave(e: React.FormEvent) {
    e.preventDefault();
    setSaving(true); setError(''); setSaved(false);
    try {
      await saveSamlConfig(cfg);
      setSaved(true);
      timerRef.current = setTimeout(() => setSaved(false), 3000);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : 'Fehler beim Speichern');
    } finally {
      setSaving(false);
    }
  }

  const field = (id: string, label: string, key: keyof SamlConfig, type = 'text', placeholder = '') => (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="text-xs text-slate-400">{label}</label>
      <input
        id={id} name={id} type={type} className="input text-xs" placeholder={placeholder}
        value={String(cfg[key] ?? '')}
        onChange={e => setCfg(c => ({ ...c, [key]: e.target.value }))}
      />
    </div>
  );

  if (loading) return <p className="text-slate-500 text-sm">Lade…</p>;

  return (
    <form onSubmit={handleSave} className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-200">SAML / SSO</h2>
        <label htmlFor="saml-enabled" className="flex items-center gap-2 cursor-pointer select-none text-xs">
          <input
            id="saml-enabled" name="saml-enabled" type="checkbox"
            className="accent-purple-500"
            checked={cfg.enabled}
            onChange={e => setCfg(c => ({ ...c, enabled: e.target.checked }))}
          />
          <span className={cfg.enabled ? 'text-purple-300 font-medium' : 'text-slate-500'}>
            SAML aktiviert
          </span>
        </label>
      </div>

      <div className={`space-y-4 ${!cfg.enabled ? 'opacity-50 pointer-events-none' : ''}`}>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          {field('saml-idp-url',    'IdP Metadata-URL',   'idp_metadata_url', 'url', 'https://idp.example.com/metadata')}
          {field('saml-entity-id',  'SP Entity-ID',       'sp_entity_id',     'url', 'https://ids.local')}
          {field('saml-acs-url',    'ACS-URL',            'acs_url',          'url', 'https://ids.local/api/auth/saml/acs')}
        </div>

        <div>
          <p className="text-xs text-slate-500 mb-2">Attribut-Mapping (SAML-Assertion → Benutzerfeld)</p>
          <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
            {field('saml-attr-user',  'Benutzername',   'attribute_username',     'text', 'uid')}
            {field('saml-attr-email', 'E-Mail',         'attribute_email',        'text', 'email')}
            {field('saml-attr-name',  'Anzeigename',    'attribute_display_name', 'text', 'displayName')}
          </div>
        </div>

        <div className="flex flex-col gap-1 max-w-xs">
          <label htmlFor="saml-role" className="text-xs text-slate-400">Standard-Rolle für neue SAML-User</label>
          <select id="saml-role" name="saml-role" className="input text-xs"
            value={cfg.default_role}
            onChange={e => setCfg(c => ({ ...c, default_role: e.target.value as 'admin' | 'viewer' }))}>
            <option value="viewer">Viewer</option>
            <option value="admin">Admin</option>
          </select>
        </div>
      </div>

      {error  && <p className="text-red-400 text-xs">{error}</p>}
      {saved  && <p className="text-green-400 text-xs">Gespeichert ✓</p>}

      <div className="flex justify-end">
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
              className="h-full bg-blue-600 rounded-full transition-all"
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
                      className={`h-full rounded-full ${isHigh ? 'bg-orange-600' : 'bg-blue-600'}`}
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

// ── Settings Navigation ───────────────────────────────────────────────────────

type SectionId = 'users' | 'saml' | 'ml-status' | 'ml-config' | 'rules-sources' | 'rules-list';

interface NavItem { id: SectionId; label: string }
interface NavGroup { label: string; items: NavItem[] }

const NAV_GROUPS: NavGroup[] = [
  {
    label: 'Benutzer & Zugang',
    items: [
      { id: 'users', label: 'Benutzerverwaltung' },
      { id: 'saml',  label: 'SAML / SSO' },
    ],
  },
  {
    label: 'KI/ML-Engine',
    items: [
      { id: 'ml-status', label: 'Status & Lernphase' },
      { id: 'ml-config', label: 'Filter-Konfiguration' },
    ],
  },
  {
    label: 'Regelwerk',
    items: [
      { id: 'rules-sources', label: 'Rule-Quellen' },
      { id: 'rules-list',    label: 'Aktive Regeln' },
    ],
  },
];

export function SettingsPage() {
  const [active, setActive] = useState<SectionId>('users');

  return (
    <div className="flex h-full overflow-hidden">

      {/* ── Sidebar ──────────────────────────────────────────────────────── */}
      <nav className="w-44 border-r border-slate-800 overflow-y-auto flex-shrink-0 py-3">
        {NAV_GROUPS.map(group => (
          <div key={group.label} className="mb-4">
            <div className="px-3 mb-1 text-[10px] font-semibold uppercase tracking-wider text-slate-600 select-none">
              {group.label}
            </div>
            {group.items.map(item => (
              <button
                key={item.id}
                onClick={() => setActive(item.id)}
                className={`w-full text-left px-3 py-1.5 text-xs transition-colors border-r-2 ${
                  active === item.id
                    ? 'text-cyan-300 bg-cyan-950/40 border-cyan-500'
                    : 'text-slate-400 border-transparent hover:text-slate-200 hover:bg-slate-800/40'
                }`}
              >
                {item.label}
              </button>
            ))}
          </div>
        ))}
      </nav>

      {/* ── Content ──────────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto">
        <div className="max-w-4xl mx-auto py-6 px-6">
          <div className="card p-5">
            {active === 'users'         && <UserManagement />}
            {active === 'saml'          && <SamlSettings />}
            {active === 'ml-status'     && <MLStatusDisplay />}
            {active === 'ml-config'     && <MLFilterConfig />}
            {active === 'rules-sources' && <RuleSources />}
            {active === 'rules-list'    && <RulesList />}
          </div>
        </div>
      </div>

    </div>
  );
}
