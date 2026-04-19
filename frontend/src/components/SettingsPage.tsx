import { useEffect, useRef, useState } from 'react';
import {
  createUser, deleteUser, fetchSamlConfig, fetchUsers,
  saveSamlConfig, updateUser,
} from '../api';
import type { SamlConfig, User } from '../types';

// ── Helpers ───────────────────────────────────────────────────────────────────

function SourceBadge({ source }: { source: string }) {
  return source === 'saml'
    ? <span className="px-1.5 py-0.5 text-[10px] rounded bg-purple-900/50 text-purple-300 border border-purple-700/40">SAML</span>
    : <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">Lokal</span>;
}

function RoleBadge({ role }: { role: string }) {
  return role === 'admin'
    ? <span className="px-1.5 py-0.5 text-[10px] rounded bg-amber-900/50 text-amber-300 border border-amber-700/40">Admin</span>
    : <span className="px-1.5 py-0.5 text-[10px] rounded bg-slate-700/60 text-slate-400 border border-slate-600/40">Viewer</span>;
}

interface NewUserForm { username: string; email: string; display_name: string; role: 'admin' | 'viewer'; password: string; password2: string; }
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

  useEffect(() => {
    fetchUsers()
      .then(setUsers)
      .catch(() => setError('Benutzer konnten nicht geladen werden'))
      .finally(() => setLoading(false));
  }, []);

  async function handleCreate(e: React.FormEvent) {
    e.preventDefault();
    setFormErr('');
    if (form.password !== form.password2) { setFormErr('Passwörter stimmen nicht überein'); return; }
    setSaving(true);
    try {
      const u = await createUser({
        username:     form.username,
        email:        form.email || undefined,
        display_name: form.display_name || undefined,
        role:         form.role,
        password:     form.password,
      });
      setUsers(prev => [...prev, u]);
      setForm(EMPTY_FORM);
      setShowNew(false);
    } catch (err: unknown) {
      setFormErr(err instanceof Error ? err.message : 'Fehler beim Erstellen');
    } finally {
      setSaving(false);
    }
  }

  async function handleUpdate(id: string) {
    setSaving(true);
    try {
      const payload: Parameters<typeof updateUser>[1] = {};
      if (editData.email        !== undefined) payload.email        = editData.email;
      if (editData.display_name !== undefined) payload.display_name = editData.display_name;
      if (editData.role         !== undefined) payload.role         = editData.role as 'admin' | 'viewer';
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
    if (!confirm(`Benutzer "${user.username}" wirklich löschen?`)) return;
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
              value={form.role} onChange={e => setForm(f => ({ ...f, role: e.target.value as 'admin' | 'viewer' }))}>
              <option value="viewer">Viewer</option>
              <option value="admin">Admin</option>
            </select>
          </div>
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
      <table className="w-full text-xs">
        <thead className="border-b border-slate-800">
          <tr className="text-left text-slate-500">
            <th className="pb-2 pr-4">Benutzer</th>
            <th className="pb-2 pr-4">E-Mail</th>
            <th className="pb-2 pr-4">Rolle</th>
            <th className="pb-2 pr-4">Quelle</th>
            <th className="pb-2 pr-4">Letzter Login</th>
            <th className="pb-2 pr-4">Aktiv</th>
            <th className="pb-2"></th>
          </tr>
        </thead>
        <tbody>
          {users.map(u => (
            <tr key={u.id} className="border-b border-slate-800/50 hover:bg-slate-800/20">
              {editId === u.id ? (
                /* Edit-Zeile */
                <>
                  <td className="py-2 pr-4">
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
                  <td className="py-2 pr-4">
                    <input className="input w-full" placeholder="E-Mail" type="email"
                      value={editData.email ?? u.email ?? ''}
                      onChange={e => setEditData(d => ({ ...d, email: e.target.value }))} />
                  </td>
                  <td className="py-2 pr-4">
                    <select className="input"
                      value={editData.role ?? u.role}
                      onChange={e => setEditData(d => ({ ...d, role: e.target.value as 'admin' | 'viewer' }))}>
                      <option value="viewer">Viewer</option>
                      <option value="admin">Admin</option>
                    </select>
                  </td>
                  <td className="py-2 pr-4"><SourceBadge source={u.source} /></td>
                  <td className="py-2 pr-4 text-slate-500">—</td>
                  <td className="py-2 pr-4">—</td>
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
                  <td className="py-2 pr-4">
                    <span className="text-slate-200 font-medium">{u.username}</span>
                    {u.display_name && <div className="text-slate-500">{u.display_name}</div>}
                  </td>
                  <td className="py-2 pr-4 text-slate-400">{u.email ?? '—'}</td>
                  <td className="py-2 pr-4"><RoleBadge role={u.role} /></td>
                  <td className="py-2 pr-4"><SourceBadge source={u.source} /></td>
                  <td className="py-2 pr-4 text-slate-500">
                    {u.last_login ? new Date(u.last_login).toLocaleString() : '—'}
                  </td>
                  <td className="py-2 pr-4">
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
                      <button className="btn-ghost text-xs"
                        onClick={() => { setEditId(u.id); setEditData({}); setFormErr(''); }}>
                        Bearbeiten
                      </button>
                      <button className="text-xs text-red-500 hover:text-red-400 px-2 py-1 rounded hover:bg-red-950/30 transition-colors"
                        onClick={() => handleDelete(u)}>
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

// ── SettingsPage ──────────────────────────────────────────────────────────────

export function SettingsPage() {
  return (
    <div className="h-full overflow-y-auto">
      <div className="max-w-4xl mx-auto py-6 px-4 space-y-8">
        <section className="card p-5">
          <UserManagement />
        </section>
        <section className="card p-5">
          <SamlSettings />
        </section>
      </div>
    </div>
  );
}
