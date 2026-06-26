import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { CustomRoleDef, CustomRolePort } from '../types';
import { fetchCustomRoles, upsertCustomRole, deleteCustomRole } from '../api';

// Ports-Textfeld ⇄ CustomRolePort[]. Akzeptiert "2010, 9100-9110".
function parsePorts(text: string, proto: CustomRolePort['proto']): CustomRolePort[] {
  const out: CustomRolePort[] = [];
  for (const tok of text.split(',').map(s => s.trim()).filter(Boolean)) {
    const range = tok.match(/^(\d+)\s*-\s*(\d+)$/);
    if (range) {
      out.push({ port_from: +range[1], port_to: +range[2], proto });
    } else if (/^\d+$/.test(tok)) {
      out.push({ port: +tok, proto });
    } else {
      throw new Error(tok);
    }
  }
  return out;
}

function portsToText(ports: CustomRolePort[]): string {
  return ports
    .map(p => (p.port_from != null && p.port_to != null) ? `${p.port_from}-${p.port_to}` : `${p.port}`)
    .join(', ');
}

function slugId(label: string): string {
  const slug = label.toLowerCase().replace(/[^a-z0-9]+/g, '_').replace(/^_+|_+$/g, '').slice(0, 40);
  return `custom_${slug || 'rolle'}`;
}

const EMPTY = { id: '', label: '', proto: 'TCP' as CustomRolePort['proto'], portsText: '',
                mode: 'all' as 'all' | 'any', min_any: 1, base_confidence: 0.7, enabled: true };

export function CustomRolesPanel({ onCatalogChange }: { onCatalogChange?: () => void }) {
  const { t } = useTranslation();
  const [open, setOpen]   = useState(false);
  const [roles, setRoles] = useState<CustomRoleDef[]>([]);
  const [form, setForm]   = useState({ ...EMPTY });
  const [editing, setEditing] = useState(false);
  const [err, setErr]     = useState('');
  const [busy, setBusy]   = useState(false);

  const load = () => fetchCustomRoles().then(setRoles).catch(() => {});
  useEffect(() => { if (open) load(); }, [open]);

  const startEdit = (r: CustomRoleDef) => {
    setEditing(true);
    setForm({
      id: r.id, label: r.label, proto: (r.ports[0]?.proto ?? 'TCP'),
      portsText: portsToText(r.ports), mode: r.mode, min_any: r.min_any,
      base_confidence: r.base_confidence, enabled: r.enabled,
    });
    setErr('');
  };
  const reset = () => { setForm({ ...EMPTY }); setEditing(false); setErr(''); };

  const save = async () => {
    setErr('');
    if (!form.label.trim()) { setErr(t('roles.custom.errLabel')); return; }
    let ports: CustomRolePort[];
    try { ports = parsePorts(form.portsText, form.proto); }
    catch (e) { setErr(t('roles.custom.errPort', { tok: String((e as Error).message) })); return; }
    if (!ports.length) { setErr(t('roles.custom.errNoPort')); return; }
    const id = editing && form.id ? form.id : slugId(form.label);
    setBusy(true);
    try {
      await upsertCustomRole(id, {
        label: form.label.trim(), category: 'custom', ports, mode: form.mode,
        min_any: form.min_any, base_confidence: form.base_confidence,
        min_flows_per_port: 1, enabled: form.enabled,
      });
      reset(); await load(); onCatalogChange?.();
    } catch (e) {
      setErr(String((e as Error).message));
    } finally { setBusy(false); }
  };

  const remove = async (r: CustomRoleDef) => {
    if (!window.confirm(t('roles.custom.confirmDelete', { label: r.label }))) return;
    setBusy(true);
    try { await deleteCustomRole(r.id); await load(); onCatalogChange?.(); }
    catch (e) { setErr(String((e as Error).message)); }
    finally { setBusy(false); }
  };

  return (
    <div className="mb-3 rounded border border-slate-700/50 bg-slate-900/40">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-3 py-2 text-sm text-slate-300 hover:bg-slate-800/40"
      >
        <span>⚙ {t('roles.custom.title')}{roles.length ? ` (${roles.length})` : ''}</span>
        <span className="text-slate-500">{open ? '▾' : '▸'}</span>
      </button>

      {open && (
        <div className="px-3 pb-3 space-y-3">
          <p className="text-[11px] text-slate-500">{t('roles.custom.hint')}</p>

          {/* Liste */}
          {roles.length > 0 && (
            <div className="space-y-1">
              {roles.map(r => (
                <div key={r.id} className="flex items-center gap-2 text-xs bg-slate-800/40 rounded px-2 py-1">
                  <span className={`px-1 py-0.5 rounded border ${r.enabled ? 'bg-cyan-900/40 text-cyan-300 border-cyan-700/40' : 'bg-slate-800 text-slate-500 border-slate-700'}`}>
                    {r.label}
                  </span>
                  <span className="text-slate-500 font-mono">
                    {r.mode === 'all' ? t('roles.custom.modeAllShort') : t('roles.custom.modeAnyShort')}: {portsToText(r.ports)}/{r.ports[0]?.proto}
                  </span>
                  <span className="text-slate-600 tabular-nums">{Math.round(r.base_confidence * 100)}%</span>
                  <div className="ml-auto flex gap-1">
                    <button onClick={() => startEdit(r)} className="btn-ghost text-[10px] px-1 py-0.5">{t('common.edit')}</button>
                    <button onClick={() => remove(r)} className="btn-ghost text-[10px] text-red-400 px-1 py-0.5">{t('common.delete')}</button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Formular */}
          <div className="grid grid-cols-2 gap-2 text-xs">
            <label className="flex flex-col gap-0.5">
              <span className="text-slate-500">{t('roles.custom.label')}</span>
              <input className="input text-xs py-1" value={form.label}
                     onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
                     placeholder={t('roles.custom.labelPlaceholder')} />
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-slate-500">{t('roles.custom.proto')}</span>
              <select className="input text-xs py-1" value={form.proto}
                      onChange={e => setForm(f => ({ ...f, proto: e.target.value as CustomRolePort['proto'] }))}>
                <option value="TCP">TCP</option><option value="UDP">UDP</option><option value="ANY">ANY</option>
              </select>
            </label>
            <label className="flex flex-col gap-0.5 col-span-2">
              <span className="text-slate-500">{t('roles.custom.ports')}</span>
              <input className="input text-xs py-1 font-mono" value={form.portsText}
                     onChange={e => setForm(f => ({ ...f, portsText: e.target.value }))}
                     placeholder="2010, 9100-9110" />
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-slate-500">{t('roles.custom.mode')}</span>
              <select className="input text-xs py-1" value={form.mode}
                      onChange={e => setForm(f => ({ ...f, mode: e.target.value as 'all' | 'any' }))}>
                <option value="all">{t('roles.custom.modeAll')}</option>
                <option value="any">{t('roles.custom.modeAny')}</option>
              </select>
            </label>
            <label className="flex flex-col gap-0.5">
              <span className="text-slate-500">{t('roles.custom.confidence')}</span>
              <input type="number" min={0} max={1} step={0.05} className="input text-xs py-1"
                     value={form.base_confidence}
                     onChange={e => setForm(f => ({ ...f, base_confidence: Math.max(0, Math.min(1, +e.target.value)) }))} />
            </label>
            {form.mode === 'any' && (
              <label className="flex flex-col gap-0.5">
                <span className="text-slate-500">{t('roles.custom.minAny')}</span>
                <input type="number" min={1} className="input text-xs py-1" value={form.min_any}
                       onChange={e => setForm(f => ({ ...f, min_any: Math.max(1, +e.target.value) }))} />
              </label>
            )}
            <label className="flex items-center gap-1 col-span-2 text-slate-400">
              <input type="checkbox" checked={form.enabled}
                     onChange={e => setForm(f => ({ ...f, enabled: e.target.checked }))} />
              {t('roles.custom.enabled')}
            </label>
          </div>

          {err && <div className="text-[11px] text-red-400">{err}</div>}

          <div className="flex gap-2">
            <button onClick={save} disabled={busy} className="btn-primary text-xs">
              {editing ? t('common.save') : t('roles.custom.add')}
            </button>
            {editing && <button onClick={reset} className="btn-ghost text-xs">{t('common.cancel')}</button>}
          </div>
        </div>
      )}
    </div>
  );
}
