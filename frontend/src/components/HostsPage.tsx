import { useEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { Network } from 'lucide-react';
import {
  createHost,
  deleteHost,
  fetchHosts,
  fetchRoleCatalog,
  updateHostRoles,
  downloadHostsExampleCsv,
  importHostsCsv,
  updateHost,
} from '../api';
import type { Host, HostRoleAction, RoleCatalogEntry } from '../types';
import { showHostConnections } from './HostConnectionDrawer';
import { ConfirmDialog } from './ConfirmDialog';
import { TrustBadge } from './TrustBadge';
import { RoleBadge } from './RoleBadge';

type EditState = { ip: string; display_name: string; trusted: boolean } | null;

// Sortierte Rollen-Keys eines Hosts (erst manual, dann nach Confidence absteigend).
function sortedRoleIds(h: Host): string[] {
  const roles = h.detected_roles?.roles;
  if (!roles) return [];
  return Object.keys(roles).sort((a, b) => {
    const ra = roles[a], rb = roles[b];
    if (ra.source !== rb.source) return ra.source === 'manual' ? -1 : 1;
    return (rb.confidence ?? 0) - (ra.confidence ?? 0);
  });
}

export function HostsPage() {
  const { t } = useTranslation();
  const [confirmIp, setConfirmIp] = useState<string | null>(null);
  const [hosts, setHosts]       = useState<Host[]>([]);
  const [search, setSearch]     = useState('');
  const [filter, setFilter]     = useState<'all' | 'trusted' | 'unknown'>('all');
  const [roleFilter, setRoleFilter] = useState<string>('');   // '' = alle Rollen
  const [catalog, setCatalog]   = useState<RoleCatalogEntry[]>([]);
  const [editState, setEdit]    = useState<EditState>(null);
  const [newIp, setNewIp]       = useState('');
  const [newName, setNewName]   = useState('');
  const [importResult, setImportResult] = useState<string>('');
  const [error, setError]       = useState('');
  const [loading, setLoading]   = useState(false);
  const fileRef = useRef<HTMLInputElement>(null);

  const load = () => {
    const params: { trusted?: boolean; search?: string } = {};
    if (filter === 'trusted') params.trusted = true;
    if (filter === 'unknown') params.trusted = false;
    if (search) params.search = search;
    fetchHosts(params).then(setHosts).catch(() => {});
  };

  useEffect(() => { load(); }, [filter, search]);
  useEffect(() => { fetchRoleCatalog().then(setCatalog).catch(() => {}); }, []);

  // Rollen-Filter clientseitig — die /api/hosts?role=-Variante wäre ein
  // Round-Trip pro Wechsel; bei der überschaubaren Inventar-Größe reicht das.
  const visibleHosts = roleFilter
    ? hosts.filter(h => !!h.detected_roles?.roles?.[roleFilter])
    : hosts;

  // Manuelles Set/Reset/Remove einer Rolle; danach Host-Liste neu laden.
  const changeRole = async (ip: string, roleId: string, action: HostRoleAction) => {
    setError('');
    try {
      await updateHostRoles(ip, roleId, action);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
    }
  };

  const addHost = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await createHost({ ip: newIp, display_name: newName || undefined });
      setNewIp(''); setNewName('');
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
    } finally {
      setLoading(false);
    }
  };

  const saveEdit = async () => {
    if (!editState) return;
    try {
      await updateHost(editState.ip, {
        display_name: editState.display_name || undefined,
        trusted:      editState.trusted,
      });
      setEdit(null);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
    }
  };

  const remove = async (ip: string) => {
    await deleteHost(ip).catch(() => {});
    load();
  };

  const handleCsv = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportResult('');
    try {
      const result = await importHostsCsv(file);
      let msg = t('hosts.importResult', { imported: result.imported, skipped: result.skipped });
      if (result.errors.length) {
        msg += t('hosts.importErrors', { errors: result.errors.slice(0, 3).join('; ') });
      }
      setImportResult(msg);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('hosts.importError'));
    }
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div className="space-y-4">
      {/* Add host + CSV import */}
      <div className="card p-4 space-y-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h2 className="text-sm font-semibold text-slate-300">{t('hosts.addHost')}</h2>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => downloadHostsExampleCsv().catch(() => {})}
              className="btn-ghost text-xs text-slate-500 hover:text-slate-300"
              title={t('hosts.exampleCsvTitle')}
            >
              {t('hosts.exampleCsv')}
            </button>
            <label className="btn-ghost cursor-pointer text-xs">
              {t('hosts.importCsv')}
              <input
                ref={fileRef}
                type="file"
                accept=".csv,.txt"
                className="hidden"
                onChange={handleCsv}
              />
            </label>
            {importResult && (
              <span className="text-xs text-green-400">{importResult}</span>
            )}
          </div>
        </div>

        <form onSubmit={addHost} className="flex flex-wrap gap-2 items-end">
          <label className="flex flex-col gap-1 w-full sm:w-40">
            <span className="text-xs text-slate-500">{t('hosts.ipRequired')}</span>
            <input
              required
              className="input w-full"
              placeholder="192.168.1.1"
              value={newIp}
              onChange={e => setNewIp(e.target.value)}
            />
          </label>
          <label className="flex flex-col gap-1 w-full sm:w-48">
            <span className="text-xs text-slate-500">{t('hosts.displayName')}</span>
            <input
              className="input w-full"
              placeholder={t('hosts.displayNamePlaceholder')}
              value={newName}
              onChange={e => setNewName(e.target.value)}
            />
          </label>
          <button type="submit" disabled={loading} className="btn-primary self-end">
            {loading ? '…' : t('common.add')}
          </button>
          {error && <span className="text-red-400 text-xs self-end">{error}</span>}
        </form>

        <p className="text-xs text-slate-600">
          <Trans
            i18nKey="hosts.csvFormatHint"
            components={{ code: <code className="text-slate-500" /> }}
          />
        </p>
      </div>

      {/* Filter + Search */}
      <div className="flex flex-wrap gap-2 items-center">
        <input
          className="input w-full md:flex-1 md:max-w-xs"
          placeholder={t('hosts.searchPlaceholder')}
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {(['all', 'trusted', 'unknown'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`px-3 py-2 md:py-1 rounded text-xs font-medium font-mono border transition-colors ${
              filter === f
                ? 'bg-cyan-500/15 text-cyan-200 border-cyan-500/50'
                : 'bg-slate-900 text-slate-500 border-slate-700 hover:text-slate-300'
            }`}
          >
            {t(`hosts.filter${f.charAt(0).toUpperCase() + f.slice(1)}`)}
          </button>
        ))}
        {catalog.length > 0 && (
          <select
            value={roleFilter}
            onChange={e => setRoleFilter(e.target.value)}
            title={t('roles.filterTitle')}
            className="input w-auto text-xs py-2 md:py-1"
          >
            <option value="">{t('roles.filterAll')}</option>
            {catalog.map(c => (
              <option key={c.id} value={c.id}>{c.label}</option>
            ))}
          </select>
        )}
        <span className="text-xs text-slate-500 ml-auto">{t('hosts.count', { count: visibleHosts.length })}</span>
      </div>

      {/* Mobile: Card-Stack */}
      <div className="md:hidden flex flex-col gap-2">
        {visibleHosts.length === 0 && (
          <div className="card p-6 text-center text-slate-600 text-xs">{t('hosts.noHosts')}</div>
        )}
        {visibleHosts.map(h => (
          <div key={h.ip} className="card p-3">
            <div className="flex items-start justify-between gap-2 mb-2">
              <button
                type="button"
                onClick={() => showHostConnections(h.ip, { roles: h.detected_roles, catalog })}
                title={t('hosts.showConnectionsTitle')}
                className="inline-flex items-center gap-1.5 font-mono text-sm text-slate-200 hover:text-cyan-300 transition-colors min-w-0"
              >
                <Network size={12} className="text-slate-500 shrink-0" />
                <span className="truncate">{h.ip}</span>
              </button>
              <div className="shrink-0">
                <TrustBadge trusted={h.trusted} source={h.trust_source} />
              </div>
            </div>

            {sortedRoleIds(h).length > 0 && (
              <div className="flex flex-wrap gap-1 mb-2">
                {sortedRoleIds(h).map(rid => (
                  <RoleBadge key={rid} roleId={rid} entry={h.detected_roles!.roles[rid]} catalog={catalog} />
                ))}
              </div>
            )}

            {editState?.ip === h.ip ? (
              <div className="flex flex-col gap-2 mb-2">
                <input
                  autoFocus
                  className="input"
                  placeholder={t('hosts.columns.displayHostname')}
                  value={editState.display_name}
                  onChange={e => setEdit({ ...editState, display_name: e.target.value })}
                />
                <label className="flex items-center gap-2 text-xs text-slate-300 cursor-pointer">
                  <input
                    type="checkbox"
                    className="accent-blue-500 w-4 h-4"
                    checked={editState.trusted}
                    onChange={e => setEdit({ ...editState, trusted: e.target.checked })}
                  />
                  {t('hosts.trustedToggle')}
                </label>
                <RoleEditor host={h} catalog={catalog} onChange={changeRole} />
              </div>
            ) : (
              <div className="text-xs text-slate-300 mb-2 truncate">
                {h.display_name || h.hostname || <span className="text-slate-600">–</span>}
              </div>
            )}

            <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[11px] font-mono mb-2">
              <div className="text-slate-500">
                <span className="text-slate-600 mr-1">geo</span>
                {h.geo
                  ? [h.geo.city, h.geo.country].filter(Boolean).join(', ') || '–'
                  : h.asn?.org ?? '–'}
              </div>
              <div className="text-slate-500 tabular-nums text-right">
                <span className="text-slate-600 mr-1">ping</span>
                {h.ping_ms != null ? `${h.ping_ms} ms` : '–'}
              </div>
              <div className="text-slate-600 col-span-2">
                <span className="text-slate-700 mr-1">last seen</span>
                {h.last_seen ? new Date(h.last_seen).toLocaleString() : '–'}
              </div>
            </div>

            <div className="flex gap-2 justify-end">
              {editState?.ip === h.ip ? (
                <>
                  <button onClick={() => setEdit(null)} className="btn-ghost min-h-[40px]">{t('common.cancel')}</button>
                  <button onClick={saveEdit}           className="btn-primary min-h-[40px]">{t('common.save')}</button>
                </>
              ) : (
                <>
                  <button
                    onClick={() => setEdit({ ip: h.ip, display_name: h.display_name ?? '', trusted: h.trusted })}
                    className="btn-ghost min-h-[40px]"
                  >
                    {t('common.edit')}
                  </button>
                  <button onClick={() => setConfirmIp(h.ip)} className="btn-ghost text-red-500 min-h-[40px]">
                    {t('common.delete')}
                  </button>
                </>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Desktop: Tabelle (unverändert) */}
      <div className="hidden md:block card overflow-hidden">
        <table className="w-full text-xs">
          <thead className="cyjan-table-head text-left">
            <tr>
              <th>{t('hosts.columns.ip')}</th>
              <th>{t('hosts.columns.displayHostname')}</th>
              <th>{t('hosts.columns.trust')}</th>
              <th>{t('hosts.columns.roles')}</th>
              <th>{t('hosts.columns.geoAsn')}</th>
              <th>{t('hosts.columns.ping')}</th>
              <th>{t('hosts.columns.lastSeen')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {visibleHosts.length === 0 && (
              <tr>
                <td colSpan={8} className="text-center text-slate-600 py-8">{t('hosts.noHosts')}</td>
              </tr>
            )}
            {visibleHosts.map(h => (
              <tr key={h.ip} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                <td className="px-4 py-2 font-mono text-slate-200">
                  <button
                    type="button"
                    onClick={() => showHostConnections(h.ip, { roles: h.detected_roles, catalog })}
                    title={t('hosts.showConnectionsTitle')}
                    className="group inline-flex items-center gap-1.5 hover:text-cyan-300 transition-colors"
                  >
                    <Network size={11} className="text-slate-500 group-hover:text-cyan-400 transition-colors" />
                    {h.ip}
                  </button>
                </td>
                <td className="px-4 py-2">
                  {editState?.ip === h.ip ? (
                    <input
                      autoFocus
                      className="input w-44"
                      value={editState.display_name}
                      onChange={e => setEdit({ ...editState, display_name: e.target.value })}
                      onKeyDown={e => { if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') setEdit(null); }}
                    />
                  ) : (
                    <span className="text-slate-300">
                      {h.display_name || h.hostname || <span className="text-slate-600">–</span>}
                    </span>
                  )}
                </td>
                <td className="px-4 py-2">
                  {editState?.ip === h.ip ? (
                    <label className="flex items-center gap-1.5 cursor-pointer">
                      <input
                        type="checkbox"
                        className="accent-blue-500"
                        checked={editState.trusted}
                        onChange={e => setEdit({ ...editState, trusted: e.target.checked })}
                      />
                      <span className="text-slate-400">{t('hosts.trustedToggle')}</span>
                    </label>
                  ) : (
                    <TrustBadge trusted={h.trusted} source={h.trust_source} />
                  )}
                </td>
                <td className="px-4 py-2">
                  {editState?.ip === h.ip ? (
                    <RoleEditor host={h} catalog={catalog} onChange={changeRole} />
                  ) : sortedRoleIds(h).length > 0 ? (
                    <div className="flex flex-wrap gap-1">
                      {sortedRoleIds(h).map(rid => (
                        <RoleBadge key={rid} roleId={rid} entry={h.detected_roles!.roles[rid]} catalog={catalog} />
                      ))}
                    </div>
                  ) : (
                    <span className="text-slate-600">–</span>
                  )}
                </td>
                <td className="px-4 py-2 text-slate-500">
                  {h.geo
                    ? [h.geo.city, h.geo.country].filter(Boolean).join(', ')
                    : h.asn?.org ?? '–'}
                </td>
                <td className="px-4 py-2 text-slate-500 tabular-nums">
                  {h.ping_ms != null ? `${h.ping_ms} ms` : '–'}
                </td>
                <td className="px-4 py-2 text-slate-600">
                  {h.last_seen ? new Date(h.last_seen).toLocaleDateString() : '–'}
                </td>
                <td className="px-4 py-2 text-right">
                  {editState?.ip === h.ip ? (
                    <div className="flex gap-1 justify-end">
                      <button onClick={saveEdit}   className="btn-primary">{t('common.save')}</button>
                      <button onClick={() => setEdit(null)} className="btn-ghost">{t('common.cancel')}</button>
                    </div>
                  ) : (
                    <div className="flex gap-1 justify-end">
                      <button
                        onClick={() => setEdit({ ip: h.ip, display_name: h.display_name ?? '', trusted: h.trusted })}
                        className="btn-ghost"
                      >
                        {t('common.edit')}
                      </button>
                      <button onClick={() => setConfirmIp(h.ip)} className="btn-ghost text-red-500">
                        {t('common.delete')}
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {confirmIp && (
        <ConfirmDialog
          message={t('hosts.deleteConfirm', { ip: confirmIp })}
          onConfirm={() => { setConfirmIp(null); remove(confirmIp); }}
          onCancel={() => setConfirmIp(null)}
        />
      )}
    </div>
  );
}

// ── Inline-Rollen-Editor (Edit-State) ────────────────────────────────────────
// Pro bereits erkannter Rolle: Reset (Lock raus → auto) bzw. Remove (auto weg).
// Darunter ein Select, um eine Katalog-Rolle manuell zu setzen (source=manual).
function RoleEditor({
  host,
  catalog,
  onChange,
}: {
  host:     Host;
  catalog:  RoleCatalogEntry[];
  onChange: (ip: string, roleId: string, action: HostRoleAction) => void;
}) {
  const { t } = useTranslation();
  const roles = host.detected_roles?.roles ?? {};
  const manual = host.detected_roles?.manual ?? {};
  const ids = sortedRoleIds(host);
  // Dauerhaft unterdrückte Rollen (Negativ-Lock) — nicht in `roles`, nur im
  // manual-Block. Separat unten gelistet mit Aufheben-Button.
  const suppressedIds = Object.keys(manual).filter(id => manual[id]?.suppressed);
  const labelOf = (id: string) => catalog.find(c => c.id === id)?.label ?? id;
  // Im Set-Select nur Rollen anbieten, die der Host weder trägt noch unterdrückt.
  const assignable = catalog.filter(c => !roles[c.id] && !manual[c.id]?.suppressed);

  return (
    <div className="flex flex-col gap-1.5">
      {ids.map(rid => {
        const entry = roles[rid];
        const label = labelOf(rid);
        return (
          <div key={rid} className="flex items-center gap-1.5">
            <RoleBadge roleId={rid} entry={entry} catalog={catalog} />
            {entry.source === 'manual' ? (
              <button
                onClick={() => onChange(host.ip, rid, 'reset')}
                className="btn-ghost text-[10px] text-amber-400 px-1 py-0.5"
                title={t('roles.resetTitle', { role: label })}
              >
                {t('roles.reset')}
              </button>
            ) : (
              <>
                <button
                  onClick={() => onChange(host.ip, rid, 'remove')}
                  className="btn-ghost text-[10px] text-red-400 px-1 py-0.5"
                  title={t('roles.removeTitle', { role: label })}
                >
                  {t('roles.remove')}
                </button>
                <button
                  onClick={() => onChange(host.ip, rid, 'suppress')}
                  className="btn-ghost text-[10px] text-slate-400 px-1 py-0.5"
                  title={t('roles.suppressTitle', { role: label })}
                >
                  🚫 {t('roles.suppress')}
                </button>
              </>
            )}
          </div>
        );
      })}
      {suppressedIds.map(rid => (
        <div key={`sup-${rid}`} className="flex items-center gap-1.5">
          <span
            className="px-1 py-0.5 text-xs rounded bg-slate-800/60 text-slate-500 border border-slate-700/50 line-through"
            title={t('roles.suppressedTitle', { role: labelOf(rid) })}
          >
            🚫 {labelOf(rid)}
          </span>
          <button
            onClick={() => onChange(host.ip, rid, 'reset')}
            className="btn-ghost text-[10px] text-amber-400 px-1 py-0.5"
            title={t('roles.unsuppressTitle', { role: labelOf(rid) })}
          >
            {t('roles.unsuppress')}
          </button>
        </div>
      ))}
      {assignable.length > 0 && (
        <select
          value=""
          onChange={e => { if (e.target.value) onChange(host.ip, e.target.value, 'set'); }}
          title={t('roles.setTitle')}
          className="input w-auto text-[11px] py-1"
        >
          <option value="">{t('roles.setPlaceholder')}</option>
          {assignable.map(c => (
            <option key={c.id} value={c.id}>{c.label}</option>
          ))}
        </select>
      )}
    </div>
  );
}
