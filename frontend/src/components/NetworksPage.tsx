import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { bulkDeleteNetworks, createNetwork, deleteNetwork, downloadNetworksExampleCsv, fetchNetworks, importNetworksCsv, updateNetwork } from '../api';
import type { KnownNetwork, User } from '../types';
import { ConfirmDialog } from './ConfirmDialog';
import { MobileDesktopHint } from './MobileDesktopHint';

type Kind = 'ot' | 'it';
type ZoneFilter = 'all' | 'ot' | 'it';
type ViewMode = 'list' | 'tree';
type EditState = { name: string; description: string; color: string; kind: Kind } | null;
type BulkScope = 'all' | 'ot' | 'it';

interface Props {
  user: User;
}

const KIND_BADGE: Record<Kind, { label: string; cls: string }> = {
  ot: { label: 'OT', cls: 'bg-cyan-900/40 text-cyan-300 border-cyan-700/40' },
  it: { label: 'IT', cls: 'bg-violet-900/40 text-violet-300 border-violet-700/40' },
};

// ── CIDR-Containment-Math (BigInt, IPv4+IPv6) ─────────────────────────────
// Frontend rechnet die Tree-Hierarchie selbst, weil das Backend nur eine
// flache Liste liefert. BigInt ist für IPv4 oversized aber unifiziert den
// Codepfad mit IPv6 — der OT-Stack setzt aktuell zwar v4-only ein, aber das
// Schema erlaubt v6, also keine Annahmen einbauen die das später brechen.

type ParsedCidr = { addr: bigint; prefix: number; family: 4 | 6 };
const FAMILY_BITS = { 4: 32, 6: 128 } as const;

function expandIpv6(ip: string): string[] | null {
  if (ip === '::') return ['0', '0', '0', '0', '0', '0', '0', '0'];
  const dcIdx = ip.indexOf('::');
  let parts: string[];
  if (dcIdx >= 0) {
    const left  = ip.slice(0, dcIdx).split(':').filter(Boolean);
    const right = ip.slice(dcIdx + 2).split(':').filter(Boolean);
    const fill  = 8 - left.length - right.length;
    if (fill < 0) return null;
    parts = [...left, ...Array(fill).fill('0'), ...right];
  } else {
    parts = ip.split(':');
  }
  return parts.length === 8 ? parts : null;
}

function parseCidr(cidr: string): ParsedCidr | null {
  const slash = cidr.indexOf('/');
  if (slash < 0) return null;
  const ip       = cidr.slice(0, slash);
  const prefix   = Number(cidr.slice(slash + 1));
  if (!Number.isInteger(prefix) || prefix < 0) return null;
  if (ip.includes(':')) {
    if (prefix > 128) return null;
    const parts = expandIpv6(ip);
    if (!parts) return null;
    let addr = 0n;
    for (const p of parts) {
      const n = parseInt(p, 16);
      if (!Number.isInteger(n) || n < 0 || n > 0xffff) return null;
      addr = (addr << 16n) | BigInt(n);
    }
    return { addr, prefix, family: 6 };
  }
  if (prefix > 32) return null;
  const octets = ip.split('.');
  if (octets.length !== 4) return null;
  let addr = 0n;
  for (const o of octets) {
    const n = Number(o);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    addr = (addr << 8n) | BigInt(n);
  }
  return { addr, prefix, family: 4 };
}

function contains(parent: ParsedCidr, child: ParsedCidr): boolean {
  if (parent.family !== child.family) return false;
  if (child.prefix <= parent.prefix)  return false;
  if (parent.prefix === 0)            return true;
  const shift = BigInt(FAMILY_BITS[parent.family] - parent.prefix);
  return (parent.addr >> shift) === (child.addr >> shift);
}

// ── Tree-Aufbau ────────────────────────────────────────────────────────────
type TreeNode = { net: KnownNetwork; parsed: ParsedCidr; children: TreeNode[] };

function buildTree(nets: KnownNetwork[]): { roots: TreeNode[]; orphans: KnownNetwork[] } {
  const orphans:  KnownNetwork[] = [];
  const parsed: { net: KnownNetwork; parsed: ParsedCidr }[] = [];
  for (const n of nets) {
    const p = parseCidr(n.cidr);
    if (p) parsed.push({ net: n, parsed: p });
    else   orphans.push(n);
  }
  // Kleinster prefix zuerst (= breitester Container) — garantiert dass beim
  // Einfügen jedes Knotens alle möglichen Eltern bereits als Knoten vorliegen.
  parsed.sort((a, b) => a.parsed.prefix - b.parsed.prefix);

  const nodes: TreeNode[] = parsed.map(x => ({ net: x.net, parsed: x.parsed, children: [] }));
  const roots: TreeNode[] = [];
  for (let i = 0; i < nodes.length; i++) {
    const node = nodes[i];
    // Suche kleinsten Container — kandidaten haben kleineren prefix, also
    // stehen vor i in der nach prefix sortierten Liste.
    let best: TreeNode | null = null;
    for (let j = 0; j < i; j++) {
      const cand = nodes[j];
      if (!contains(cand.parsed, node.parsed)) continue;
      if (!best || cand.parsed.prefix > best.parsed.prefix) best = cand;
    }
    if (best) best.children.push(node);
    else      roots.push(node);
  }
  const cmpAddr = (a: TreeNode, b: TreeNode) =>
    a.parsed.addr < b.parsed.addr ? -1 : a.parsed.addr > b.parsed.addr ? 1 : 0;
  function sortRec(n: TreeNode) { n.children.sort(cmpAddr); n.children.forEach(sortRec); }
  roots.sort(cmpAddr);
  roots.forEach(sortRec);
  return { roots, orphans };
}

function collectAllIds(nodes: TreeNode[]): string[] {
  const ids: string[] = [];
  function walk(n: TreeNode) { ids.push(n.net.id); n.children.forEach(walk); }
  nodes.forEach(walk);
  return ids;
}


export function NetworksPage({ user }: Props) {
  const { t } = useTranslation();
  const isAdmin = user.role === 'admin';
  const [networks, setNetworks]         = useState<KnownNetwork[]>([]);
  const [form, setForm]                 = useState<{ cidr: string; name: string; description: string; color: string; kind: Kind }>({ cidr: '', name: '', description: '', color: '#4CAF50', kind: 'ot' });
  const [error, setError]               = useState('');
  const [loading, setLoading]           = useState(false);
  const [importResult, setImportResult] = useState('');
  const [editId, setEditId]             = useState<string | null>(null);
  const [editState, setEditState]       = useState<EditState>(null);
  const [editError, setEditError]       = useState('');
  const [confirmId, setConfirmId]       = useState<string | null>(null);
  const [bulkScope, setBulkScope]       = useState<BulkScope | null>(null);
  const [bulkBusy, setBulkBusy]         = useState(false);
  const [searchQuery, setSearchQuery]   = useState('');
  const [zoneFilter, setZoneFilter]     = useState<ZoneFilter>('all');
  const [viewMode, setViewMode]         = useState<ViewMode>('list');
  const [expanded, setExpanded]         = useState<Set<string>>(new Set());
  const fileRef = useRef<HTMLInputElement>(null);

  const filteredNetworks = useMemo(() => {
    const q = searchQuery.trim().toLowerCase();
    return networks.filter(n => {
      if (zoneFilter !== 'all' && (n.kind ?? 'ot') !== zoneFilter) return false;
      if (!q) return true;
      return (n.cidr.toLowerCase().includes(q)
           || n.name.toLowerCase().includes(q)
           || (n.description ?? '').toLowerCase().includes(q));
    });
  }, [networks, searchQuery, zoneFilter]);

  // Tree wird aus dem gefilterten Set gebaut. Orphan-Children (Eltern raus-
  // gefiltert, Kind drin) werden auf Root-Level befördert — der User hat
  // explizit nach dem Kind gesucht, da brauchen wir den Parent nicht für den
  // Kontext.
  const tree = useMemo(() => buildTree(filteredNetworks), [filteredNetworks]);

  const load = () =>
    fetchNetworks()
      .then(setNetworks)
      .catch(() => {});

  useEffect(() => { load(); }, []);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await createNetwork(form);
      setForm({ cidr: '', name: '', description: '', color: '#4CAF50', kind: 'ot' });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
    } finally {
      setLoading(false);
    }
  };

  const startEdit = (n: KnownNetwork) => {
    setEditId(n.id);
    setEditState({ name: n.name, description: n.description ?? '', color: n.color ?? '#4CAF50', kind: (n.kind === 'it' ? 'it' : 'ot') });
    setEditError('');
  };

  const cancelEdit = () => { setEditId(null); setEditState(null); setEditError(''); };

  const saveEdit = async () => {
    if (!editId || !editState) return;
    setEditError('');
    try {
      await updateNetwork(editId, {
        name:        editState.name || undefined,
        description: editState.description || undefined,
        color:       editState.color || undefined,
        kind:        editState.kind,
      });
      setEditId(null);
      setEditState(null);
      load();
    } catch (err) {
      setEditError(err instanceof Error ? err.message : 'Fehler');
    }
  };

  const remove = async (id: string) => {
    await deleteNetwork(id).catch(() => {});
    load();
  };

  const handleCsv = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportResult('');
    setError('');
    try {
      const result = await importNetworksCsv(file);
      let msg = t('hosts.importResult', { imported: result.imported, skipped: result.skipped });
      if (result.skipped_ot_priority && result.skipped_ot_priority > 0) {
        msg += ' · ' + t('networks.importOtPriority', {
          defaultValue: '{{count}} OT-Konflikt(e) verworfen (OT-Vorrang)',
          count: result.skipped_ot_priority,
        });
      }
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

  const runBulkDelete = async () => {
    if (!bulkScope) return;
    setBulkBusy(true);
    try {
      const kindArg = bulkScope === 'all' ? undefined : bulkScope;
      const res = await bulkDeleteNetworks(kindArg);
      setImportResult(t('networks.bulkDeleteResult', {
        defaultValue: '{{deleted}} Netz(e) gelöscht',
        deleted: res.deleted,
      }));
      setBulkScope(null);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
      setBulkScope(null);
    } finally {
      setBulkBusy(false);
    }
  };

  const toggleExpand = (id: string) => {
    setExpanded(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const expandAll   = () => setExpanded(new Set(collectAllIds(tree.roots)));
  const collapseAll = () => setExpanded(new Set());

  const confirmNetwork = networks.find(n => n.id === confirmId);

  const renderRowActions = (n: KnownNetwork) =>
    editId === n.id ? (
      <div className="flex gap-1.5 justify-end">
        {editError && <span className="text-red-400 text-xs self-center">{editError}</span>}
        <button onClick={saveEdit}   className="btn-primary text-xs">{t('common.save')}</button>
        <button onClick={cancelEdit} className="btn-ghost   text-xs">{t('common.cancel')}</button>
      </div>
    ) : (
      <div className="flex gap-1.5 justify-end">
        <button onClick={() => startEdit(n)}     className="btn-ghost text-xs">{t('common.edit')}</button>
        <button onClick={() => setConfirmId(n.id)} className="btn-ghost text-xs text-red-500 hover:text-red-400">{t('common.delete')}</button>
      </div>
    );

  return (
    <div className="space-y-4">
      <MobileDesktopHint />
      {/* Form */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
          <h2 className="text-sm font-semibold text-slate-300">{t('networks.addNetwork')}</h2>
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => downloadNetworksExampleCsv().catch(() => {})}
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
            {isAdmin && networks.length > 0 && (
              <div className="flex items-center gap-1 border-l border-slate-700/60 pl-2">
                <span className="text-[10px] text-slate-500 uppercase tracking-wider">
                  {t('networks.bulkDelete', { defaultValue: 'Massenlöschen' })}:
                </span>
                <button
                  onClick={() => setBulkScope('all')}
                  className="btn-ghost text-xs text-red-500 hover:text-red-400"
                  title={t('networks.bulkDeleteAllTitle', { defaultValue: 'Alle Netzwerke löschen (Recovery nach fehlerhaftem Import)' })}
                >
                  {t('common.all', { defaultValue: 'Alle' })}
                </button>
                <button
                  onClick={() => setBulkScope('ot')}
                  className="btn-ghost text-xs text-cyan-500 hover:text-cyan-300"
                >
                  OT
                </button>
                <button
                  onClick={() => setBulkScope('it')}
                  className="btn-ghost text-xs text-violet-500 hover:text-violet-300"
                >
                  IT
                </button>
              </div>
            )}
            {importResult && <span className="text-xs text-green-400">{importResult}</span>}
          </div>
        </div>
        <form onSubmit={submit} className="flex flex-wrap gap-2 items-end">
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">{t('networks.cidrRequired')}</span>
            <input
              required
              className="input w-44"
              placeholder="192.168.1.0/24"
              value={form.cidr}
              onChange={e => setForm(f => ({ ...f, cidr: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">{t('networks.nameRequired')}</span>
            <input
              required
              className="input w-40"
              placeholder={t('networks.namePlaceholder')}
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">{t('networks.description')}</span>
            <input
              className="input w-48"
              placeholder={t('networks.descriptionPlaceholder')}
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">{t('networks.color')}</span>
            <input
              type="color"
              className="h-8 w-10 rounded bg-slate-800 border border-slate-700 cursor-pointer"
              value={form.color}
              onChange={e => setForm(f => ({ ...f, color: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">{t('networks.zone', { defaultValue: 'Zone' })}</span>
            <select
              className="input w-24"
              value={form.kind}
              onChange={e => setForm(f => ({ ...f, kind: (e.target.value as Kind) }))}
            >
              <option value="ot">OT</option>
              <option value="it">IT</option>
            </select>
          </label>
          <button type="submit" disabled={loading} className="btn-primary self-end">
            {loading ? '…' : t('common.add')}
          </button>
          {error && <span className="text-red-400 text-xs self-end">{error}</span>}
        </form>
      </div>

      {/* Search + Filter + View-Toggle */}
      {networks.length > 5 && (
        <div className="card p-3 flex flex-wrap items-center gap-3">
          <input
            type="search"
            className="input flex-1 min-w-[200px]"
            placeholder={t('networks.searchPlaceholder', { defaultValue: 'Suche CIDR, Name oder Beschreibung …' })}
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
          />
          <div className="flex items-center gap-1 text-xs">
            <span className="text-slate-500">{t('networks.zone', { defaultValue: 'Zone' })}:</span>
            {(['all', 'ot', 'it'] as const).map(z => (
              <button
                key={z}
                type="button"
                onClick={() => setZoneFilter(z)}
                className={`px-2 py-1 rounded border font-mono uppercase text-[10px] transition-colors ${
                  zoneFilter === z
                    ? (z === 'ot' ? KIND_BADGE.ot.cls
                      : z === 'it' ? KIND_BADGE.it.cls
                      : 'bg-slate-700/40 text-slate-200 border-slate-500/40')
                    : 'bg-slate-900/40 text-slate-500 border-slate-700/50 hover:text-slate-300'
                }`}
              >
                {z === 'all' ? t('common.all', { defaultValue: 'Alle' }) : z}
              </button>
            ))}
          </div>
          <div className="flex items-center gap-1 text-xs">
            <span className="text-slate-500">{t('networks.view', { defaultValue: 'Ansicht' })}:</span>
            {(['list', 'tree'] as const).map(v => (
              <button
                key={v}
                type="button"
                onClick={() => setViewMode(v)}
                className={`px-2 py-1 rounded border text-[10px] transition-colors ${
                  viewMode === v
                    ? 'bg-slate-700/40 text-slate-200 border-slate-500/40'
                    : 'bg-slate-900/40 text-slate-500 border-slate-700/50 hover:text-slate-300'
                }`}
              >
                {v === 'list'
                  ? t('networks.viewList', { defaultValue: 'Liste' })
                  : t('networks.viewTree', { defaultValue: 'Baum' })}
              </button>
            ))}
            {viewMode === 'tree' && (
              <>
                <button
                  type="button"
                  onClick={expandAll}
                  className="btn-ghost text-[10px] text-slate-500 hover:text-slate-300 ml-1"
                  title={t('networks.expandAll', { defaultValue: 'Alle ausklappen' })}
                >
                  ▾▾
                </button>
                <button
                  type="button"
                  onClick={collapseAll}
                  className="btn-ghost text-[10px] text-slate-500 hover:text-slate-300"
                  title={t('networks.collapseAll', { defaultValue: 'Alle einklappen' })}
                >
                  ▸▸
                </button>
              </>
            )}
          </div>
          <span className="text-[10px] text-slate-500 font-mono whitespace-nowrap">
            {t('networks.filterCount', {
              defaultValue: '{{shown}} von {{total}}',
              shown: filteredNetworks.length,
              total: networks.length,
            })}
          </span>
          {(searchQuery || zoneFilter !== 'all') && (
            <button
              type="button"
              onClick={() => { setSearchQuery(''); setZoneFilter('all'); }}
              className="btn-ghost text-[10px] text-slate-500 hover:text-slate-300"
            >
              ↺ {t('common.reset', { defaultValue: 'Zurücksetzen' })}
            </button>
          )}
        </div>
      )}

      {/* Datenanzeige: Liste oder Baum */}
      {viewMode === 'list' ? (
        <>
        {/* Mobile: Card-Stack */}
        <div className="md:hidden flex flex-col gap-2">
          {filteredNetworks.length === 0 && networks.length > 0 && (
            <div className="card p-6 text-center text-slate-600 text-xs">
              {t('networks.noMatch', { defaultValue: 'Keine Treffer für diese Filter.' })}
            </div>
          )}
          {networks.length === 0 && (
            <div className="card p-6 text-center text-slate-600 text-xs">{t('networks.noNetworks')}</div>
          )}
          {filteredNetworks.map(n => {
            const k: Kind = (n.kind === 'it' ? 'it' : 'ot');
            const kindBadge = KIND_BADGE[k];
            const isEditing = editId === n.id && editState;
            return (
              <div key={n.id} className="card p-3">
                <div className="flex items-start justify-between gap-2 mb-2">
                  <span className="font-mono text-sm text-slate-200 truncate">{n.cidr}</span>
                  <span className={`inline-block px-2 py-0.5 rounded border text-[10px] font-mono uppercase shrink-0 ${kindBadge.cls}`}>
                    {kindBadge.label}
                  </span>
                </div>

                {isEditing ? (
                  <div className="flex flex-col gap-2 mb-2">
                    <input
                      autoFocus
                      className="input w-full"
                      placeholder={t('networks.columns.name')}
                      value={editState.name}
                      onChange={e => setEditState(s => s ? { ...s, name: e.target.value } : s)}
                    />
                    <input
                      className="input w-full"
                      placeholder={t('networks.columns.description')}
                      value={editState.description}
                      onChange={e => setEditState(s => s ? { ...s, description: e.target.value } : s)}
                    />
                    <div className="flex items-center gap-2">
                      <input
                        type="color"
                        className="h-9 w-12 rounded bg-slate-800 border border-slate-700 cursor-pointer shrink-0"
                        value={editState.color}
                        onChange={e => setEditState(s => s ? { ...s, color: e.target.value } : s)}
                      />
                      <select
                        className="input flex-1"
                        value={editState.kind}
                        onChange={e => setEditState(s => s ? { ...s, kind: (e.target.value as Kind) } : s)}
                      >
                        <option value="ot">OT</option>
                        <option value="it">IT</option>
                      </select>
                    </div>
                  </div>
                ) : (
                  <>
                    <div className="text-xs text-slate-300 truncate mb-1">{n.name}</div>
                    {n.description && (
                      <div className="text-[11px] text-slate-500 mb-2">{n.description}</div>
                    )}
                    {n.color && (
                      <div className="flex items-center gap-1.5 mb-2 text-[11px] font-mono">
                        <span className="w-3 h-3 rounded-full inline-block" style={{ backgroundColor: n.color }} />
                        <span className="text-slate-500">{n.color}</span>
                      </div>
                    )}
                  </>
                )}

                <div className="flex gap-2 justify-end">
                  {isEditing ? (
                    <>
                      {editError && <span className="text-red-400 text-xs self-center">{editError}</span>}
                      <button onClick={cancelEdit} className="btn-ghost min-h-[40px]">{t('common.cancel')}</button>
                      <button onClick={saveEdit}   className="btn-primary min-h-[40px]">{t('common.save')}</button>
                    </>
                  ) : (
                    <>
                      <button onClick={() => startEdit(n)}       className="btn-ghost min-h-[40px]">{t('common.edit')}</button>
                      <button onClick={() => setConfirmId(n.id)} className="btn-ghost min-h-[40px] text-red-500 hover:text-red-400">{t('common.delete')}</button>
                    </>
                  )}
                </div>
              </div>
            );
          })}
        </div>

        {/* Desktop: Tabelle */}
        <div className="hidden md:block card overflow-hidden">
          <table className="w-full text-xs">
            <thead className="cyjan-table-head">
              <tr className="text-left">
                <th>{t('networks.columns.cidr')}</th>
                <th>{t('networks.columns.name')}</th>
                <th>{t('networks.columns.description')}</th>
                <th>{t('networks.columns.color')}</th>
                <th>{t('networks.columns.zone', { defaultValue: 'Zone' })}</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {filteredNetworks.length === 0 && networks.length > 0 && (
                <tr>
                  <td colSpan={6} className="text-center text-slate-600 py-8">
                    {t('networks.noMatch', { defaultValue: 'Keine Treffer für diese Filter.' })}
                  </td>
                </tr>
              )}
              {networks.length === 0 && (
                <tr>
                  <td colSpan={6} className="text-center text-slate-600 py-8">{t('networks.noNetworks')}</td>
                </tr>
              )}
              {filteredNetworks.map(n => (
                <tr key={n.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-4 py-2 font-mono text-slate-200">{n.cidr}</td>
                  <td className="px-4 py-2">
                    {editId === n.id && editState ? (
                      <input
                        autoFocus
                        className="input w-36"
                        value={editState.name}
                        onChange={e => setEditState(s => s ? { ...s, name: e.target.value } : s)}
                        onKeyDown={e => { if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') cancelEdit(); }}
                      />
                    ) : (
                      <span className="text-slate-300">{n.name}</span>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    {editId === n.id && editState ? (
                      <input
                        className="input w-44"
                        placeholder="optional"
                        value={editState.description}
                        onChange={e => setEditState(s => s ? { ...s, description: e.target.value } : s)}
                        onKeyDown={e => { if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') cancelEdit(); }}
                      />
                    ) : (
                      <span className="text-slate-500">{n.description ?? '–'}</span>
                    )}
                  </td>
                  <td className="px-4 py-2">
                    {editId === n.id && editState ? (
                      <input
                        type="color"
                        className="h-8 w-10 rounded bg-slate-800 border border-slate-700 cursor-pointer"
                        value={editState.color}
                        onChange={e => setEditState(s => s ? { ...s, color: e.target.value } : s)}
                      />
                    ) : (
                      n.color && (
                        <span className="flex items-center gap-1.5">
                          <span className="w-3 h-3 rounded-full inline-block" style={{ backgroundColor: n.color }} />
                          <span className="text-slate-500">{n.color}</span>
                        </span>
                      )
                    )}
                  </td>
                  <td className="px-4 py-2">
                    {editId === n.id && editState ? (
                      <select
                        className="input w-20"
                        value={editState.kind}
                        onChange={e => setEditState(s => s ? { ...s, kind: (e.target.value as Kind) } : s)}
                      >
                        <option value="ot">OT</option>
                        <option value="it">IT</option>
                      </select>
                    ) : (() => {
                      const k: Kind = (n.kind === 'it' ? 'it' : 'ot');
                      const b = KIND_BADGE[k];
                      return (
                        <span className={`inline-block px-2 py-0.5 rounded border text-[10px] font-mono uppercase ${b.cls}`}>
                          {b.label}
                        </span>
                      );
                    })()}
                  </td>
                  <td className="px-4 py-2 text-right">{renderRowActions(n)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        </>
      ) : (
        <div className="card overflow-hidden p-2">
          {filteredNetworks.length === 0 && networks.length > 0 && (
            <div className="text-center text-slate-600 py-8 text-xs">
              {t('networks.noMatch', { defaultValue: 'Keine Treffer für diese Filter.' })}
            </div>
          )}
          {networks.length === 0 && (
            <div className="text-center text-slate-600 py-8 text-xs">{t('networks.noNetworks')}</div>
          )}
          {tree.roots.map(node => (
            <TreeRow
              key={node.net.id}
              node={node}
              depth={0}
              expanded={expanded}
              onToggle={toggleExpand}
              editId={editId}
              editState={editState}
              setEditState={setEditState}
              startEdit={startEdit}
              cancelEdit={cancelEdit}
              saveEdit={saveEdit}
              editError={editError}
              onDelete={(id) => setConfirmId(id)}
              t={t}
            />
          ))}
          {tree.orphans.length > 0 && (
            <div className="mt-3 pt-2 border-t border-slate-800 text-[10px] text-slate-500">
              {t('networks.orphans', { defaultValue: '{{count}} Eintrag/Einträge mit nicht-parsbarer CIDR — siehe Liste-Ansicht', count: tree.orphans.length })}
            </div>
          )}
        </div>
      )}

      {confirmId && confirmNetwork && (
        <ConfirmDialog
          message={t('networks.deleteConfirm', { name: confirmNetwork.name, cidr: confirmNetwork.cidr })}
          onConfirm={() => { setConfirmId(null); remove(confirmId); }}
          onCancel={() => setConfirmId(null)}
        />
      )}

      {bulkScope && (
        <ConfirmDialog
          message={
            bulkScope === 'all'
              ? t('networks.bulkDeleteAllConfirm', {
                  defaultValue: 'ALLE {{count}} bekannten Netzwerke löschen? Das ist nicht rückgängig zu machen.',
                  count: networks.length,
                })
              : t('networks.bulkDeleteKindConfirm', {
                  defaultValue: 'Alle {{kind}}-Netzwerke löschen? Das ist nicht rückgängig zu machen.',
                  kind: bulkScope.toUpperCase(),
                })
          }
          onConfirm={runBulkDelete}
          onCancel={() => !bulkBusy && setBulkScope(null)}
        />
      )}
    </div>
  );
}

// ── Tree-Row (rekursiv) ─────────────────────────────────────────────────────
interface TreeRowProps {
  node:        TreeNode;
  depth:       number;
  expanded:    Set<string>;
  onToggle:    (id: string) => void;
  editId:      string | null;
  editState:   EditState;
  setEditState: React.Dispatch<React.SetStateAction<EditState>>;
  startEdit:   (n: KnownNetwork) => void;
  cancelEdit:  () => void;
  saveEdit:    () => void;
  editError:   string;
  onDelete:    (id: string) => void;
  t:           (k: string, opts?: Record<string, unknown>) => string;
}

function TreeRow(p: TreeRowProps) {
  const { node, depth, expanded, onToggle, editId, editState, setEditState, startEdit, cancelEdit, saveEdit, editError, onDelete, t } = p;
  const n           = node.net;
  const hasChildren = node.children.length > 0;
  const isOpen      = expanded.has(n.id);
  const k: Kind     = (n.kind === 'it' ? 'it' : 'ot');
  const b           = KIND_BADGE[k];
  const inEdit      = editId === n.id && editState;

  return (
    <>
      <div
        className="flex items-center gap-2 px-2 py-1.5 hover:bg-slate-800/30 border-b border-slate-800/30"
        style={{ paddingLeft: `${0.5 + depth * 1.25}rem` }}
      >
        <button
          type="button"
          onClick={() => hasChildren && onToggle(n.id)}
          className={`w-4 text-slate-500 ${hasChildren ? 'hover:text-slate-200 cursor-pointer' : 'opacity-30 cursor-default'}`}
          aria-label={hasChildren ? (isOpen ? t('networks.collapse', { defaultValue: 'Einklappen' }) : t('networks.expand', { defaultValue: 'Ausklappen' })) : undefined}
        >
          {hasChildren ? (isOpen ? '▾' : '▸') : '·'}
        </button>
        <span className="font-mono text-slate-200 text-xs min-w-[10rem]">{n.cidr}</span>
        <span className={`inline-block px-2 py-0.5 rounded border text-[10px] font-mono uppercase ${b.cls}`}>{b.label}</span>
        {inEdit ? (
          <input
            autoFocus
            className="input flex-1 max-w-[14rem] text-xs"
            value={editState!.name}
            onChange={e => setEditState(s => s ? { ...s, name: e.target.value } : s)}
            onKeyDown={e => { if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') cancelEdit(); }}
          />
        ) : (
          <span className="text-slate-300 text-xs flex-1">{n.name}</span>
        )}
        {n.color && !inEdit && (
          <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: n.color }} />
        )}
        {hasChildren && (
          <span className="text-[10px] text-slate-500 font-mono">{node.children.length}</span>
        )}
        <div className="flex gap-1.5">
          {inEdit ? (
            <>
              {editError && <span className="text-red-400 text-xs self-center">{editError}</span>}
              <button onClick={saveEdit}   className="btn-primary text-xs">{t('common.save')}</button>
              <button onClick={cancelEdit} className="btn-ghost   text-xs">{t('common.cancel')}</button>
            </>
          ) : (
            <>
              <button onClick={() => startEdit(n)}     className="btn-ghost text-xs">{t('common.edit')}</button>
              <button onClick={() => onDelete(n.id)}   className="btn-ghost text-xs text-red-500 hover:text-red-400">{t('common.delete')}</button>
            </>
          )}
        </div>
      </div>
      {isOpen && node.children.map(child => (
        <TreeRow
          key={child.net.id}
          node={child}
          depth={depth + 1}
          expanded={expanded}
          onToggle={onToggle}
          editId={editId}
          editState={editState}
          setEditState={setEditState}
          startEdit={startEdit}
          cancelEdit={cancelEdit}
          saveEdit={saveEdit}
          editError={editError}
          onDelete={onDelete}
          t={t}
        />
      ))}
    </>
  );
}
