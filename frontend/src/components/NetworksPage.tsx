import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { createNetwork, deleteNetwork, downloadNetworksExampleCsv, fetchNetworks, importNetworksCsv, updateNetwork } from '../api';
import type { KnownNetwork } from '../types';
import { ConfirmDialog } from './ConfirmDialog';

type EditState = { name: string; description: string; color: string } | null;

export function NetworksPage() {
  const { t } = useTranslation();
  const [networks, setNetworks]         = useState<KnownNetwork[]>([]);
  const [form, setForm]                 = useState({ cidr: '', name: '', description: '', color: '#4CAF50' });
  const [error, setError]               = useState('');
  const [loading, setLoading]           = useState(false);
  const [importResult, setImportResult] = useState('');
  const [editId, setEditId]             = useState<string | null>(null);
  const [editState, setEditState]       = useState<EditState>(null);
  const [editError, setEditError]       = useState('');
  const [confirmId, setConfirmId]       = useState<string | null>(null);
  const fileRef = useRef<HTMLInputElement>(null);

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
      setForm({ cidr: '', name: '', description: '', color: '#4CAF50' });
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
    } finally {
      setLoading(false);
    }
  };

  const startEdit = (n: KnownNetwork) => {
    setEditId(n.id);
    setEditState({ name: n.name, description: n.description ?? '', color: n.color ?? '#4CAF50' });
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

  const confirmNetwork = networks.find(n => n.id === confirmId);

  return (
    <div className="space-y-4">
      {/* Form */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-300">{t('networks.addNetwork')}</h2>
          <div className="flex items-center gap-2">
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
          <button type="submit" disabled={loading} className="btn-primary self-end">
            {loading ? '…' : t('common.add')}
          </button>
          {error && <span className="text-red-400 text-xs self-end">{error}</span>}
        </form>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-xs">
          <thead className="cyjan-table-head">
            <tr className="text-left">
              <th>{t('networks.columns.cidr')}</th>
              <th>{t('networks.columns.name')}</th>
              <th>{t('networks.columns.description')}</th>
              <th>{t('networks.columns.color')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {networks.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center text-slate-600 py-8">{t('networks.noNetworks')}</td>
              </tr>
            )}
            {networks.map(n => (
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
                        <span
                          className="w-3 h-3 rounded-full inline-block"
                          style={{ backgroundColor: n.color }}
                        />
                        <span className="text-slate-500">{n.color}</span>
                      </span>
                    )
                  )}
                </td>
                <td className="px-4 py-2 text-right">
                  {editId === n.id ? (
                    <div className="flex gap-1.5 justify-end">
                      {editError && <span className="text-red-400 text-xs self-center">{editError}</span>}
                      <button onClick={saveEdit} className="btn-primary text-xs">{t('common.save')}</button>
                      <button onClick={cancelEdit} className="btn-ghost text-xs">{t('common.cancel')}</button>
                    </div>
                  ) : (
                    <div className="flex gap-1.5 justify-end">
                      <button
                        onClick={() => startEdit(n)}
                        className="btn-ghost text-xs"
                      >
                        {t('common.edit')}
                      </button>
                      <button
                        onClick={() => setConfirmId(n.id)}
                        className="btn-ghost text-xs text-red-500 hover:text-red-400"
                      >
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

      {confirmId && confirmNetwork && (
        <ConfirmDialog
          message={t('networks.deleteConfirm', { name: confirmNetwork.name, cidr: confirmNetwork.cidr })}
          onConfirm={() => { setConfirmId(null); remove(confirmId); }}
          onCancel={() => setConfirmId(null)}
        />
      )}
    </div>
  );
}
