import { useEffect, useRef, useState } from 'react';
import {
  createHost,
  deleteHost,
  fetchHosts,
  hostsExampleCsvUrl,
  importHostsCsv,
  updateHost,
} from '../api';
import type { Host } from '../types';
import { TrustBadge } from './TrustBadge';

type EditState = { ip: string; display_name: string; trusted: boolean } | null;

export function HostsPage() {
  const [hosts, setHosts]       = useState<Host[]>([]);
  const [search, setSearch]     = useState('');
  const [filter, setFilter]     = useState<'all' | 'trusted' | 'unknown'>('all');
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

  const addHost = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      await createHost({ ip: newIp, display_name: newName || undefined });
      setNewIp(''); setNewName('');
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fehler');
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
      setError(err instanceof Error ? err.message : 'Fehler');
    }
  };

  const remove = async (ip: string) => {
    if (!confirm(`Host ${ip} entfernen?`)) return;
    await deleteHost(ip).catch(() => {});
    load();
  };

  const handleCsv = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setImportResult('');
    try {
      const result = await importHostsCsv(file);
      setImportResult(
        `Importiert: ${result.imported} | Übersprungen: ${result.skipped}` +
        (result.errors.length ? ` | Fehler: ${result.errors.slice(0, 3).join('; ')}` : '')
      );
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Import-Fehler');
    }
    if (fileRef.current) fileRef.current.value = '';
  };

  return (
    <div className="space-y-4">
      {/* Add host + CSV import */}
      <div className="card p-4 space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-semibold text-slate-300">Host hinzufügen</h2>
          <div className="flex items-center gap-2">
            <a
              href={hostsExampleCsvUrl()}
              download="hosts_example.csv"
              className="btn-ghost text-xs text-slate-500 hover:text-slate-300"
              title="Beispiel-CSV herunterladen"
            >
              Beispiel-CSV
            </a>
            <label className="btn-ghost cursor-pointer text-xs">
              CSV importieren
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
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">IP-Adresse *</span>
            <input
              required
              className="input w-40"
              placeholder="192.168.1.1"
              value={newIp}
              onChange={e => setNewIp(e.target.value)}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">Anzeigename</span>
            <input
              className="input w-48"
              placeholder="z.B. Router, Drucker …"
              value={newName}
              onChange={e => setNewName(e.target.value)}
            />
          </label>
          <button type="submit" disabled={loading} className="btn-primary self-end">
            {loading ? '…' : 'Hinzufügen'}
          </button>
          {error && <span className="text-red-400 text-xs self-end">{error}</span>}
        </form>

        <p className="text-xs text-slate-600">
          CSV-Format: <code className="text-slate-500">Hostname;IP-Adresse</code> oder <code className="text-slate-500">IP-Adresse;Hostname</code> – Semikolon oder Komma als Trennzeichen.
        </p>
      </div>

      {/* Filter + Search */}
      <div className="flex gap-2 items-center">
        <input
          className="input flex-1 max-w-xs"
          placeholder="IP oder Name suchen…"
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        {(['all', 'trusted', 'unknown'] as const).map(f => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            className={`btn ${filter === f ? 'btn-primary' : 'btn-ghost'}`}
          >
            {{ all: 'Alle', trusted: 'Bekannt', unknown: 'Unbekannt' }[f]}
          </button>
        ))}
        <span className="text-xs text-slate-500 ml-auto">{hosts.length} Hosts</span>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-xs">
          <thead className="border-b border-slate-800 text-slate-500 text-left">
            <tr>
              <th className="px-4 py-2">IP</th>
              <th className="px-4 py-2">Anzeigename / Hostname</th>
              <th className="px-4 py-2">Trust</th>
              <th className="px-4 py-2">Geo / ASN</th>
              <th className="px-4 py-2">Ping</th>
              <th className="px-4 py-2">Zuletzt gesehen</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {hosts.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center text-slate-600 py-8">Keine Hosts</td>
              </tr>
            )}
            {hosts.map(h => (
              <tr key={h.ip} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                <td className="px-4 py-2 font-mono text-slate-200">{h.ip}</td>
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
                      <span className="text-slate-400">Trusted</span>
                    </label>
                  ) : (
                    <TrustBadge trusted={h.trusted} source={h.trust_source} />
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
                      <button onClick={saveEdit}   className="btn-primary">Speichern</button>
                      <button onClick={() => setEdit(null)} className="btn-ghost">Abbrechen</button>
                    </div>
                  ) : (
                    <div className="flex gap-1 justify-end">
                      <button
                        onClick={() => setEdit({ ip: h.ip, display_name: h.display_name ?? '', trusted: h.trusted })}
                        className="btn-ghost"
                      >
                        Bearbeiten
                      </button>
                      <button onClick={() => remove(h.ip)} className="btn-ghost text-red-500">
                        Entfernen
                      </button>
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
