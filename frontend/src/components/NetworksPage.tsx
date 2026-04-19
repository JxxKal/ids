import { useEffect, useRef, useState } from 'react';
import { createNetwork, deleteNetwork, fetchNetworks, importNetworksCsv, networksExampleCsvUrl } from '../api';
import type { KnownNetwork } from '../types';

export function NetworksPage() {
  const [networks, setNetworks]         = useState<KnownNetwork[]>([]);
  const [form, setForm]                 = useState({ cidr: '', name: '', description: '', color: '#4CAF50' });
  const [error, setError]               = useState('');
  const [loading, setLoading]           = useState(false);
  const [importResult, setImportResult] = useState('');
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
      setError(err instanceof Error ? err.message : 'Fehler');
    } finally {
      setLoading(false);
    }
  };

  const remove = async (id: string) => {
    if (!confirm('Netzwerk löschen?')) return;
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
      {/* Form */}
      <div className="card p-4">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-slate-300">Netzwerk hinzufügen</h2>
          <div className="flex items-center gap-2">
            <a
              href={networksExampleCsvUrl()}
              download="networks_example.csv"
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
            {importResult && <span className="text-xs text-green-400">{importResult}</span>}
          </div>
        </div>
        <form onSubmit={submit} className="flex flex-wrap gap-2 items-end">
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">CIDR *</span>
            <input
              required
              className="input w-44"
              placeholder="192.168.1.0/24"
              value={form.cidr}
              onChange={e => setForm(f => ({ ...f, cidr: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">Name *</span>
            <input
              required
              className="input w-40"
              placeholder="Office LAN"
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">Beschreibung</span>
            <input
              className="input w-48"
              placeholder="optional"
              value={form.description}
              onChange={e => setForm(f => ({ ...f, description: e.target.value }))}
            />
          </label>
          <label className="flex flex-col gap-1">
            <span className="text-xs text-slate-500">Farbe</span>
            <input
              type="color"
              className="h-8 w-10 rounded bg-slate-800 border border-slate-700 cursor-pointer"
              value={form.color}
              onChange={e => setForm(f => ({ ...f, color: e.target.value }))}
            />
          </label>
          <button type="submit" disabled={loading} className="btn-primary self-end">
            {loading ? '…' : 'Hinzufügen'}
          </button>
          {error && <span className="text-red-400 text-xs self-end">{error}</span>}
        </form>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <table className="w-full text-xs">
          <thead className="border-b border-slate-800 text-slate-500">
            <tr className="text-left">
              <th className="px-4 py-2">CIDR</th>
              <th className="px-4 py-2">Name</th>
              <th className="px-4 py-2">Beschreibung</th>
              <th className="px-4 py-2">Farbe</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {networks.length === 0 && (
              <tr>
                <td colSpan={5} className="text-center text-slate-600 py-8">Keine Netzwerke</td>
              </tr>
            )}
            {networks.map(n => (
              <tr key={n.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                <td className="px-4 py-2 font-mono text-slate-200">{n.cidr}</td>
                <td className="px-4 py-2 text-slate-300">{n.name}</td>
                <td className="px-4 py-2 text-slate-500">{n.description ?? '–'}</td>
                <td className="px-4 py-2">
                  {n.color && (
                    <span className="flex items-center gap-1.5">
                      <span
                        className="w-3 h-3 rounded-full inline-block"
                        style={{ backgroundColor: n.color }}
                      />
                      <span className="text-slate-500">{n.color}</span>
                    </span>
                  )}
                </td>
                <td className="px-4 py-2 text-right">
                  <button
                    onClick={() => remove(n.id)}
                    className="btn-ghost text-red-500 hover:text-red-400"
                  >
                    Löschen
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
