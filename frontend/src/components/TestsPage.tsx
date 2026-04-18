import { useEffect, useState } from 'react';
import { deleteAllTestRuns, deleteTestRun, fetchTestRuns, runTest } from '../api';
import type { TestRun } from '../types';

const SCENARIOS = [
  { id: 'TEST_001',    label: 'IDS Test Signature',   desc: 'EICAR-Äquivalent: TCP SYN+FIN+URG+PSH an Port 65535' },
  { id: 'SCAN_001',   label: 'TCP SYN Port Scan',     desc: '55 SYN-Flows an verschiedene Ports' },
  { id: 'DOS_SYN_001',label: 'SYN Flood',             desc: '510 SYN-Flows → syn_count > 500 in 10s' },
  { id: 'RECON_003',  label: 'RST-Verbindungsflut',   desc: '55 TCP-RST-Flows → flow_rate > 50 in 60s' },
  { id: 'DNS_DGA_001',label: 'DNS High-Entropy (DGA)', desc: 'UDP/53 mit hoher IAT-Entropie' },
];

function statusColor(status: string) {
  switch (status) {
    case 'completed': return 'text-green-400';
    case 'failed':    return 'text-red-400';
    default:          return 'text-yellow-400';
  }
}

export function TestsPage() {
  const [runs, setRuns]             = useState<TestRun[]>([]);
  const [running, setRunning]       = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [error, setError]           = useState('');

  const load = () =>
    fetchTestRuns()
      .then(setRuns)
      .catch(() => {});

  useEffect(() => {
    load();
    const id = setInterval(load, 5000);
    return () => clearInterval(id);
  }, []);

  const trigger = async (scenarioId: string) => {
    setRunning(scenarioId);
    setError('');
    try {
      await runTest(scenarioId);
      load();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Fehler');
    } finally {
      setRunning(null);
    }
  };

  const handleDelete = async (runId: string) => {
    setDeletingId(runId);
    try {
      await deleteTestRun(runId);
      setRuns(prev => prev.filter(r => r.id !== runId));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Löschen fehlgeschlagen');
    } finally {
      setDeletingId(null);
    }
  };

  const handleDeleteAll = async () => {
    try {
      await deleteAllTestRuns();
      setRuns([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Löschen fehlgeschlagen');
    }
  };

  return (
    <div className="space-y-4">
      {/* Scenarios */}
      <div className="card p-4">
        <h2 className="text-sm font-semibold text-slate-300 mb-3">Test-Szenarien</h2>
        {error && <p className="text-red-400 text-xs mb-3">{error}</p>}
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {SCENARIOS.map(s => (
            <div key={s.id} className="bg-slate-800/50 border border-slate-700 rounded p-3 flex flex-col gap-2">
              <div>
                <p className="text-slate-200 text-xs font-medium">{s.label}</p>
                <p className="text-slate-500 text-xs mt-0.5">{s.desc}</p>
                <p className="text-blue-500 text-xs font-mono mt-1">{s.id}</p>
              </div>
              <button
                onClick={() => trigger(s.id)}
                disabled={running !== null}
                className="btn-primary self-start mt-auto"
              >
                {running === s.id ? 'Läuft…' : 'Starten'}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Run Log */}
      <div className="card overflow-hidden">
        <div className="px-4 py-2 border-b border-slate-800 flex justify-between items-center">
          <h2 className="text-sm font-semibold text-slate-300">Protokoll</h2>
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-500">Aktualisierung alle 5s</span>
            {runs.length > 0 && (
              <button
                onClick={handleDeleteAll}
                className="text-xs text-slate-500 hover:text-red-400 transition-colors"
                title="Alle Einträge löschen"
              >
                Alle löschen
              </button>
            )}
          </div>
        </div>
        <table className="w-full text-xs">
          <thead className="border-b border-slate-800 text-slate-500 text-left">
            <tr>
              <th className="px-4 py-2">Zeit</th>
              <th className="px-4 py-2">Szenario</th>
              <th className="px-4 py-2">Status</th>
              <th className="px-4 py-2">Erwartet</th>
              <th className="px-4 py-2">Ausgelöst</th>
              <th className="px-4 py-2">Latenz</th>
              <th className="px-4 py-2"></th>
            </tr>
          </thead>
          <tbody>
            {runs.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center text-slate-600 py-8">Noch keine Tests</td>
              </tr>
            )}
            {runs.map(r => (
              <tr key={r.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                <td className="px-4 py-2 text-slate-500 whitespace-nowrap">
                  {new Date(r.started_at).toLocaleTimeString()}
                </td>
                <td className="px-4 py-2 text-slate-300">{r.scenario_id}</td>
                <td className={`px-4 py-2 font-medium ${statusColor(r.status)}`}>{r.status}</td>
                <td className="px-4 py-2 text-slate-400">{r.expected_rule ?? '–'}</td>
                <td className="px-4 py-2">
                  {r.triggered == null ? '–' : r.triggered
                    ? <span className="text-green-400">✓</span>
                    : <span className="text-red-400">✗</span>
                  }
                </td>
                <td className="px-4 py-2 text-slate-400 tabular-nums">
                  {r.latency_ms != null ? `${r.latency_ms} ms` : '–'}
                </td>
                <td className="px-4 py-2">
                  <button
                    onClick={() => handleDelete(r.id)}
                    disabled={deletingId === r.id}
                    className="text-slate-600 hover:text-red-400 transition-colors disabled:opacity-40"
                    title="Eintrag löschen"
                  >
                    ✕
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
