import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { deleteAllTestRuns, deleteTestRun, fetchTestRuns, runTest } from '../api';
import type { TestRun } from '../types';

const SCENARIO_IDS = ['TEST_001', 'SCAN_001', 'DOS_SYN_001', 'RECON_003', 'DNS_DGA_001'] as const;

function statusColor(status: string) {
  switch (status) {
    case 'completed': return 'text-green-400';
    case 'failed':    return 'text-red-400';
    default:          return 'text-yellow-400';
  }
}

export function TestsPage() {
  const { t } = useTranslation();
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
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
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
      setError(err instanceof Error ? err.message : t('tests.deleteFailed'));
    } finally {
      setDeletingId(null);
    }
  };

  const handleDeleteAll = async () => {
    try {
      await deleteAllTestRuns();
      setRuns([]);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('tests.deleteFailed'));
    }
  };

  return (
    <div className="space-y-4">
      {/* Scenarios */}
      <div className="card p-4">
        <h2 className="text-sm font-semibold text-slate-300 mb-3">{t('tests.title')}</h2>
        {error && <p className="text-red-400 text-xs mb-3">{error}</p>}
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {SCENARIO_IDS.map(id => (
            <div key={id} className="bg-slate-800/50 border border-slate-700 rounded p-3 flex flex-col gap-2">
              <div>
                <p className="text-slate-200 text-xs font-medium">{t(`tests.scenarios.${id}.label`)}</p>
                <p className="text-slate-500 text-xs mt-0.5">{t(`tests.scenarios.${id}.desc`)}</p>
                <p className="text-blue-500 text-xs font-mono mt-1">{id}</p>
              </div>
              <button
                onClick={() => trigger(id)}
                disabled={running !== null}
                className="btn-primary self-start mt-auto"
              >
                {running === id ? t('tests.running') : t('tests.start')}
              </button>
            </div>
          ))}
        </div>
      </div>

      {/* Run Log */}
      <div className="card overflow-hidden">
        <div className="px-4 py-2 border-b border-slate-800 flex justify-between items-center">
          <h2 className="text-sm font-semibold text-slate-300">{t('tests.logTitle')}</h2>
          <div className="flex items-center gap-3">
            <span className="text-xs text-slate-500">{t('tests.refreshHint')}</span>
            {runs.length > 0 && (
              <button
                onClick={handleDeleteAll}
                className="text-xs text-slate-500 hover:text-red-400 transition-colors"
                title={t('tests.deleteAllTitle')}
              >
                {t('tests.deleteAll')}
              </button>
            )}
          </div>
        </div>
        <table className="w-full text-xs">
          <thead className="cyjan-table-head text-left">
            <tr>
              <th>{t('tests.columns.time')}</th>
              <th>{t('tests.columns.scenario')}</th>
              <th>{t('tests.columns.status')}</th>
              <th>{t('tests.columns.expected')}</th>
              <th>{t('tests.columns.triggered')}</th>
              <th>{t('tests.columns.latency')}</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {runs.length === 0 && (
              <tr>
                <td colSpan={7} className="text-center text-slate-600 py-8">{t('tests.noRuns')}</td>
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
                    title={t('tests.deleteEntryTitle')}
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
