import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  deleteAllTestRuns, deleteTestRun, fetchTestRuns, runTest,
  fetchFeatureFlags, fetchRedTeamScenarios,
} from '../api';
import type { TestRun, FeatureFlags } from '../types';
import type { RedTeamScenario } from '../types';
import { MobileDesktopHint } from './MobileDesktopHint';
import { ScenarioRunner } from './ScenarioRunner';

// Synthetische Tests — Traffic-Generator injiziert Flows direkt in Kafka.
// Bewusst hardcoded, weil die Backend-Logik je Scenario unterschiedlich ist
// (DOS_SYN_001 generiert N SYNs pro Sekunde, DNS_DGA_001 entropy-DNS-Pakete).
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

  // Feature-Flag + Payload-Scenarios (nur sichtbar wenn redteam_enabled=true)
  const [flags, setFlags]                 = useState<FeatureFlags | null>(null);
  const [payloadScenarios, setPayloadScenarios] = useState<RedTeamScenario[]>([]);

  const load = () =>
    fetchTestRuns()
      .then(setRuns)
      .catch(() => {});

  const loadPayload = async () => {
    try {
      const f = await fetchFeatureFlags();
      setFlags(f);
      if (f.redteam_enabled) {
        setPayloadScenarios(await fetchRedTeamScenarios().catch(() => []));
      }
    } catch { /* feature-flags endpoint unavailable → keep payload-section hidden */ }
  };

  useEffect(() => {
    load();
    loadPayload();
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
      <MobileDesktopHint />

      {/* ───── Section 1: Synthetische Tests ─────
         Traffic-Generator injiziert Flows direkt in Kafka — kein echter
         Netzwerk-Traffic. Zweck: Smoketest der Signature-Engine. */}
      <div className="card p-4">
        <div className="flex items-baseline justify-between gap-2 flex-wrap mb-3">
          <h2 className="text-sm font-semibold text-slate-300">
            🧪 Synthetische Tests
          </h2>
          <p className="text-[11px] text-slate-500">
            Traffic-Generator → Kafka-Flows (kein Netzwerk-Verkehr).
            Smoketest der Cyjan-Signature-Engine.
          </p>
        </div>
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

      {/* ───── Section 2: Payload-Szenarios (RedTeam) ─────
         Nur sichtbar wenn redteam_enabled=true. Spielt YAML-basierte Byte-
         Payloads via kali-shell → veth → cy-inj-peer-Listener; voller
         Pipeline-Test inkl. Suricata-Detection. */}
      {flags?.redteam_enabled && (
        <div className="card p-4">
          <div className="flex items-baseline justify-between gap-2 flex-wrap mb-3">
            <h2 className="text-sm font-semibold text-violet-300">
              🎯 Payload-Szenarios (RedTeam)
            </h2>
            <p className="text-[11px] text-slate-500">
              kali-shell → veth → Listener. Echter Pen-Test der vollen Pipeline
              (Sniffer + Suricata + AI-Rules). Lab-only.
            </p>
          </div>
          <ScenarioRunner scenarios={payloadScenarios} onAuditChange={loadPayload} />
        </div>
      )}

      {/* ───── Section 3: Run Log (Synthetische Tests) ─────
         Nur synth-Runs hier — RedTeam-Runs landen in redteam_audit_log und
         sind unter Settings → RedTeam tooling sichtbar. */}
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

      {/* Cross-Link für RedTeam-Audit-Log */}
      {flags?.redteam_enabled && (
        <p className="text-[11px] text-slate-600 text-center">
          RedTeam-Audit-Log (alle MCP-/REST-Aktionen) unter <em>Settings → RedTeam tooling</em>
        </p>
      )}
    </div>
  );
}
