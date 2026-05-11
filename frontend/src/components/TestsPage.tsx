import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  runTest, fetchFeatureFlags, fetchRedTeamScenarios, fetchRedTeamHealth,
} from '../api';
import type { FeatureFlags, RedTeamScenario, RedTeamHealth } from '../types';
import { MobileDesktopHint } from './MobileDesktopHint';
import { ScenarioRunner } from './ScenarioRunner';
import { ManualToolRun } from './ManualToolRun';
import { UnifiedRunLog } from './UnifiedRunLog';
import { CollapsibleSection } from './CollapsibleSection';

// Synthetische Tests — Traffic-Generator injiziert Flows direkt in Kafka.
// Hardcoded weil die Generator-Logik pro Scenario unterschiedlich ist
// (DOS_SYN_001 = N SYNs/sec, DNS_DGA_001 = high-entropy DNS-Pakete, …).
const SCENARIO_IDS = ['TEST_001', 'SCAN_001', 'DOS_SYN_001', 'RECON_003', 'DNS_DGA_001'] as const;


export function TestsPage() {
  const { t } = useTranslation();
  const [running, setRunning] = useState<string | null>(null);
  const [error, setError]     = useState('');
  const [reloadKey, setReloadKey] = useState(0);  // bumped nach jedem Run → UnifiedRunLog refresht

  // Feature-Flag + RedTeam-Daten
  const [flags, setFlags]                       = useState<FeatureFlags | null>(null);
  const [payloadScenarios, setPayloadScenarios] = useState<RedTeamScenario[]>([]);
  const [health, setHealth]                     = useState<RedTeamHealth | null>(null);

  const loadRedTeam = async () => {
    try {
      const f = await fetchFeatureFlags();
      setFlags(f);
      if (f.redteam_enabled) {
        setPayloadScenarios(await fetchRedTeamScenarios().catch(() => []));
        setHealth(await fetchRedTeamHealth().catch(() => ({ reachable: false, error: 'fetch error' })));
      }
    } catch {
      /* feature-flags-endpoint unavailable → RedTeam-Section hidden */
    }
  };

  useEffect(() => { loadRedTeam(); }, []);

  const triggerSynth = async (scenarioId: string) => {
    setRunning(scenarioId);
    setError('');
    try {
      await runTest(scenarioId);
      setReloadKey(k => k + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : t('common.errorGeneric'));
    } finally {
      setRunning(null);
    }
  };

  const bumpLog = () => setReloadKey(k => k + 1);

  return (
    <div className="space-y-4">
      <MobileDesktopHint />

      {/* ───── 🧪 Synthetische Tests ─────
         Traffic-Generator injiziert Flows direkt in Kafka — kein echter
         Netzwerk-Traffic. Smoketest der Cyjan-Signature-Engine. */}
      <CollapsibleSection
        storageKey="cyjan-scenarios-section-synthetic"
        title={<span className="text-blue-300">🧪 Synthetische Tests</span>}
        subtitle="Traffic-Generator → Kafka-Flows (kein Netzwerk-Verkehr)"
      >
        {error && <p className="text-red-400 text-xs mb-3 break-words">{error}</p>}
        <div className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
          {SCENARIO_IDS.map(id => (
            <div key={id} className="bg-slate-800/50 border border-slate-700 rounded p-3 flex flex-col gap-2">
              <div>
                <p className="text-slate-200 text-xs font-medium">{t(`tests.scenarios.${id}.label`)}</p>
                <p className="text-slate-500 text-xs mt-0.5">{t(`tests.scenarios.${id}.desc`)}</p>
                <p className="text-blue-500 text-xs font-mono mt-1">{id}</p>
              </div>
              <button
                onClick={() => triggerSynth(id)}
                disabled={running !== null}
                className="btn-primary self-start mt-auto"
              >
                {running === id ? t('tests.running') : t('tests.start')}
              </button>
            </div>
          ))}
        </div>
      </CollapsibleSection>

      {/* ───── 🎯 Payload-Szenarios (RedTeam) ───── */}
      {flags?.redteam_enabled && (
        <CollapsibleSection
          storageKey="cyjan-scenarios-section-payload"
          title={<span className="text-violet-300">🎯 Payload-Szenarios (RedTeam)</span>}
          subtitle={`${payloadScenarios.length} YAMLs · kali→veth→Listener · Lab-only`}
        >
          {/* Orchestrator-Health-Indikator */}
          {health && !health.reachable && (
            <div className="bg-amber-500/10 border border-amber-500/40 rounded p-2 text-[11px] text-amber-300 mb-3">
              ⚠ Orchestrator nicht erreichbar — Runs werden 503 zurückbekommen.
              {health.error && <span className="text-amber-400/70 ml-2 break-words">{health.error}</span>}
            </div>
          )}
          <ScenarioRunner scenarios={payloadScenarios} onAuditChange={bumpLog} />
        </CollapsibleSection>
      )}

      {/* ───── 🔧 Manueller Tool-Run ───── */}
      {flags?.redteam_enabled && (
        <CollapsibleSection
          storageKey="cyjan-scenarios-section-manual"
          title={<span className="text-cyan-300">🔧 Manueller Tool-Run</span>}
          subtitle="Direkter kali-Aufruf (nmap/hping3/hydra/ncat/ping)"
          defaultOpen={false}
        >
          <ManualToolRun onRunComplete={bumpLog} />
        </CollapsibleSection>
      )}

      {/* ───── Unified Run Log ─────
         Merged: test_runs (synthetisch) + redteam_audit_log (alle MCP-/REST-
         Aktionen). Chronologisch absteigend, color-coded nach Aktionstyp,
         Filter-Chips pro Typ. */}
      <UnifiedRunLog key={reloadKey} redteamEnabled={!!flags?.redteam_enabled} />
    </div>
  );
}
