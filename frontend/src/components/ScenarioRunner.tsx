// ── ScenarioRunner — Payload-Scenarios mit Run-Button + Result ──────────────
//
// Eigenständige Komponente — wird sowohl auf der ScenariosPage (Hauptmenü)
// als auch ggf. an anderen Stellen embedded. Hält ihren eigenen Form-State
// (Target-IP, Timeout, Filter) und Result-State.

import { useState } from 'react';
import { runRedTeamScenario } from '../api';
import type { RedTeamScenario, RedTeamScenarioRunResponse } from '../types';


export function ScenarioRunner({
  scenarios, onAuditChange,
}: {
  scenarios:     RedTeamScenario[];
  onAuditChange: () => void;
}) {
  const [targetIp, setTargetIp]   = useState('192.0.2.254');
  const [timeout, setTimeout_]    = useState(10);
  const [running, setRunning]     = useState<string | null>(null);
  const [results, setResults]     = useState<Record<string, RedTeamScenarioRunResponse>>({});
  const [errors, setErrors]       = useState<Record<string, string>>({});
  const [filter, setFilter]       = useState('');

  // Group nach Verzeichnis: templates/ vor generated/ vor imported/ — gibt
  // Builtin-Library-vs-User-Generated-Lifecycle visuell wieder.
  const groups: Record<string, typeof scenarios> = {};
  scenarios.forEach(s => {
    const folder = s.file?.split('/')[0] || 'andere';
    (groups[folder] ??= []).push(s);
  });

  const visible = (s: RedTeamScenario) => {
    if (!filter) return true;
    const q = filter.toLowerCase();
    return (
      s.scenario_id.toLowerCase().includes(q) ||
      (s.description ?? '').toLowerCase().includes(q) ||
      (s.tags ?? []).some(t => t.toLowerCase().includes(q))
    );
  };

  async function handleRun(scenarioId: string) {
    if (!targetIp.trim()) return;
    setRunning(scenarioId);
    setErrors(prev => { const n = { ...prev }; delete n[scenarioId]; return n; });
    try {
      const r = await runRedTeamScenario({
        scenario_id: scenarioId, target_ip: targetIp.trim(), timeout_sec: timeout,
      });
      setResults(prev => ({ ...prev, [scenarioId]: r }));
      onAuditChange();
    } catch (e) {
      setErrors(prev => ({
        ...prev,
        [scenarioId]: e instanceof Error ? e.message : 'Run fehlgeschlagen',
      }));
    } finally {
      setRunning(null);
    }
  }

  return (
    <div className="border border-slate-800 rounded p-3 space-y-3">
      <div className="flex flex-wrap items-end justify-between gap-3">
        <div>
          <h3 className="text-[11px] uppercase tracking-wider text-slate-500">
            Payload-Szenarios ({scenarios.length})
          </h3>
          <p className="text-[11px] text-slate-600 mt-0.5">
            YAMLs aus <code className="font-mono">/scenarios/&#123;templates,generated,imported&#125;/</code>.
            Klick auf <em>Run</em> spielt das Scenario gegen target-IP ab und pollt 10 s
            auf das <code className="font-mono">expected_alert_rule_id</code>.
          </p>
        </div>
        <div className="flex gap-2 items-end flex-wrap">
          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-slate-500">Target-IP</label>
            <input className="input font-mono text-xs h-7 w-32" value={targetIp}
              onChange={e => setTargetIp(e.target.value)} placeholder="192.0.2.254" />
          </div>
          <div className="flex flex-col gap-1">
            <label className="text-[10px] text-slate-500">Timeout</label>
            <input className="input text-xs h-7 w-16" type="number" min={1} max={60}
              value={timeout} onChange={e => setTimeout_(parseInt(e.target.value) || 10)} />
          </div>
          <input className="input text-xs h-7 w-40" value={filter}
            onChange={e => setFilter(e.target.value)} placeholder="Filter (id, tag, …)" />
        </div>
      </div>

      {scenarios.length === 0 && (
        <p className="text-[11px] text-slate-600">
          Keine Szenarios vorhanden. Builtin-Templates kommen mit dem orchestrator-Image,
          KI-generierte über MCP <code className="font-mono">create_payload_scenario_v1</code>.
        </p>
      )}

      {Object.entries(groups).map(([folder, items]) => {
        const filtered = items.filter(visible);
        if (filtered.length === 0) return null;
        const folderColor = folder === 'templates' ? 'text-cyan-300' :
                            folder === 'generated' ? 'text-emerald-300' :
                            folder === 'imported'  ? 'text-amber-300' :
                            'text-slate-400';
        return (
          <div key={folder} className="space-y-1">
            <p className={`text-[10px] uppercase tracking-wider ${folderColor}`}>
              {folder}/ <span className="text-slate-600 normal-case">({filtered.length})</span>
            </p>
            <div className="space-y-1">
              {filtered.map(s => {
                const res = results[s.scenario_id];
                const err = errors[s.scenario_id];
                const isRunning = running === s.scenario_id;
                return (
                  <div key={s.scenario_id}
                       className="bg-slate-900/40 border border-slate-800/60 rounded p-2 text-[11px]">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-baseline gap-2 flex-wrap">
                          <span className="font-mono text-slate-200">{s.scenario_id}</span>
                          {s.protocol && s.target_port && (
                            <span className="font-mono text-slate-600">
                              {s.protocol}/{s.target_port}
                            </span>
                          )}
                          {s.expected_alert_rule_id && (
                            <span className="font-mono text-slate-500 break-all">
                              → {s.expected_alert_rule_id}
                            </span>
                          )}
                        </div>
                        {s.description && (
                          <p className="text-slate-500 mt-0.5 break-words">{s.description}</p>
                        )}
                        {(s.tags?.length || s.mitre?.length) ? (
                          <div className="flex gap-1 flex-wrap mt-1">
                            {s.tags?.map(t => (
                              <span key={t} className="text-[10px] px-1 rounded bg-slate-800/70 text-slate-400">
                                {t}
                              </span>
                            ))}
                            {s.mitre?.map(m => (
                              <span key={m} className="text-[10px] px-1 rounded bg-violet-500/10 text-violet-300 font-mono">
                                {m}
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </div>
                      <button
                        onClick={() => handleRun(s.scenario_id)}
                        disabled={isRunning || running !== null || !targetIp.trim()}
                        className="btn-primary text-[11px] px-3 py-1 self-start whitespace-nowrap"
                      >
                        {isRunning ? '⋯' : 'Run'}
                      </button>
                    </div>
                    {(res || err) && (
                      <div className="mt-2 pt-2 border-t border-slate-800/50">
                        {err && <span className="text-red-400 break-words">{err}</span>}
                        {res && (
                          <div className="flex items-center gap-3 flex-wrap font-mono text-[10px]">
                            <span className={res.exit_code === 0 ? 'text-emerald-400' : 'text-amber-400'}>
                              exit={res.exit_code}
                            </span>
                            <span className="text-slate-500">
                              sent={res.sent_bytes ?? '–'} B
                            </span>
                            <span className="text-slate-500">{res.duration_ms} ms</span>
                            <span className={
                              res.detection_success === true  ? 'text-emerald-400' :
                              res.detection_success === false ? 'text-amber-400' :
                              'text-slate-600'
                            }>
                              alerts={res.matched_alerts.length}
                              {res.expected_rule && ` (erwartet: ${res.expected_rule})`}
                            </span>
                            {res.stderr_excerpt && (
                              <span className="text-red-400 truncate max-w-md">
                                stderr: {res.stderr_excerpt.slice(0, 80)}
                              </span>
                            )}
                          </div>
                        )}
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        );
      })}
    </div>
  );
}
