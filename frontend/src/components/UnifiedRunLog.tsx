// ── UnifiedRunLog — merged Synth-Tests + RedTeam-Audit-Trail ────────────────
//
// Quellen:
//   1. test_runs                  (synthetische Cyjan-Tests, traffic-generator)
//   2. redteam_audit_log          (alle MCP-/REST-Aktionen am Orchestrator —
//                                  run_kali_tool, run_payload_scenario,
//                                  create/delete_payload_scenario,
//                                  create/delete_suricata_rule)
//
// Beide werden parallel gefetched, normalisiert auf ein Common-Shape und
// chronologisch absteigend gemerged. Color-coded Badge pro Typ macht die
// Aktion auf einen Blick erkennbar.

import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import {
  deleteAllTestRuns, deleteTestRun, fetchTestRuns, fetchRedTeamAuditLog,
} from '../api';
import type { TestRun, RedTeamAuditEntry } from '../types';


type EntryType =
  | 'synthetic'
  | 'tool'
  | 'scenario'
  | 'scenario_create'
  | 'scenario_delete'
  | 'rule_create'
  | 'rule_delete'
  | 'other';

interface UnifiedEntry {
  id:           string;
  ts:           string;        // ISO timestamp
  type:         EntryType;
  label:        string;
  detail:       string;
  target:       string | null;
  duration_ms:  number | null;
  status:       'ok' | 'failed' | 'pending' | 'rejected';
  raw_audit?:   RedTeamAuditEntry;
  raw_synth?:   TestRun;
}


function mapTestRun(r: TestRun): UnifiedEntry {
  return {
    id:          `synth:${r.id}`,
    ts:          r.started_at,
    type:        'synthetic',
    label:       `Synthetic Test: ${r.scenario_id}`,
    detail:      [
                  r.expected_rule ? `erwartet=${r.expected_rule}` : '',
                  r.triggered === true ? 'detected ✓' : r.triggered === false ? 'NOT detected ✗' : '',
                  r.latency_ms != null ? `${r.latency_ms} ms` : '',
                ].filter(Boolean).join(' · '),
    target:      null,
    duration_ms: r.latency_ms ?? null,
    status:      r.status === 'completed' ? 'ok' :
                 r.status === 'failed' ? 'failed' : 'pending',
    raw_synth:   r,
  };
}


function mapAuditEntry(e: RedTeamAuditEntry): UnifiedEntry {
  const rs = (e.result_summary || {}) as Record<string, unknown>;
  let type: EntryType = 'other';
  let label = e.mcp_tool;
  let detail = '';

  if (e.mcp_tool === 'run_payload_scenario_v1') {
    type   = 'scenario';
    const sid = String(rs.scenario_id ?? '?');
    const via = rs.via ? ` (${rs.via})` : '';
    label  = `Payload-Scenario: ${sid}${via}`;
    detail = [
      rs.sent_bytes != null ? `sent=${rs.sent_bytes} B` : '',
      rs.matched_alerts != null ? `alerts=${rs.matched_alerts}` : '',
      rs.expected_rule ? `erwartet=${rs.expected_rule}` : '',
    ].filter(Boolean).join(' · ');
  } else if (e.mcp_tool === 'run_kali_tool_v1') {
    type = 'tool';
    let argsDetail = '';
    try {
      const arr = JSON.parse(e.args_excerpt || '[]');
      if (Array.isArray(arr) && arr.length > 0) argsDetail = ' ' + arr.join(' ');
    } catch { /* ignore */ }
    // tool name könnte in result_summary stehen — sonst aus args inferieren
    label = `Kali-Tool${argsDetail}`;
    detail = [
      `exit=${rs.exit_code ?? '?'}`,
      rs.matched_alerts != null ? `alerts=${rs.matched_alerts}` : '',
      rs.expected_rule ? `erwartet=${rs.expected_rule}` : '',
    ].filter(Boolean).join(' · ');
  } else if (e.mcp_tool === 'create_payload_scenario_v1') {
    type   = 'scenario_create';
    label  = `Scenario angelegt: ${rs.scenario_id ?? '?'}`;
    detail = String(rs.path ?? '');
  } else if (e.mcp_tool === 'delete_payload_scenario_v1') {
    type   = 'scenario_delete';
    label  = `Scenario gelöscht: ${rs.scenario_id ?? '?'}`;
    detail = rs.removed ? 'removed=true' : 'nicht gefunden';
  } else if (e.mcp_tool === 'create_suricata_rule_v1') {
    type = 'rule_create';
    const replaced = rs.replaced_existing ? ' (ersetzt)' : '';
    label = `Suricata-Rule SID ${rs.sid ?? '?'} geschrieben${replaced}`;
    detail = `${rs.proto ?? '?'}/${rs.dst_port ?? '?'} — ${String(rs.msg ?? '').slice(0, 60)}`;
  } else if (e.mcp_tool === 'delete_suricata_rule_v1') {
    type   = 'rule_delete';
    label  = `Suricata-Rule SID ${rs.sid ?? '?'} gelöscht`;
    detail = rs.removed ? 'removed=true' : 'nicht gefunden';
  }

  const status: UnifiedEntry['status'] =
    e.decision === 'allowed' ? 'ok' :
    e.decision === 'rejected_validation' ? 'rejected' :
    e.decision === 'rejected_rate_limit' ? 'rejected' : 'ok';

  return {
    id:          `audit:${e.id}`,
    ts:          e.ts,
    type, label, detail,
    target:      e.target_ip,
    duration_ms: e.duration_ms,
    status,
    raw_audit:   e,
  };
}


const TYPE_META: Record<EntryType, { label: string; classes: string; bgFor: string }> = {
  synthetic:       { label: '🧪 SYNTH',    classes: 'text-blue-300',   bgFor: 'bg-blue-500/15' },
  tool:            { label: '🔧 TOOL',     classes: 'text-cyan-300',   bgFor: 'bg-cyan-500/15' },
  scenario:        { label: '🎯 SCENARIO', classes: 'text-violet-300', bgFor: 'bg-violet-500/15' },
  scenario_create: { label: '+ SCEN',      classes: 'text-emerald-300', bgFor: 'bg-emerald-500/15' },
  scenario_delete: { label: '– SCEN',      classes: 'text-slate-400',  bgFor: 'bg-slate-500/15' },
  rule_create:     { label: '+ RULE',      classes: 'text-amber-300',  bgFor: 'bg-amber-500/15' },
  rule_delete:     { label: '– RULE',      classes: 'text-slate-400',  bgFor: 'bg-slate-500/15' },
  other:           { label: '?',           classes: 'text-slate-500',  bgFor: 'bg-slate-500/15' },
};


export function UnifiedRunLog({ redteamEnabled }: { redteamEnabled: boolean }) {
  const { t } = useTranslation();
  const [entries, setEntries] = useState<UnifiedEntry[]>([]);
  const [filter, setFilter]   = useState<EntryType | 'all'>('all');
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const reload = async () => {
    const [synth, audit] = await Promise.all([
      fetchTestRuns().catch(() => []),
      redteamEnabled ? fetchRedTeamAuditLog(50).catch(() => []) : Promise.resolve([]),
    ]);
    const merged = [
      ...synth.map(mapTestRun),
      ...audit.map(mapAuditEntry),
    ].sort((a, b) => b.ts.localeCompare(a.ts));
    setEntries(merged);
  };

  useEffect(() => {
    reload();
    const id = setInterval(reload, 5000);
    return () => clearInterval(id);
  }, [redteamEnabled]);

  const filtered = filter === 'all' ? entries : entries.filter(e => e.type === filter);

  // Count per type — für Filter-Buttons
  const counts: Record<string, number> = { all: entries.length };
  entries.forEach(e => { counts[e.type] = (counts[e.type] || 0) + 1; });

  async function handleDelete(entry: UnifiedEntry) {
    if (entry.type !== 'synthetic' || !entry.raw_synth) return;
    setDeletingId(entry.id);
    try {
      await deleteTestRun(entry.raw_synth.id);
      setEntries(prev => prev.filter(x => x.id !== entry.id));
    } finally {
      setDeletingId(null);
    }
  }

  async function handleDeleteAllSynth() {
    if (!confirm(t('tests.deleteAllTitle'))) return;
    await deleteAllTestRuns();
    reload();
  }

  return (
    <div className="card overflow-hidden">
      <div className="px-4 py-2 border-b border-slate-800 flex justify-between items-center flex-wrap gap-2">
        <h2 className="text-sm font-semibold text-slate-300">
          Run Log <span className="text-slate-600 normal-case">({entries.length})</span>
        </h2>
        <div className="flex items-center gap-3 flex-wrap">
          {/* Filter-Chips pro Typ */}
          <div className="flex gap-1 flex-wrap">
            <FilterChip active={filter === 'all'} count={counts.all || 0}
              onClick={() => setFilter('all')}
              label="Alle" classes="text-slate-300" />
            {(['synthetic', 'tool', 'scenario', 'scenario_create', 'rule_create'] as EntryType[]).map(t => {
              const c = counts[t] || 0;
              if (c === 0) return null;
              return (
                <FilterChip key={t} active={filter === t} count={c}
                  onClick={() => setFilter(t)}
                  label={TYPE_META[t].label} classes={TYPE_META[t].classes} />
              );
            })}
          </div>
          {counts.synthetic > 0 && (
            <button onClick={handleDeleteAllSynth}
              className="text-xs text-slate-500 hover:text-red-400 transition-colors"
              title="Alle synth-Runs löschen">
              {t('tests.deleteAll')}
            </button>
          )}
        </div>
      </div>

      <div className="p-3 space-y-1.5">
        {filtered.length === 0 && (
          <p className="text-[11px] text-slate-600 text-center py-6 italic">
            {filter === 'all'
              ? 'Noch keine Runs in dieser Woche.'
              : `Keine ${TYPE_META[filter as EntryType]?.label}-Einträge.`}
          </p>
        )}
        {filtered.map(e => (
          <div key={e.id}
               className="bg-slate-900/30 border border-slate-800/60 rounded p-2 text-[11px]">
            <div className="flex items-baseline justify-between gap-2 mb-1 flex-wrap">
              <div className="flex items-baseline gap-2 flex-wrap">
                <span className={`px-1.5 py-0.5 rounded text-[9px] font-mono whitespace-nowrap ${TYPE_META[e.type].bgFor} ${TYPE_META[e.type].classes}`}>
                  {TYPE_META[e.type].label}
                </span>
                <span className="text-slate-500 font-mono text-[10px] whitespace-nowrap">
                  {new Date(e.ts).toLocaleString()}
                </span>
              </div>
              <div className="flex items-baseline gap-2 ml-auto">
                {e.status !== 'ok' && (
                  <span className={`px-1.5 py-0.5 rounded text-[10px] whitespace-nowrap ${
                    e.status === 'failed' ? 'bg-red-500/15 text-red-300' :
                    e.status === 'rejected' ? 'bg-amber-500/15 text-amber-300' :
                    'bg-slate-500/15 text-slate-400'
                  }`}>{e.status}</span>
                )}
                <span className="text-slate-400 font-mono text-[10px] tabular-nums whitespace-nowrap">
                  {e.duration_ms != null ? `${e.duration_ms} ms` : '—'}
                </span>
                {e.type === 'synthetic' && (
                  <button
                    onClick={() => handleDelete(e)}
                    disabled={deletingId === e.id}
                    className="text-slate-600 hover:text-red-400 transition-colors disabled:opacity-40 text-[11px]"
                    title="Eintrag löschen">
                    ✕
                  </button>
                )}
              </div>
            </div>

            <div className={`font-mono ${TYPE_META[e.type].classes} break-words`}>{e.label}</div>
            {(e.detail || e.target) && (
              <div className="text-slate-400 mt-0.5 break-words">
                {e.detail}
                {e.target && (
                  <span className="text-slate-600 ml-2 font-mono">→ {e.target}</span>
                )}
              </div>
            )}
            {e.raw_audit?.reject_reason && (
              <div className="text-red-400 text-[10px] mt-0.5 break-words">{e.raw_audit.reject_reason}</div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}


function FilterChip({
  active, count, onClick, label, classes,
}: {
  active:  boolean;
  count:   number;
  onClick: () => void;
  label:   string;
  classes: string;
}) {
  return (
    <button onClick={onClick}
      className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${
        active
          ? `border-cyan-500/60 bg-cyan-500/10 ${classes}`
          : `border-slate-700 hover:border-slate-500 ${classes} opacity-60 hover:opacity-100`
      }`}>
      {label} <span className="tabular-nums">({count})</span>
    </button>
  );
}
