import { Handle, Position } from '@xyflow/react';
import { ChevronDown, ChevronRight, CloudOff, Shield, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { de } from '../../i18n/de';
import type { Hop } from '../../types';
import RulesetTable from '../RulesetTable';

export interface FirewallNodeData {
  hop: Hop;
  onSuggest: (hop: Hop) => void;
  [key: string]: unknown;
}

const verdictStyles: Record<string, string> = {
  ALLOW: 'bg-emerald-900/70 text-emerald-300 ring-emerald-700',
  DENY: 'bg-red-900/70 text-red-300 ring-red-700',
  UNKNOWN: 'bg-amber-900/70 text-amber-300 ring-amber-700',
};

export default function FirewallNode({ data }: { data: FirewallNodeData }) {
  const { hop, onSuggest } = data;
  const [expanded, setExpanded] = useState(false);
  const dim = hop.after_deny ? 'opacity-40' : '';

  return (
    <div className={`w-72 rounded-lg border bg-slate-900 shadow-lg ${dim} ${
      hop.verdict === 'DENY' ? 'border-red-800' : hop.degraded ? 'border-amber-800' : 'border-slate-700'
    }`}>
      <Handle type="target" position={Position.Left} className="!bg-cyan-600" />
      <Handle type="source" position={Position.Right} className="!bg-cyan-600" />

      <div className="flex items-center gap-2 border-b border-slate-800 p-3">
        <Shield size={18} className={hop.verdict === 'DENY' ? 'text-red-400' : 'text-cyan-400'} />
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-slate-100">{hop.device}</p>
          <p className="text-xs text-slate-500">
            {hop.srcintf} → {hop.egress ?? '?'}
          </p>
        </div>
        <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] font-medium text-slate-300">
          {hop.vdom}
        </span>
        <span className={`rounded-full px-2 py-0.5 text-[11px] font-semibold ring-1 ring-inset ${
          verdictStyles[hop.verdict]
        }`}>
          {de.verdict[hop.verdict]}
        </span>
      </div>

      <div className="space-y-1.5 p-3 text-xs">
        {hop.degraded && (
          <p className="flex items-center gap-1.5 text-amber-400">
            <CloudOff size={12} /> {de.hop.degraded}
          </p>
        )}
        {hop.matched_policy ? (
          <p className="truncate text-slate-300">
            {de.hop.matched}:{' '}
            <span className="font-mono text-cyan-300">
              #{hop.matched_policy.policyid} {hop.matched_policy.name}
            </span>
          </p>
        ) : hop.verdict === 'DENY' ? (
          <p className="text-red-400">{de.hop.implicitDeny}</p>
        ) : null}
        {hop.warnings.map((w) => (
          <p key={w} className="flex items-start gap-1.5 text-amber-500/90">
            <TriangleAlert size={12} className="mt-0.5 shrink-0" />
            <span>{w}</span>
          </p>
        ))}
        <div className="flex items-center gap-2 pt-1">
          <button
            type="button"
            className="flex items-center gap-1 text-slate-400 hover:text-cyan-400"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
            {de.hop.candidates} ({hop.candidates.length})
          </button>
          {hop.verdict === 'DENY' && hop.suggestion && (
            <button
              type="button"
              className="ml-auto rounded bg-amber-900/60 px-2 py-0.5 text-[11px] font-medium text-amber-300 hover:bg-amber-800/60"
              onClick={() => onSuggest(hop)}
            >
              {de.hop.suggestion}
            </button>
          )}
        </div>
      </div>

      {expanded && (
        <div className="border-t border-slate-800">
          <RulesetTable candidates={hop.candidates} />
        </div>
      )}
    </div>
  );
}
