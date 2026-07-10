import { Check, Copy, TriangleAlert } from 'lucide-react';
import { useState } from 'react';
import { de } from '../i18n/de';
import type { Suggestion } from '../types';

function CopyBlock({ label, text }: { label: string; text: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <div>
      <div className="mb-1 flex items-center justify-between">
        <span className="text-xs font-medium text-slate-400">{label}</span>
        <button
          type="button" className="fwpt-btn-ghost !px-2 !py-1 text-xs"
          onClick={async () => {
            await navigator.clipboard.writeText(text);
            setCopied(true);
            setTimeout(() => setCopied(false), 1500);
          }}
        >
          {copied ? <Check size={12} /> : <Copy size={12} />}
          {copied ? de.suggestion.copied : de.suggestion.copy}
        </button>
      </div>
      <pre className="max-h-64 overflow-auto rounded-md border border-slate-800 bg-slate-950 p-3 text-xs text-slate-300">
        {text}
      </pre>
    </div>
  );
}

function ObjBadge({ label, obj }: { label: string; obj: { name: string; existing: boolean } }) {
  return (
    <div className="flex items-center gap-2 text-sm">
      <span className="w-20 text-xs text-slate-500">{label}</span>
      <span className="font-mono text-slate-200">{obj.name}</span>
      <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${
        obj.existing ? 'bg-slate-800 text-slate-400' : 'bg-amber-900/60 text-amber-300'
      }`}>
        {obj.existing ? de.suggestion.existingObject : de.suggestion.newObject}
      </span>
    </div>
  );
}

export default function SuggestionCard({ suggestion }: { suggestion: Suggestion }) {
  return (
    <div className="fwpt-card space-y-4 border-amber-900/60">
      <div className="flex items-center gap-2 text-amber-400">
        <TriangleAlert size={16} />
        <h3 className="font-medium text-slate-100">
          {de.suggestion.title} — {suggestion.device}/{suggestion.vdom}
        </h3>
      </div>
      <div className="grid gap-1.5 sm:grid-cols-2">
        <ObjBadge label="Quelle" obj={suggestion.src_obj} />
        <ObjBadge label="Ziel" obj={suggestion.dst_obj} />
        <ObjBadge label="Service" obj={suggestion.service} />
        <div className="flex items-center gap-2 text-sm">
          <span className="w-20 text-xs text-slate-500">Zonen</span>
          <span className="font-mono text-slate-200">
            {suggestion.src_zone} → {suggestion.dst_zone}
          </span>
        </div>
      </div>
      <CopyBlock label={de.suggestion.cli} text={suggestion.cli} />
      <CopyBlock label={de.suggestion.jsonrpc} text={suggestion.jsonrpc.join('\n\n')} />
      <p className="text-xs text-amber-500/90">{suggestion.note}</p>
    </div>
  );
}
