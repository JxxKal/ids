import { de } from '../i18n/de';
import type { Candidate } from '../types';

export default function RulesetTable({ candidates }: { candidates: Candidate[] }) {
  if (candidates.length === 0) {
    return <p className="p-2 text-xs text-slate-500">—</p>;
  }
  return (
    <div className="max-h-56 overflow-auto">
      <table className="w-full text-left text-xs">
        <thead className="sticky top-0 bg-slate-900 text-slate-500">
          <tr>
            <th className="px-2 py-1 font-medium">ID</th>
            <th className="px-2 py-1 font-medium">Name</th>
            <th className="px-2 py-1 font-medium">Aktion</th>
            <th className="px-2 py-1 font-medium">Quelle</th>
            <th className="px-2 py-1 font-medium">Ziel</th>
            <th className="px-2 py-1 font-medium">Service</th>
          </tr>
        </thead>
        <tbody>
          {candidates.map((c) => (
            <tr
              key={c.policyid ?? c.name}
              className={
                c.hit
                  ? 'bg-cyan-950/60 text-cyan-200 ring-1 ring-inset ring-cyan-700'
                  : 'text-slate-400'
              }
              title={c.hit ? de.hop.matched : undefined}
            >
              <td className="px-2 py-1 font-mono">{c.policyid}</td>
              <td className="max-w-32 truncate px-2 py-1">{c.name}</td>
              <td className={`px-2 py-1 font-medium ${c.action === 'accept' ? 'text-emerald-400' : 'text-red-400'}`}>
                {c.action}
              </td>
              <td className="max-w-28 truncate px-2 py-1">{c.srcaddr.join(', ')}</td>
              <td className="max-w-28 truncate px-2 py-1">{c.dstaddr.join(', ')}</td>
              <td className="max-w-24 truncate px-2 py-1">{c.service.join(', ')}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
