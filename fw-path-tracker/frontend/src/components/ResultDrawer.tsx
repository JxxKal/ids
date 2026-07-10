import { X } from 'lucide-react';
import { de } from '../i18n/de';
import type { TraceResult } from '../types';

interface Props {
  result: TraceResult;
  onClose: () => void;
}

export default function ResultDrawer({ result, onClose }: Props) {
  return (
    <div className="fixed inset-y-0 right-0 z-30 w-96 overflow-y-auto border-l border-slate-800 bg-slate-900 p-4 shadow-2xl">
      <div className="mb-4 flex items-center justify-between">
        <h2 className="font-medium text-slate-100">{de.drawer.title}</h2>
        <button type="button" className="text-slate-500 hover:text-slate-300" onClick={onClose}>
          <X size={18} />
        </button>
      </div>

      <section className="mb-4">
        <h3 className="mb-1 text-xs font-medium uppercase text-slate-500">{de.drawer.lookupParams}</h3>
        <pre className="rounded-md bg-slate-950 p-2 text-xs text-slate-300">
{JSON.stringify({
  src: result.src.ip, dst: result.dst.ip, protocol: result.protocol,
  dst_port: result.dst_port, src_port: result.src_port,
  icmp_type: result.icmp_type, icmp_code: result.icmp_code,
}, null, 2)}
        </pre>
      </section>

      {result.hops.map((hop) => (
        <section key={hop.index} className="mb-4">
          <h3 className="mb-1 text-xs font-medium uppercase text-slate-500">
            Hop {hop.index + 1}: {hop.device}/{hop.vdom}
          </h3>
          <pre className="rounded-md bg-slate-950 p-2 text-xs text-slate-300">
{JSON.stringify({
  srcintf: hop.srcintf, src_zone: hop.src_zone,
  egress: hop.egress, egress_zone: hop.egress_zone,
  egress_class: hop.egress_class, route: hop.route,
  verdict: hop.verdict, policy_id: hop.matched_policy?.policyid ?? null,
}, null, 2)}
          </pre>
        </section>
      ))}

      {result.warnings.length > 0 && (
        <section className="mb-4">
          <h3 className="mb-1 text-xs font-medium uppercase text-slate-500">{de.drawer.warnings}</h3>
          <ul className="space-y-1 text-xs text-amber-400">
            {result.warnings.map((w) => <li key={w}>{w}</li>)}
          </ul>
        </section>
      )}

      <p className="text-xs text-slate-500">
        {de.drawer.duration}: {result.duration_ms} ms
        {result.inventory_synced_at && (
          <> · {de.drawer.syncedAt} {new Date(result.inventory_synced_at).toLocaleTimeString('de-DE')}</>
        )}
      </p>
    </div>
  );
}
