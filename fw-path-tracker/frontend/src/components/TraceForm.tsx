import { ArrowLeftRight, Play } from 'lucide-react';
import { FormEvent, useState } from 'react';
import { de } from '../i18n/de';
import type { TraceRequest } from '../types';
import EndpointAutocomplete from './EndpointAutocomplete';

interface Props {
  onSubmit: (req: TraceRequest) => void;
  busy: boolean;
  initial?: TraceRequest | null;
}

export default function TraceForm({ onSubmit, busy, initial }: Props) {
  const [src, setSrc] = useState(initial?.src ?? '');
  const [dst, setDst] = useState(initial?.dst ?? '');
  const [protocol, setProtocol] = useState(initial?.protocol ?? 'tcp');
  const [dstPort, setDstPort] = useState(initial?.dst_port ? String(initial.dst_port) : '443');
  const [srcPort, setSrcPort] = useState('');
  const [icmpType, setIcmpType] = useState('8');
  const [icmpCode, setIcmpCode] = useState('0');

  function build(swap = false): TraceRequest {
    const isIcmp = protocol === 'icmp';
    return {
      src: swap ? dst : src,
      dst: swap ? src : dst,
      protocol,
      dst_port: isIcmp ? null : Number(dstPort) || null,
      src_port: isIcmp || !srcPort ? null : Number(srcPort),
      icmp_type: isIcmp ? Number(icmpType) : null,
      icmp_code: isIcmp ? Number(icmpCode) : null,
    };
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (src.trim() && dst.trim()) onSubmit(build());
  }

  const isIcmp = protocol === 'icmp';

  return (
    <form onSubmit={submit} className="fwpt-card flex flex-wrap items-end gap-3">
      <div className="min-w-56 flex-1">
        <label className="mb-1 block text-xs text-slate-400">{de.trace.src}</label>
        <EndpointAutocomplete value={src} onChange={setSrc} placeholder="10.1.1.10 / ws0042" />
      </div>
      <div className="min-w-56 flex-1">
        <label className="mb-1 block text-xs text-slate-400">{de.trace.dst}</label>
        <EndpointAutocomplete value={dst} onChange={setDst} placeholder="10.2.1.30 / srv-db" />
      </div>
      <div>
        <label className="mb-1 block text-xs text-slate-400">{de.trace.protocol}</label>
        <select className="fwpt-input" value={protocol} onChange={(e) => setProtocol(e.target.value)}>
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="icmp">ICMP</option>
        </select>
      </div>
      {!isIcmp && (
        <>
          <div className="w-28">
            <label className="mb-1 block text-xs text-slate-400">{de.trace.dstPort}</label>
            <input className="fwpt-input" value={dstPort} inputMode="numeric"
              onChange={(e) => setDstPort(e.target.value)} />
          </div>
          <div className="w-32">
            <label className="mb-1 block text-xs text-slate-400">{de.trace.srcPort}</label>
            <input className="fwpt-input" value={srcPort} inputMode="numeric"
              onChange={(e) => setSrcPort(e.target.value)} placeholder="—" />
          </div>
        </>
      )}
      {isIcmp && (
        <>
          <div className="w-24">
            <label className="mb-1 block text-xs text-slate-400">{de.trace.icmpType}</label>
            <input className="fwpt-input" value={icmpType} inputMode="numeric"
              onChange={(e) => setIcmpType(e.target.value)} />
          </div>
          <div className="w-24">
            <label className="mb-1 block text-xs text-slate-400">{de.trace.icmpCode}</label>
            <input className="fwpt-input" value={icmpCode} inputMode="numeric"
              onChange={(e) => setIcmpCode(e.target.value)} />
          </div>
        </>
      )}
      <button className="fwpt-btn" disabled={busy || !src.trim() || !dst.trim()}>
        <Play size={15} />
        {busy ? de.trace.running : de.trace.run}
      </button>
      <button
        type="button" className="fwpt-btn-ghost" title={de.trace.reverseHint}
        disabled={busy || !src.trim() || !dst.trim()}
        onClick={() => onSubmit(build(true))}
      >
        <ArrowLeftRight size={14} />
        {de.trace.reverse}
      </button>
    </form>
  );
}
