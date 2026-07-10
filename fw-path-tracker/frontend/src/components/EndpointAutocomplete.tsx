import { Database, Globe, Server } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { searchEndpoints } from '../api';
import type { Provenance, SearchHit } from '../types';

export function ProvenanceIcon({ provenance }: { provenance: Provenance }) {
  // FMG = Server, iTop = Database, DNS/IP = Globe
  if (provenance === 'fmg') return <Server size={13} className="text-cyan-400" />;
  if (provenance === 'itop') return <Database size={13} className="text-emerald-400" />;
  return <Globe size={13} className="text-slate-400" />;
}

interface Props {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
}

export default function EndpointAutocomplete({ value, onChange, placeholder }: Props) {
  const [hits, setHits] = useState<SearchHit[]>([]);
  const [open, setOpen] = useState(false);
  const timer = useRef<number>();
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    window.clearTimeout(timer.current);
    if (value.trim().length < 2 || /^[0-9.]+$/.test(value)) {
      setHits([]);
      return;
    }
    timer.current = window.setTimeout(async () => {
      try {
        const res = await searchEndpoints(value.trim());
        setHits(res);
        setOpen(res.length > 0);
      } catch {
        setHits([]);
      }
    }, 300);
    return () => window.clearTimeout(timer.current);
  }, [value]);

  useEffect(() => {
    function onClick(e: MouseEvent) {
      if (box.current && !box.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', onClick);
    return () => document.removeEventListener('mousedown', onClick);
  }, []);

  return (
    <div className="relative" ref={box}>
      <input
        className="fwpt-input" placeholder={placeholder} value={value}
        onChange={(e) => onChange(e.target.value)}
        onFocus={() => hits.length > 0 && setOpen(true)}
      />
      {open && (
        <ul className="absolute z-20 mt-1 w-full overflow-hidden rounded-md border border-slate-700 bg-slate-900 shadow-xl">
          {hits.map((h) => (
            <li key={`${h.provenance}-${h.name}`}>
              <button
                type="button"
                className="flex w-full items-center gap-2 px-3 py-2 text-left text-sm hover:bg-slate-800"
                onClick={() => {
                  onChange(h.name);
                  setOpen(false);
                }}
              >
                <ProvenanceIcon provenance={h.provenance} />
                <span className="text-slate-200">{h.name}</span>
                {h.ip && <span className="ml-auto text-xs text-slate-500">{h.ip}</span>}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
