import { Handle, Position } from '@xyflow/react';
import { Cloud, Monitor } from 'lucide-react';
import type { NameEntry } from '../../types';
import { ProvenanceIcon } from '../EndpointAutocomplete';

export interface HostNodeData {
  ip: string;
  names: NameEntry[];
  role: 'src' | 'dst' | 'internet';
  [key: string]: unknown;
}

export default function HostNode({ data }: { data: HostNodeData }) {
  const isInternet = data.role === 'internet';
  return (
    <div className="w-44 rounded-lg border border-slate-700 bg-slate-900 p-3 shadow-lg">
      {data.role !== 'src' && <Handle type="target" position={Position.Left} className="!bg-cyan-600" />}
      {data.role === 'src' && <Handle type="source" position={Position.Right} className="!bg-cyan-600" />}
      <div className="flex items-center gap-2">
        {isInternet
          ? <Cloud size={18} className="text-slate-400" />
          : <Monitor size={18} className="text-cyan-400" />}
        <div className="min-w-0">
          <p className="truncate font-mono text-sm text-slate-100">{data.ip}</p>
          {data.names.slice(0, 2).map((n) => (
            <p key={n.provenance + n.name} className="flex items-center gap-1 truncate text-xs text-slate-400">
              <ProvenanceIcon provenance={n.provenance} />
              {n.name}
            </p>
          ))}
        </div>
      </div>
    </div>
  );
}
