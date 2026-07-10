import { Background, Edge, Node, ReactFlow } from '@xyflow/react';
import { useMemo } from 'react';
import { de } from '../i18n/de';
import type { Hop, TraceResult } from '../types';
import FirewallNode from './nodes/FirewallNode';
import HostNode from './nodes/HostNode';

const nodeTypes = { host: HostNode, firewall: FirewallNode } as never;

const edgeColor: Record<string, string> = {
  ALLOW: '#34d399',
  DENY: '#f87171',
  UNKNOWN: '#fbbf24',
};

interface Props {
  result: TraceResult;
  onSuggest: (hop: Hop) => void;
}

// Linearer Pfad → manueller Horizontal-Layouter (kein dagre/elk nötig)
const HOST_W = 176;
const FW_W = 288;
const GAP = 90;

export default function PathGraph({ result, onSuggest }: Props) {
  const { nodes, edges } = useMemo(() => {
    const nodes: Node[] = [];
    const edges: Edge[] = [];
    let x = 0;

    nodes.push({
      id: 'src', type: 'host', position: { x, y: 40 },
      data: { ip: result.src.ip, names: result.src.names, role: 'src' },
    });
    x += HOST_W + GAP;

    result.hops.forEach((hop, i) => {
      nodes.push({
        id: `hop-${i}`, type: 'firewall', position: { x, y: 0 },
        data: { hop, onSuggest },
      });
      x += FW_W + GAP;
    });

    const lastHop = result.hops[result.hops.length - 1];
    const isInternet = lastHop?.egress_class === 'DEFAULT';
    nodes.push({
      id: 'dst', type: 'host', position: { x, y: 40 },
      data: isInternet
        ? { ip: result.dst.ip, names: [{ name: de.common.internet, provenance: 'ip' }], role: 'internet' }
        : { ip: result.dst.ip, names: result.dst.names, role: 'dst' },
    });

    const chain = ['src', ...result.hops.map((_, i) => `hop-${i}`), 'dst'];
    for (let i = 0; i < chain.length - 1; i++) {
      const hop = result.hops[Math.min(i, result.hops.length - 1)];
      const verdict = i === 0 ? result.hops[0]?.verdict ?? 'UNKNOWN' : hop.verdict;
      const label = i < result.hops.length
        ? undefined
        : de.egress[result.hops[result.hops.length - 1].egress_class];
      // Label der Kante NACH einem Hop = dessen Egress-Klasse
      const outHopIdx = i - 1;
      const egressLabel = outHopIdx >= 0 && outHopIdx < result.hops.length
        ? de.egress[result.hops[outHopIdx].egress_class]
        : label;
      const dimmed = hop?.after_deny ?? false;
      edges.push({
        id: `e-${i}`,
        source: chain[i],
        target: chain[i + 1],
        animated: verdict === 'ALLOW' && !dimmed,
        label: i === 0 ? undefined : egressLabel,
        labelStyle: { fill: '#94a3b8', fontSize: 10 },
        labelBgStyle: { fill: '#0f172a', fillOpacity: 0.9 },
        style: {
          stroke: dimmed ? '#475569' : edgeColor[verdict] ?? '#64748b',
          strokeWidth: 2,
          opacity: dimmed ? 0.4 : 1,
        },
      });
    }
    return { nodes, edges };
  }, [result, onSuggest]);

  return (
    <div className="h-[420px] rounded-lg border border-slate-800 bg-slate-950">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
        colorMode="dark"
      >
        <Background color="#1e293b" gap={24} />
      </ReactFlow>
    </div>
  );
}
