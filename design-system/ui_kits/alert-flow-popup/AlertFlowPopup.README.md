# AlertFlowPopup — React component

Drop `AlertFlowPopup.tsx` into `frontend/src/components/` and use it from the alert list.

## Basic usage

```tsx
import { AlertFlowPopup, Connection, Host, AlertMeta } from './AlertFlowPopup';

const [selected, setSelected] = useState<AlertMeta | null>(null);
const [conns,    setConns]    = useState<Connection[]>([]);

// When a row is clicked:
function openAlert(alert: AlertMeta) {
  setSelected(alert);
  // subscribe to live flow for this alert (WebSocket, SSE, polling, …)
  subscribeToFlow(alert.id, (list: Connection[]) => setConns(list));
}

<AlertFlowPopup
  open={selected !== null}
  onClose={() => { setSelected(null); setConns([]); }}
  alert={selected}
  hostA={{ ip: '10.10.20.14', name: 'PLC·S7-1500', kind: 'PLC', role: 'Control' }}
  hostB={{ ip: '10.10.20.41', name: 'HMI·WinCC',   kind: 'HMI', role: 'Operator' }}
  alertHost="a"
  connections={conns}
  onMarkThreat={() => markAsThreat(selected!.id)}
/>
```

## Connection shape

```ts
{
  id: 'c1',        // stable — used for diffing; reuse the id when packet count updates
  from: 'a',       // which host initiated
  to:   'b',
  proto: 'TCP',    // 'TCP' | 'UDP' | 'ICMP'
  port: 502,
  packets: 213,    // just replace the whole Connection object to update
  threat: true,    // red styling + dashed stroke + pulse
  label: 'Modbus', // optional free-text tag
}
```

The component is **declarative**: pass it the full list of currently-active connections on every render. It diffs internally — new ids animate in (0.5 s stroke-draw), removed ids fade out over 500 ms, updated packet counts re-render live. No imperative `push/close/tick` calls needed from the parent.

## Wiring to a WebSocket

```ts
useEffect(() => {
  if (!selected) return;
  const ws = new WebSocket(`/api/alerts/${selected.id}/flow`);
  ws.onmessage = (e) => setConns(JSON.parse(e.data));
  return () => ws.close();
}, [selected]);
```

The server sends the full list on every tick (e.g. every 500 ms). For very high-rate flows, throttle server-side — the component can comfortably render 12+ concurrent connections at 60 fps.

## Styling

All styles are inline so the component drops into any Tailwind/CSS-modules/whatever project without conflict. If you want to theme it, fork the `styles` object at the bottom of the file — palette is already CYJAN slate + cyan.

## Props reference

| prop | type | notes |
|---|---|---|
| `open` | `boolean` | controls visibility |
| `onClose` | `() => void` | called on ESC, backdrop click, or close button |
| `alert` | `AlertMeta \| null` | severity, ruleId/Name, id, firstSeen, optional session/sensor |
| `hostA`, `hostB` | `Host` | ip, name, kind, optional role |
| `alertHost` | `'a' \| 'b' \| null` | which host card gets the red border |
| `connections` | `Connection[]` | live list — see shape above |
| `onMarkThreat?` | `() => void` | if provided, shows "Mark as threat" button |
