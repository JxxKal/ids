import { useCallback, useEffect, useRef, useState } from 'react';
import type { Alert, WsMessage } from '../types';

const WS_BASE = import.meta.env.VITE_WS_URL
  ?? `ws://${window.location.host}`;

const RECONNECT_DELAY_MS = 3000;
const MAX_ALERTS = 500;

export function useWebSocket() {
  const [alerts, setAlerts]       = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef  = useRef<WebSocket | null>(null);
  const timer  = useRef<ReturnType<typeof setTimeout> | null>(null);

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return;

    const ws = new WebSocket(`${WS_BASE}/ws/alerts`);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (ev: MessageEvent<string>) => {
      try {
        const msg = JSON.parse(ev.data) as WsMessage;
        if (msg.type === 'initial') {
          setAlerts(msg.data.slice(-MAX_ALERTS));
        } else if (msg.type === 'alert') {
          setAlerts(prev => {
            const next = [msg.data, ...prev];
            return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
          });
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      setConnected(false);
      timer.current = setTimeout(connect, RECONNECT_DELAY_MS);
    };

    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    connect();
    return () => {
      if (timer.current) clearTimeout(timer.current);
      wsRef.current?.close();
    };
  }, [connect]);

  return { alerts, connected, setAlerts };
}
