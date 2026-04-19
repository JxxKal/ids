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
          // Merge mit bestehendem State: Feedback/pcap-Flags aus lokalem State behalten,
          // falls der DB-Snapshot sie noch nicht hat (Race condition beim Reconnect)
          setAlerts(prev => {
            const prevMap = new Map(prev.map(a => [a.alert_id, a]));
            const merged = msg.data.map(incoming => {
              const existing = prevMap.get(incoming.alert_id);
              if (!existing) return incoming;
              return {
                ...incoming,
                feedback:      existing.feedback      ?? incoming.feedback,
                feedback_ts:   existing.feedback_ts   ?? incoming.feedback_ts,
                feedback_note: existing.feedback_note ?? incoming.feedback_note,
                pcap_available: existing.pcap_available || incoming.pcap_available,
              };
            });
            return merged.slice(-MAX_ALERTS);
          });
        } else if (msg.type === 'alert') {
          setAlerts(prev => {
            const next = [msg.data, ...prev];
            return next.length > MAX_ALERTS ? next.slice(0, MAX_ALERTS) : next;
          });
        } else if (msg.type === 'alert_enriched') {
          const { alert_id, enrichment } = msg.data;
          setAlerts(prev => prev.map(a =>
            a.alert_id === alert_id ? { ...a, enrichment } : a,
          ));
        } else if (msg.type === 'pcap_available') {
          const { alert_id } = msg.data;
          setAlerts(prev => prev.map(a =>
            a.alert_id === alert_id ? { ...a, pcap_available: true } : a,
          ));
        } else if (msg.type === 'feedback_updated') {
          const { alert_id, feedback, feedback_ts, feedback_note } = msg.data;
          setAlerts(prev => prev.map(a =>
            a.alert_id === alert_id ? { ...a, feedback, feedback_ts, feedback_note } : a,
          ));
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
