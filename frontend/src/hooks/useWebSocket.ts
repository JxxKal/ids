import { useCallback, useEffect, useRef, useState } from 'react';
import { getToken } from '../api';
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

    const token = getToken();
    const url   = `${WS_BASE}/ws/alerts${token ? `?token=${encodeURIComponent(token)}` : ''}`;
    const ws    = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => setConnected(true);

    ws.onmessage = (ev: MessageEvent<string>) => {
      try {
        const msg = JSON.parse(ev.data) as WsMessage;
        if (msg.type === 'initial') {
          // Merge mit bestehendem State:
          // 1. DB-Snapshot ist Source of Truth für neue Felder
          // 2. Lokale Flags (feedback, pcap) haben Vorrang vor dem DB-Snapshot
          //    (Race condition: DB-Snapshot kann veraltet sein)
          // 3. Alerts aus lokalem State die NICHT im DB-Snapshot sind, bleiben erhalten
          //    (z.B. ML-Alert oder ältere Alerts die aus dem 50er-Fenster rausgefallen sind)
          setAlerts(prev => {
            const incomingMap = new Map(msg.data.map(a => [a.alert_id, a]));
            const prevMap     = new Map(prev.map(a => [a.alert_id, a]));

            // DB-Snapshot mit lokalen Flags mergen
            const fromDb: Alert[] = msg.data.map(incoming => {
              const existing = prevMap.get(incoming.alert_id);
              if (!existing) return incoming;
              return {
                ...incoming,
                // Lokale Flags haben Vorrang über den (möglicherweise veralteten) DB-Snapshot
                tags:           (incoming.tags?.length ? incoming.tags : null) ?? existing.tags,
                feedback:       existing.feedback       ?? incoming.feedback,
                feedback_ts:    existing.feedback_ts    ?? incoming.feedback_ts,
                feedback_note:  existing.feedback_note  ?? incoming.feedback_note,
                pcap_available: existing.pcap_available || incoming.pcap_available,
              } satisfies Alert;
            });

            // Lokale Alerts die nicht im DB-Snapshot sind, erhalten bleiben
            const localOnly = prev.filter(a => !incomingMap.has(a.alert_id));

            // Zusammenführen, nach Timestamp sortieren, auf MAX_ALERTS begrenzen
            return [...localOnly, ...fromDb]
              .sort((a, b) => new Date(b.ts).getTime() - new Date(a.ts).getTime())
              .slice(0, MAX_ALERTS);
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
            a.alert_id === alert_id ? {
              ...a,
              feedback,
              feedback_ts:   feedback_ts   ?? undefined,
              feedback_note: feedback_note ?? undefined,
            } : a,
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
