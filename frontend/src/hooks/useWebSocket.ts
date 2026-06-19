import { useCallback, useEffect, useRef, useState } from 'react';
import { getToken } from '../api';
import { isDemoMode } from '../demo/mode';
import { getAlerts, subscribe } from '../demo/store';
import type { Alert, WsMessage } from '../types';

const WS_BASE = import.meta.env.VITE_WS_URL
  ?? `${window.location.protocol === 'https:' ? 'wss' : 'ws'}://${window.location.host}`;

// Reconnect mit exponentiellem Backoff statt festem 3s-Hämmern: 1s, 2s, 4s …
// gedeckelt bei 30s, mit ±20% Jitter (verhindert Thundering-Herd, wenn viele
// Clients gleichzeitig nach einem Master-Neustart reconnecten). Reset auf 0
// nach erfolgreichem open.
const RECONNECT_BASE_MS = 1000;
const RECONNECT_MAX_MS  = 30000;
// Wie lange ein Socket in CONNECTING verharren darf, bevor wir ihn als tot
// betrachten und neu aufbauen. Beim Fresh-Login direkt nach dem Login-POST
// kam es auf langsameren Prod-Hosts vor, dass der WS-Upgrade hinter nginx
// hängenblieb — weder `open` noch `close`/`error` feuerte je. Ohne dieses
// Timeout gab es dann keinen Reconnect und der Stream blieb bis zum manuellen
// Browser-Reload offline. (Reload baute eine frische Verbindung auf → ging.)
const CONNECT_TIMEOUT_MS = 8000;
// Watchdog: gleicht den connected-State periodisch mit der echten
// readyState ab und reconnectet eine tote/fehlende Verbindung. Fängt sowohl
// verschluckte close-Events als auch in CONNECTING hängende Sockets ab.
const WATCHDOG_INTERVAL_MS = 4000;
const MAX_ALERTS = 500;

export function useWebSocket() {
  const [alerts, setAlerts]       = useState<Alert[]>([]);
  const [connected, setConnected] = useState(false);
  const wsRef       = useRef<WebSocket | null>(null);
  const reconnectAt = useRef<ReturnType<typeof setTimeout> | null>(null);
  const reconnectTries = useRef(0);

  const connect = useCallback(() => {
    const cur = wsRef.current;
    // Schon offen oder gerade im Aufbau → nichts tun (verhindert doppelte
    // Sockets, wenn der Watchdog und ein onclose-Reconnect kollidieren).
    if (cur && (cur.readyState === WebSocket.OPEN || cur.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const token = getToken();
    if (!token) {
      // Noch nicht authentifiziert — kein tokenloser WS, den das Backend eh
      // mit 4001 schließt. Der Watchdog versucht es erneut, sobald ein Token da ist.
      return;
    }

    const url = `${WS_BASE}/ws/alerts?token=${encodeURIComponent(token)}`;
    const ws  = new WebSocket(url);
    wsRef.current = ws;

    // Establishment-Timeout: hängt der Handshake, erzwingen wir ein close →
    // löst onclose → Reconnect aus.
    const estTimer = setTimeout(() => {
      if (ws.readyState === WebSocket.CONNECTING) ws.close();
    }, CONNECT_TIMEOUT_MS);

    const scheduleReconnect = () => {
      if (reconnectAt.current) return;
      const exp   = Math.min(RECONNECT_BASE_MS * 2 ** reconnectTries.current, RECONNECT_MAX_MS);
      const delay = exp * (0.8 + Math.random() * 0.4);  // ±20% Jitter
      reconnectTries.current += 1;
      reconnectAt.current = setTimeout(() => {
        reconnectAt.current = null;
        connect();
      }, delay);
    };

    ws.onopen = () => {
      clearTimeout(estTimer);
      reconnectTries.current = 0;  // erfolgreiche Verbindung → Backoff zurücksetzen
      if (ws === wsRef.current) setConnected(true);
    };

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
          // Dedupliziere: wenn alert_id bereits existiert (z.B. nach
          // Kafka-Rebalance), merge statt überschreiben. Lokale Flags
          // (feedback, severity nach FP-Markierung, tags wie auto-suppressed
          // oder ml-suppressed, pcap) MÜSSEN erhalten bleiben.
          setAlerts(prev => {
            const incoming = msg.data;
            const existing = prev.find(a => a.alert_id === incoming.alert_id);
            if (existing) {
              // Merge: lokale Feedback- und Suppression-Flags gewinnen
              const merged: Alert = {
                ...incoming,
                feedback:       existing.feedback       ?? incoming.feedback,
                feedback_ts:    existing.feedback_ts    ?? incoming.feedback_ts,
                feedback_note:  existing.feedback_note  ?? incoming.feedback_note,
                severity:       existing.feedback === 'fp' ? 'low' : incoming.severity,
                tags:           existing.tags?.length ? existing.tags : incoming.tags,
                pcap_available: existing.pcap_available || incoming.pcap_available,
                enrichment:     existing.enrichment     ?? incoming.enrichment,
              };
              return prev.map(a => a.alert_id === incoming.alert_id ? merged : a);
            }
            const next = [incoming, ...prev];
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
          // Zusätzlich zu feedback auch severity und tags aktualisieren —
          // der API-Patch setzt severity='low' bei FP-Markierung.
          const { alert_id, feedback, feedback_ts, feedback_note, severity, tags } = msg.data;
          setAlerts(prev => prev.map(a =>
            a.alert_id === alert_id ? {
              ...a,
              feedback,
              feedback_ts:   feedback_ts   ?? undefined,
              feedback_note: feedback_note ?? undefined,
              severity:      severity ?? (feedback === 'fp' ? 'low' : a.severity),
              tags:          tags ?? a.tags,
            } : a,
          ));
        }
      } catch {
        // ignore parse errors
      }
    };

    ws.onclose = () => {
      clearTimeout(estTimer);
      // Nur der aktuelle Socket darf den State umschalten — ein verspätetes
      // close eines alten Sockets darf einen frisch offenen nicht überstimmen.
      if (ws !== wsRef.current) return;
      setConnected(false);
      scheduleReconnect();
    };

    ws.onerror = () => ws.close();
  }, []);

  useEffect(() => {
    if (isDemoMode()) {
      setAlerts(getAlerts().slice(0, 50));
      setConnected(true);
      const unsub = subscribe(alert => {
        setAlerts(prev => [alert, ...prev].slice(0, MAX_ALERTS));
      });
      return () => { unsub(); setConnected(false); };
    }

    connect();

    // Watchdog: hält connected synchron mit der echten Verbindung und baut
    // tote/fehlende Sockets neu auf. Selbstheilend gegen verschluckte Events
    // und in CONNECTING hängende Handshakes.
    const watchdog = setInterval(() => {
      if (isDemoMode()) return;
      const ws   = wsRef.current;
      const open = ws?.readyState === WebSocket.OPEN;
      setConnected(prev => (prev === !!open ? prev : !!open));
      // Weder offen noch im Aufbau → connect() (no-op wenn bereits CONNECTING).
      if (!ws || (ws.readyState !== WebSocket.OPEN && ws.readyState !== WebSocket.CONNECTING)) {
        connect();
      }
    }, WATCHDOG_INTERVAL_MS);

    return () => {
      clearInterval(watchdog);
      if (reconnectAt.current) { clearTimeout(reconnectAt.current); reconnectAt.current = null; }
      const ws = wsRef.current;
      wsRef.current = null;
      ws?.close();
    };
  }, [connect]);

  return { alerts, connected, setAlerts };
}
