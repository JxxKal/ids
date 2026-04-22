import type { Alert } from '../types';
import { generateInitialAlerts, generateLiveAlert } from './data';

type Listener = (alert: Alert) => void;

let alerts: Alert[] | null = null;
const listeners = new Set<Listener>();
let interval: ReturnType<typeof setInterval> | null = null;

function ensureAlerts(): Alert[] {
  if (alerts === null) alerts = generateInitialAlerts();
  return alerts;
}

export function getAlerts(): Alert[] {
  return ensureAlerts();
}

export function updateAlert(updated: Alert): void {
  ensureAlerts();
  alerts = alerts!.map(a => a.alert_id === updated.alert_id ? updated : a);
}

export function subscribe(fn: Listener): () => void {
  ensureAlerts();
  listeners.add(fn);
  startSimulator();
  return () => {
    listeners.delete(fn);
    if (listeners.size === 0) stopSimulator();
  };
}

function startSimulator() {
  if (interval) return;
  interval = setInterval(() => {
    if (listeners.size === 0) return;
    const alert = generateLiveAlert();
    alerts = [alert, ...(alerts ?? [])].slice(0, 500);
    for (const fn of listeners) fn(alert);
  }, 3500);
}

function stopSimulator() {
  if (!interval) return;
  clearInterval(interval);
  interval = null;
}

export function resetStore(): void {
  alerts = null;
  stopSimulator();
}
