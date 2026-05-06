import type { Alert } from '../types';

export type Severity = Alert['severity'];

/**
 * Effektive Severity für Anzeige + lokale Sortierung/Filterung.
 *
 * Regeln (in der Reihenfolge angewandt):
 *   1. feedback === 'fp'              → 'low'
 *      User hat den Alert als False-Positive markiert → optisch
 *      runterstufen, egal ob Boundary oder normaler Severity-Wert.
 *   2. boundary_priority === 'P0'     → 'critical'
 *      OT↔Internet- oder vergleichbare Top-Priority-Boundary-Breach: in
 *      der UI immer als kritisch flaggen, unabhängig von der Original-
 *      Severity die der Detector vergeben hat.
 *   3. sonst                          → original alert.severity
 *
 * DB-Werte bleiben unverändert — das ist eine reine Anzeige-Override.
 * Reports/Aggregations (Backend) nutzen weiterhin alert.severity, das
 * ist Phase-2-Migration falls gewünscht.
 */
export function effectiveSeverity(alert: Pick<Alert, 'severity' | 'feedback' | 'boundary_priority'>): Severity {
  if (alert.feedback === 'fp') return 'low';
  if (alert.boundary_priority === 'P0') return 'critical';
  return alert.severity;
}

/**
 * True wenn die effective Severity sich von der Original-Severity
 * unterscheidet. Nutzbar für visuelle Indikatoren (z.B. *-Suffix).
 */
export function severityIsDerived(alert: Pick<Alert, 'severity' | 'feedback' | 'boundary_priority'>): boolean {
  return effectiveSeverity(alert) !== alert.severity;
}
