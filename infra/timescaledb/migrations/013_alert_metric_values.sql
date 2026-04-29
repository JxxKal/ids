-- Migration 013: Phase 4.5 — alert.metric_values für FP/TP-Constraints
--
-- Beim Firing einer Heuristik-Rule berechnet signature-engine die Metric-
-- Werte aller `metric:`-deklarierten Params (z.B. `port_count: 87`) und
-- packt sie in das Alert-Frame. alert-manager persistiert sie hier.
-- rule-tuner liest beim Tuning-Cycle alerts mit feedback={tp,fp} und nutzt
-- min(metric@tp) als Obergrenze + max(metric@fp)+1 als Untergrenze für
-- den ML-gewählten Schwellwert. Constraint greift nur, wenn ≥3 Markierungen
-- für die Rule existieren — sonst zu wenig Signal.
--
-- Format: {"port_count": 87, "window_s": 60} — alle metric-tunbaren Params
-- der jeweiligen Rule. Nicht-tunbare Params (window_s ohne metric:) werden
-- mit ihrem aktiven Wert mitgeschrieben, sind für den Tuner aber irrelevant.
ALTER TABLE alerts ADD COLUMN IF NOT EXISTS metric_values JSONB;

-- Sparse-Index nur über Alerts mit feedback — der Tuner queried genau das
-- Subset (rule_id + feedback != NULL + metric_values != NULL).
CREATE INDEX IF NOT EXISTS alerts_feedback_metric_idx
  ON alerts (rule_id, feedback)
  WHERE feedback IS NOT NULL AND metric_values IS NOT NULL;
