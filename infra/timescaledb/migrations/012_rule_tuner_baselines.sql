-- Migration 012: rule-tuner Phase 3 — Baselines + Trainings-State
--
-- Phase-3-Foundation für den ML-Schwellwert-Tuner. Liefert:
--   1. rule_baselines: Tabelle in die Phase-4 (rule-tuner-Service) sein
--      Reservoir-Sample alle 60s als Quantile zusammenfasst.
--   2. system_config-Defaults für den State-Maschinen-Status (idle/training/
--      tuning/paused) und die Trainings-Konfiguration (Fenstergröße, Quantil,
--      Scope-Split-Toggle, Blacklist).
--
-- Beide Tabellen sind read-heavy in Phase 4 (rule-tuner-Service liest
-- baselines beim Cycle, Status-API liest system_config auf jeden GET) und
-- entsprechend simpel — keine Hypertable, kein Trigger über schon
-- vorhandenem config_changed-Notify hinaus.

-- ──────────────────────────────────────────────────────────────────────────────
-- RULE_BASELINES — gerollte Quantile pro (rule, param, scope)
--
-- Eine Zeile pro `(rule_id, param_name, scope)`. scope ∈ {internal, external,
-- global} – global wird genutzt, wenn known_networks-Split deaktiviert ist
-- (oder wenn der Param keinen value_internal-Slot hat). Der rule-tuner upsertet
-- alle 60s aus seinem in-memory Reservoir; Quantile sind nullable, weil zu
-- Beginn (sample_count < min_samples) noch keine sinnvolle Aussage möglich
-- ist – das Frontend zeigt dann "Sammle…" statt eines konkreten Wertes.
-- ──────────────────────────────────────────────────────────────────────────────
CREATE TABLE IF NOT EXISTS rule_baselines (
  rule_id       TEXT             NOT NULL,
  param_name    TEXT             NOT NULL,
  scope         TEXT             NOT NULL
                                 CHECK (scope IN ('internal', 'external', 'global')),
  p50           DOUBLE PRECISION,
  p99           DOUBLE PRECISION,
  p995          DOUBLE PRECISION,
  p999          DOUBLE PRECISION,
  sample_count  BIGINT           NOT NULL DEFAULT 0,
  updated_at    TIMESTAMPTZ      NOT NULL DEFAULT now(),
  PRIMARY KEY (rule_id, param_name, scope)
);

CREATE INDEX IF NOT EXISTS rule_baselines_updated_idx
  ON rule_baselines (updated_at DESC);

-- ──────────────────────────────────────────────────────────────────────────────
-- SYSTEM_CONFIG-Defaults für den Tuner
--
-- ml_tuning_state:
--   state         – idle | training | tuning | paused
--   started_at    – ISO-Timestamp letzter start-training-Aufruf
--   training_until– ISO-Timestamp Ende der aktuellen Trainings-Phase
--   last_tuning_at– ISO-Timestamp letzter Override-Write durch den Tuner
--   paused_from   – State vor dem Pause (für resume); nur gesetzt während
--                   state='paused'
--
-- ml_tuning_config:
--   window_s                    – Trainings-Dauer in Sekunden (Default 10h)
--   target_alert_rate_per_hour  – Zielrate; bei Überschreitung wird der
--                                 Schwellwert höher gewählt
--   scope_split_enabled         – wenn false: nur scope=global statt
--                                 internal/external getrennt
--   quantile                    – Quantil für die Schwellwert-Wahl
--                                 (Default 0.995 = P99,5)
--   max_change_per_cycle        – maximaler relativer Sprung pro Cycle
--                                 (gegen Schwankung)
--   blacklist                   – Rule-IDs die der Tuner NICHT anfasst
-- ──────────────────────────────────────────────────────────────────────────────
INSERT INTO system_config (key, value) VALUES (
  'ml_tuning_state',
  '{"state": "idle", "started_at": null, "training_until": null, "last_tuning_at": null, "paused_from": null}'::jsonb
) ON CONFLICT (key) DO NOTHING;

INSERT INTO system_config (key, value) VALUES (
  'ml_tuning_config',
  '{
    "window_s": 36000,
    "target_alert_rate_per_hour": 0.5,
    "scope_split_enabled": true,
    "quantile": 0.995,
    "max_change_per_cycle": 0.20,
    "blacklist": []
  }'::jsonb
) ON CONFLICT (key) DO NOTHING;
