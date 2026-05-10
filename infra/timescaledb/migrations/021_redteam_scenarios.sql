-- ════════════════════════════════════════════════════════════════════════════
-- Migration 021 — RedTeam Scenario-Registry + Run-Results
--
-- redteam_scenarios: vom Lab-Engineer (oder KI via MCP) erzeugte YAML-
-- Definitionen welche Scenario welche Rule prüfen soll.
-- redteam_results:   pro Run ein Eintrag — Hypertable, weil bei aktivem
-- Auto-Loop schnell tausende Einträge.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS redteam_scenarios (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    scenario_id     text        NOT NULL UNIQUE,        -- z.B. 'MODBUS_001_unauth_write'
    rule_id         text,                                -- erwartete CYJAN-Rule (NULL bei Pure-Recon)
    yaml_source     text        NOT NULL,                -- raw YAML aus cyjankali/scenarios/
    yaml_sha256     text        NOT NULL,                -- für Drift-Detection
    description     text,
    enabled         boolean     NOT NULL DEFAULT true,
    created_by      uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    updated_at      timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_redteam_scenarios_rule_id
  ON redteam_scenarios(rule_id) WHERE rule_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS redteam_results (
    id                  uuid        NOT NULL DEFAULT gen_random_uuid(),
    ts                  timestamptz NOT NULL DEFAULT now(),
    scenario_id         text        NOT NULL,
    run_kind            text        NOT NULL CHECK (run_kind IN ('scenario', 'kali_tool')),
    tool                text,                            -- nur bei kali_tool
    target_ip           inet,
    args                jsonb       NOT NULL DEFAULT '[]'::jsonb,
    exit_code           int,
    timed_out           boolean     NOT NULL DEFAULT false,
    duration_ms         int,
    matched_alert_ids   uuid[]      NOT NULL DEFAULT '{}',
    matched_count       int         NOT NULL DEFAULT 0,
    expected_rule_id    text,
    detected            boolean,                         -- TRUE wenn matched_count>0 für expected_rule_id
    triggered_by        uuid        REFERENCES users(id) ON DELETE SET NULL,
    PRIMARY KEY (id, ts)                                 -- TimescaleDB-Anforderung
);

SELECT create_hypertable('redteam_results', 'ts',
                         chunk_time_interval => interval '7 days',
                         if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_redteam_results_scenario_ts
  ON redteam_results(scenario_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_redteam_results_detected
  ON redteam_results(scenario_id, detected) WHERE detected = false;
