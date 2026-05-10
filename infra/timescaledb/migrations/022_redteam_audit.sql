-- ════════════════════════════════════════════════════════════════════════════
-- Migration 022 — RedTeam Audit-Log
--
-- Append-only Audit-Trail für JEDEN Tool-Aufruf — auch rejected by
-- validation. Forensisch wichtig: wer hat wann mit welchen Args was
-- gegen welche Target-IP gefeuert. UPDATE/DELETE explizit revoked.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS redteam_audit_log (
    id              bigserial   NOT NULL,
    ts              timestamptz NOT NULL DEFAULT now(),
    actor_user_id   uuid        REFERENCES users(id) ON DELETE SET NULL,
    actor_token_id  text,                                 -- für API/MCP-Tokens
    mcp_tool        text        NOT NULL,                 -- 'run_kali_tool_v1', 'create_scenario_v1', ...
    target_ip       inet,
    args_hash       text,                                 -- sha256(canonical_args)
    args_excerpt    text,                                 -- erste 500 Bytes für Quick-Triage
    decision        text        NOT NULL CHECK (decision IN ('allowed', 'rejected_validation', 'rejected_rate_limit')),
    reject_reason   text,
    duration_ms     int,
    result_summary  jsonb,
    PRIMARY KEY (id, ts)
);

SELECT create_hypertable('redteam_audit_log', 'ts',
                         chunk_time_interval => interval '30 days',
                         if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_redteam_audit_actor_ts
  ON redteam_audit_log(actor_user_id, ts DESC);

CREATE INDEX IF NOT EXISTS idx_redteam_audit_decision_ts
  ON redteam_audit_log(decision, ts DESC) WHERE decision <> 'allowed';

-- Compression nach 90 Tagen — forensisch wertvoll bleibt es länger,
-- aber Storage soll nicht endlos wachsen.
SELECT add_compression_policy('redteam_audit_log', interval '90 days', if_not_exists => TRUE);

-- Hard-Lock: kein UPDATE/DELETE auf Audit-Einträgen
REVOKE UPDATE, DELETE ON redteam_audit_log FROM PUBLIC;
