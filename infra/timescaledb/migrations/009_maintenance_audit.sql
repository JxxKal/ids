-- Audit-Log für Datenbank-Wartungsaktionen.
-- Destructive Actions (Cleanup, Retention-Änderungen, Backup, Restore)
-- werden mit User + Details + Ergebnis protokolliert.

CREATE TABLE IF NOT EXISTS maintenance_audit (
    id           BIGSERIAL PRIMARY KEY,
    ts           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id      UUID,
    username     TEXT NOT NULL,
    action       TEXT NOT NULL,       -- z.B. 'cleanup_alerts', 'vacuum', 'retention_update'
    params       JSONB,               -- Parameter (z.B. {older_than_days: 30})
    result       JSONB,               -- Ergebnis (z.B. {rows_deleted: 12345})
    success      BOOLEAN NOT NULL,
    error_msg    TEXT,
    duration_ms  INTEGER
);

CREATE INDEX IF NOT EXISTS idx_maintenance_audit_ts       ON maintenance_audit (ts DESC);
CREATE INDEX IF NOT EXISTS idx_maintenance_audit_action   ON maintenance_audit (action);
CREATE INDEX IF NOT EXISTS idx_maintenance_audit_username ON maintenance_audit (username);
