-- ════════════════════════════════════════════════════════════════════════════
-- Migration 024 — Pattern-Federation: Lab-seitige Signing-Keys + Export-Log
--
-- pattern_signing_keys: Lab speichert Pubkey + Pfad zum Privkey (oder hsm://-URI).
--                       Privkey selbst niemals in der DB.
-- pattern_export_log:   Lab-Audit über erstellte Bundles. Hilfreich für
--                       Customer-Bundle-Forensik (welcher Run hat das Bundle erzeugt?).
--
-- Dieser Migration läuft auf Customer-Systemen ungenutzt mit — Tabellen
-- bleiben leer. Lab-API liest/schreibt sie nur wenn REDTEAM_ENABLED=true.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pattern_signing_keys (
    id              uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    lab_id          text        NOT NULL,                -- z.B. 'cyjan-lab-jxxk'
    key_id          text        NOT NULL,                -- human-readable, z.B. 'prod-2026Q2'
    pubkey_pem      text        NOT NULL,
    pubkey_sha256   text        NOT NULL UNIQUE,
    privkey_path    text        NOT NULL,                -- File-Pfad ODER hsm://-URI
    enabled         boolean     NOT NULL DEFAULT true,
    description     text,
    created_by      uuid        REFERENCES users(id) ON DELETE SET NULL,
    created_at      timestamptz NOT NULL DEFAULT now(),
    UNIQUE (lab_id, key_id)
);

CREATE TABLE IF NOT EXISTS pattern_export_log (
    id                  uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_sha256       text        NOT NULL,
    bundle_size         bigint      NOT NULL,
    lab_run_id          text        NOT NULL,            -- z.B. 'lab-2026-04-29'
    components_exported jsonb       NOT NULL,
    signed_with_key_id  uuid        REFERENCES pattern_signing_keys(id) ON DELETE SET NULL,
    exported_by         uuid        REFERENCES users(id) ON DELETE SET NULL,
    exported_at         timestamptz NOT NULL DEFAULT now(),
    description         text
);

CREATE INDEX IF NOT EXISTS idx_pattern_export_log_exported_at
    ON pattern_export_log(exported_at DESC);
