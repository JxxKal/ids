-- ════════════════════════════════════════════════════════════════════════════
-- Migration 023 — Pattern-Federation: Trust-Keys + Import-Audit
--
-- pattern_trust_keys: Customer-Site speichert vertrauenswürdige Lab-Pubkeys.
--                     Bundle-Signaturen werden gegen diese Liste validiert.
-- pattern_bundle_imports: jede Bundle-Upload + Apply-Operation als Audit-
--                     Eintrag. State-Maschine: staged → applied/rejected/expired.
-- ════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pattern_trust_keys (
    id            uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    lab_id        text        NOT NULL UNIQUE,           -- z.B. 'cyjan-lab-jxxk'
    public_key    text        NOT NULL,                  -- PGP-PEM oder Cosign-Pubkey
    pubkey_sha256 text        NOT NULL,                  -- für Diff-Vergleich
    description   text,
    enabled       boolean     NOT NULL DEFAULT true,
    added_by      uuid        REFERENCES users(id) ON DELETE SET NULL,
    added_at      timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pattern_bundle_imports (
    id                      uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    bundle_sha256           text        NOT NULL,
    bundle_size             bigint      NOT NULL,
    lab_id                  text,                                -- aus manifest, NULL bei force-unverified-Apply
    lab_run_id              text,
    bundle_schema_ver       int         NOT NULL,
    cyjan_version_at_import text,
    state                   text        NOT NULL CHECK (state IN ('staged', 'applied', 'rejected', 'expired')),
    signature_status        text        NOT NULL CHECK (signature_status IN ('valid', 'invalid', 'absent', 'unverified')),
    components_offered      jsonb       NOT NULL DEFAULT '{}',   -- was im Bundle war
    components_applied      jsonb       NOT NULL DEFAULT '{}',   -- was tatsächlich angewendet wurde
    diff_summary            jsonb       NOT NULL DEFAULT '{}',   -- vor-/nach-Diff für Frontend-Render
    rejected_reason         text,
    uploaded_by             uuid        REFERENCES users(id) ON DELETE SET NULL,
    uploaded_at             timestamptz NOT NULL DEFAULT now(),
    applied_by              uuid        REFERENCES users(id) ON DELETE SET NULL,
    applied_at              timestamptz,
    storage_path            text                                 -- tempdir; wird nach apply/reject geleert
);

CREATE INDEX IF NOT EXISTS idx_pattern_bundle_imports_state_uploaded
    ON pattern_bundle_imports(state, uploaded_at DESC);

CREATE INDEX IF NOT EXISTS idx_pattern_bundle_imports_lab_id
    ON pattern_bundle_imports(lab_id, uploaded_at DESC) WHERE lab_id IS NOT NULL;

REVOKE UPDATE, DELETE ON pattern_bundle_imports FROM PUBLIC;
