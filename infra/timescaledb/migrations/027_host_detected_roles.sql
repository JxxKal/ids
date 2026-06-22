-- Host-Rollenerkennung: erkannte Rollen pro Host als JSONB.
-- Geschrieben ausschließlich vom host-role-detector (Master-only). Shape +
-- Provenance/Lock-Semantik: siehe docs/contracts/host-roles.md.
--
--   {
--     "roles":  { "<role_id>": { confidence, source:"auto"|"manual", ports[],
--                                evidence[], flags[], flow_count, since,
--                                last_confirmed } },
--     "manual": { "<role_id>": { locked, set_by, set_at } },
--     "evaluated_at": "<iso8601>"
--   }
--
-- source="manual" lockt den Detektor aus (rule-tuner-Provenance-Muster).

ALTER TABLE host_info
  ADD COLUMN IF NOT EXISTS detected_roles JSONB;

-- Filter "Hosts mit Rolle X" (GET /api/hosts?role=...): Key-Existenz unter roles.
CREATE INDEX IF NOT EXISTS host_info_detected_roles_gin
  ON host_info USING gin ((detected_roles -> 'roles'));
