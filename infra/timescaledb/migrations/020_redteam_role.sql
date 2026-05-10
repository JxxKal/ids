-- ════════════════════════════════════════════════════════════════════════════
-- Migration 020 — RedTeam-Rolle in users.role-CHECK aufnehmen
--
-- Lab-Modus erlaubt einen vierten User-Typ: 'redteam'. Diese User können
-- die schreibenden RedTeam-MCP-Tools (create_scenario_v1, run_kali_tool_v1)
-- aufrufen, aber NICHT in production-Config (system_config, networks, users)
-- schreiben. An Customer-Systemen ohne redteam-Profile ist die Rolle
-- ungenutzt — die CHECK-Erweiterung ist additive und kostet nichts.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE users
  DROP CONSTRAINT IF EXISTS users_role_check;

ALTER TABLE users
  ADD CONSTRAINT users_role_check
  CHECK (role IN ('admin', 'viewer', 'api', 'redteam'));

COMMENT ON CONSTRAINT users_role_check ON users IS
  'redteam: nur RedTeam-MCP-Tools + Read-only-API. Aktiv nur wenn Compose-Profil "redteam" läuft.';
