-- ════════════════════════════════════════════════════════════════════════════
-- Migration 025 — system_config['features'] Default-Initialisierung
--
-- Cyjan-weite Feature-Flags. Alle Defaults konservativ (off oder restricted).
-- Lab-Engineer muss bewusst in der UI aktivieren.
-- ════════════════════════════════════════════════════════════════════════════

INSERT INTO system_config (key, value)
VALUES (
    'features',
    jsonb_build_object(
        'redteam_enabled',         false,   -- redteam-orchestrator + kali-shell + MCP-write-tools
        'pattern_export_enabled',  false,   -- Lab-only: /api/pattern/export-Endpoint + UI-Section
        'pattern_import_enabled',  true     -- Customer + Lab: Bundle einspielen
    )
)
ON CONFLICT (key) DO NOTHING;
