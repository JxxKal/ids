-- ════════════════════════════════════════════════════════════════════════════
-- Migration 019 — Per-Tap Push-Update-Trigger
--
-- Master-UI bekommt einen "Update jetzt senden"-Button pro Tap. Der setzt
-- update_requested_at = now(), worauf master-uplink in seinem trigger-loop
-- den passenden WebSocket-Frame an den verbundenen Tap sendet.
--
-- update_acked_at speichert wann der Frame erfolgreich rausging — damit
-- ein zweiter Trigger nur dann re-sendet, wenn requested > acked.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE taps
  ADD COLUMN IF NOT EXISTS update_requested_at  TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS update_requested_by  UUID REFERENCES users(id) ON DELETE SET NULL,
  ADD COLUMN IF NOT EXISTS update_acked_at      TIMESTAMPTZ;
