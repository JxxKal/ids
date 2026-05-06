-- ════════════════════════════════════════════════════════════════════════════
-- Migration 018 — Remote-Tap-Version
--
-- Bisher hatte master-uplink keinen Weg die laufende Version eines Taps zu
-- erfahren. Jeder Tap schickt jetzt beim Connect ein hello-Frame mit seiner
-- /opt/ids/VERSION mit, master-uplink persistiert das hier. Frontend zeigt
-- es in Settings → Remote Taps an, damit man auf einen Blick sieht welche
-- Taps noch auf alter Version laufen.
-- ════════════════════════════════════════════════════════════════════════════

ALTER TABLE taps
  ADD COLUMN IF NOT EXISTS version             TEXT,
  ADD COLUMN IF NOT EXISTS version_reported_at TIMESTAMPTZ;
