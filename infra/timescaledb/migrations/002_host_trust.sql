-- ══════════════════════════════════════════════════════════════════════════════
-- Migration 002: Host-Trust-System
--
-- Erweitert host_info um:
--   trusted        – bekannter / vertrauenswürdiger Host
--   trust_source   – wie der Host bekannt wurde: dns | csv | manual
--   display_name   – manuell gesetzter Anzeigename (überschreibt DNS-Hostname)
--
-- Ein Host gilt als "trusted" wenn er mindestens einmal explizit bekannt
-- gemacht wurde (DNS-Auflösung, CSV-Import oder manuelle Eingabe).
-- Das Trust-Flag hat keine Auswirkung auf das Erzeugen von Alerts –
-- es dient nur als Kontext-Signal im Dashboard.
-- ══════════════════════════════════════════════════════════════════════════════

ALTER TABLE host_info
  ADD COLUMN IF NOT EXISTS trusted       BOOLEAN NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS trust_source  TEXT
      CHECK (trust_source IS NULL OR trust_source IN ('dns', 'csv', 'manual')),
  ADD COLUMN IF NOT EXISTS display_name  TEXT;

-- Index: schnelles Lookup unbekannter Hosts (für Unknown-Host-Alert-Dedup)
CREATE INDEX IF NOT EXISTS host_info_untrusted_idx
    ON host_info (ip)
    WHERE trusted = false;

-- Dedup-Tabelle für UNKNOWN_HOST-Alerts
-- Verhindert Alert-Flut für dieselbe unbekannte IP
CREATE TABLE IF NOT EXISTS unknown_host_alert_dedup (
  ip          INET        PRIMARY KEY,
  last_alerted TIMESTAMPTZ NOT NULL DEFAULT now()
);
