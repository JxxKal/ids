-- Migration 010: Egress-Boundary-Klassifikation + Whitelist
--
-- Annotation auf existierende Alerts: pro Alert wird der Tupel
-- (net_known, src_known, dst_known) ermittelt + eine Priority (P0–P3).
-- Klassifikation läuft im enrichment-service zur Laufzeit; alte Alerts
-- ohne Werte sind hier NULL und tauchen nicht im Egress-Filter auf.
--
-- net_known   = dst_ip ∈ known_networks (CIDR-Match)
-- src_known   = host_info.trusted = true für src_ip
-- dst_known   = host_info.trusted = true für dst_ip
-- priority    = aus system_config-Key 'boundary_priority_map' gemapped:
--                 (n,s,d) | P (Default-Mapping siehe Spec):
--                 (✗,✗,✗) → P0  Vollständig unbekannt
--                 (✗,✓,✗) → P1  Bekannt → Unbekannt (C2/Exfil)
--                 (✗,✗,✓) → P1  Unbekannte Quelle → bekanntes Ziel
--                 (✓,✗,✗) → P2  Rogue Device im Managed-Netz
--                 (✗,✓,✓) → P2  Routing/VPN-Anomalie
--                 (✓,✗,✓) → P3  Inventory-Lücke intern
--                 (✓,✓,✗) → P3  Bekannt → unbekanntes lokales Ziel
--                 (✓,✓,✓) → NULL (nicht in Egress-View)
--
-- boundary_whitelisted ist NICHT denormalisiert – die API-Layer berechnet
-- den Status zur Query-Zeit via LEFT JOIN auf egress_whitelist (per
-- User-Vorgabe, siehe Telegram-Diskussion 2026-04-28). Damit fallen
-- Whitelist-Änderungen ohne Batch-UPDATE auf die alerts-Hypertable an.

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS boundary_net_known BOOLEAN,
  ADD COLUMN IF NOT EXISTS boundary_src_known BOOLEAN,
  ADD COLUMN IF NOT EXISTS boundary_dst_known BOOLEAN,
  ADD COLUMN IF NOT EXISTS boundary_priority  TEXT
    CHECK (boundary_priority IS NULL OR boundary_priority IN ('P0','P1','P2','P3'));

-- Index für Sort + Filter im AlertFeed (typische Query: "alle Egress-Alerts
-- der letzten X Stunden, sortiert nach Priority").
CREATE INDEX IF NOT EXISTS alerts_boundary_priority_ts_idx
  ON alerts (boundary_priority, ts DESC)
  WHERE boundary_priority IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- EGRESS_WHITELIST
-- Audit-fähige Whitelist für legitime Egress-Flows. Soft-Delete via active=
-- false, kein DELETE. Scope-Felder sind alle optional außer src_ip:
-- mindestens eine Quelle muss konkret sein, aber dst kann leer/NULL sein
-- (matcht alle Ziele für diese Quelle), oder ein dst_net (CIDR), oder eine
-- konkrete dst_ip. dst_port + proto verfeinern den Match weiter.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE TABLE IF NOT EXISTS egress_whitelist (
  id           UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  src_ip       INET        NOT NULL,
  dst_ip       INET,                 -- konkrete Ziel-IP, ODER
  dst_net      CIDR,                 -- Ziel-Netz, ODER
  dst_port     INT,                  -- bestimmter Port (NULL = alle)
  proto        TEXT,                 -- bestimmtes Protokoll (NULL = alle)
  reason       TEXT        NOT NULL, -- Pflichtbegründung
  created_by   TEXT,                 -- username; NULL = system/import
  created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at   TIMESTAMPTZ,          -- optional: temporäre Whitelist
  active       BOOLEAN     NOT NULL DEFAULT true,
  -- Soft-Delete-Pfad: deactivated_at + deactivated_by; deleted_at bleibt NULL
  -- → wir behalten die History vollständig, niemand löscht je einen Eintrag.
  deactivated_at TIMESTAMPTZ,
  deactivated_by TIMESTAMPTZ,
  CHECK (dst_ip IS NULL OR dst_net IS NULL)   -- nicht beide
);

-- Lookup-Index für die JOIN-Logik im API-Layer:
-- Match auf src_ip ist immer dabei.
CREATE INDEX IF NOT EXISTS egress_whitelist_src_ip_active_idx
  ON egress_whitelist (src_ip)
  WHERE active = true;

-- GiST für CIDR-Match auf dst_net (analog known_networks).
CREATE INDEX IF NOT EXISTS egress_whitelist_dst_net_gist
  ON egress_whitelist USING gist (dst_net inet_ops)
  WHERE dst_net IS NOT NULL AND active = true;
