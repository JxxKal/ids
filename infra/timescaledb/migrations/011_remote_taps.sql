-- Migration 011: Remote-Taps (verteilte Capture-Knoten)
--
-- Ein Remote-Tap läuft an einem entfernten Standort, hat seinen eigenen
-- sniffer + flow-aggregator + signature-engine + alert-manager (mit
-- lokalem Pre-Filter) und schickt fertige Alerts via WSS an diesen
-- Master. Authentisiert sich per mTLS – ein Pairing-Token wird einmalig
-- beim Onboarding ausgestellt und sofort gegen ein 1-Jahr-Tap-Cert
-- eingetauscht.
--
-- Tap-Frame: identisches alerts-raw-Format + tap_id-Tag. Master fügt das
-- in seine alerts-Hypertable ein, weiter durch alert-manager → enrichment
-- → frontend wie ein lokal erzeugter Alert.

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- ──────────────────────────────────────────────────────────────────────────────
-- TAPS – ein Eintrag pro registriertem Remote-Tap
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS taps (
  id                UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  name              TEXT        NOT NULL UNIQUE,        -- 'Halle West' o.ä.
  site              TEXT,                                -- freier Tag, z.B. 'site-muc'
  cert_fingerprint  TEXT        NOT NULL UNIQUE,         -- SHA-256 hex des signierten Tap-Certs
  cert_expires_at   TIMESTAMPTZ NOT NULL,
  status            TEXT        NOT NULL DEFAULT 'active'
                    CHECK (status IN ('active','revoked')),
  paired_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  paired_by         TEXT,                                -- username der den Pairing-Token erzeugt hat
  revoked_at        TIMESTAMPTZ,
  revoked_by        TEXT,
  -- Telemetrie (vom Uplink-Endpoint laufend aktualisiert)
  last_seen         TIMESTAMPTZ,
  alerts_received   BIGINT      NOT NULL DEFAULT 0,
  ip_last           TEXT                                 -- letzte beobachtete Quelle (Diagnose)
);

CREATE INDEX IF NOT EXISTS taps_status_idx ON taps (status);

-- ──────────────────────────────────────────────────────────────────────────────
-- TAP_PAIRING_TOKENS – einmalig verwendbare Bootstrap-Token
--
-- Workflow: Admin generiert im Frontend (Settings → Remote Taps → "neuen
-- Tap koppeln") einen Token. Token wird genau einmal angezeigt, danach
-- nur noch der Hash in der DB. Tap nimmt das Token + eine selbst
-- generierte CSR und postet auf POST /api/v1/taps/pair – Master prüft
-- Token, signiert die CSR, markiert das Token als used und legt einen
-- taps-Eintrag an.
-- ──────────────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS tap_pairing_tokens (
  id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  token_hash    TEXT        NOT NULL UNIQUE,            -- bcrypt o. sha256, prüfbar gegen Klartext
  tap_name      TEXT        NOT NULL,                   -- vorab vergebener Name; muss zum taps.name werden
  tap_site      TEXT,
  expires_at    TIMESTAMPTZ NOT NULL,                   -- typischerweise +60min
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_by    TEXT,                                   -- username
  used_at       TIMESTAMPTZ,                            -- NULL = noch frei
  used_by_tap   UUID                                    -- → taps.id, wenn verbraucht
);

CREATE INDEX IF NOT EXISTS tap_pairing_tokens_unused_idx
  ON tap_pairing_tokens (expires_at)
  WHERE used_at IS NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- ALERTS.tap_id – Zuordnung welcher Tap einen Alert geliefert hat
--
-- NULL = lokal erzeugt am Master (alle Bestandsdaten und alle Alerts der
-- Master-eigenen Capture-Pipeline). Soft-FK ohne Constraint, damit ein
-- gelöschter/revoked Tap nicht ALTER-Storms auf der Hypertable auslöst.
-- ──────────────────────────────────────────────────────────────────────────────

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS tap_id UUID;

CREATE INDEX IF NOT EXISTS alerts_tap_id_ts_idx
  ON alerts (tap_id, ts DESC)
  WHERE tap_id IS NOT NULL;
