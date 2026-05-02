-- ══════════════════════════════════════════════════════════════════════════════
-- Auto-Pairing für Remote-Taps (Token-frei, Admin-bestätigt)
--
-- Workflow:
--   1. Tap macht POST /api/taps/announce mit hardware_id + Name + CSR.
--   2. Source-IP wird gegen known_networks geprüft + gegen RFC1918/ULA-Whitelist.
--   3. Bei Erfolg landet ein Eintrag in pending_taps mit status='pending'.
--   4. Admin sieht im UI die Liste und drückt approve/reject.
--   5. Tap pollt /api/taps/announce-status und kriegt Cert + Master-CA bei Approval.
--
-- Audit: jede Announce-Action (auch abgelehnte) landet in tap_audit_log mit
-- Quell-IP, Hardware-ID und Begründung. Reine Diagnose-Tabelle, kein FK.
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS pending_taps (
  id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  hardware_id   TEXT        NOT NULL,                   -- /etc/machine-id der Tap-Box
  name          TEXT        NOT NULL,                   -- selbst-vergebener Name
  source_ip     INET        NOT NULL,
  hostname      TEXT,
  version       TEXT,
  csr_pem       TEXT        NOT NULL,                   -- vom Tap mitgeliefert, signing erst bei approve
  fingerprint   TEXT        NOT NULL,                   -- SHA256 des CSR-public-keys (für Polling-Identifikation)
  announced_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  status        TEXT        NOT NULL DEFAULT 'pending', -- pending | approved | rejected
  reviewed_at   TIMESTAMPTZ,
  reviewed_by   TEXT,                                   -- username
  approved_tap_id UUID,                                 -- → taps.id wenn approved
  -- Cert-Material wird bei approve persistiert, damit der Tap es bei seinem
  -- nächsten Polling-Aufruf abholen kann (cert_pem ist nur einmal verfügbar
  -- nach dem Sign-Vorgang, deshalb cachen).
  cert_pem      TEXT,
  cert_expires_at TIMESTAMPTZ,
  cert_picked_up_at TIMESTAMPTZ                         -- NULL = noch nicht abgeholt
);

-- Identifikation eines Taps: hardware_id + fingerprint sind zusammen unique.
-- Wenn der Tap re-announced (z.B. Wizard nochmal gestartet, gleicher CSR-Key),
-- gibt's nur einen Eintrag — wir machen UPSERT-Logik in der API.
CREATE UNIQUE INDEX IF NOT EXISTS pending_taps_identity_idx
  ON pending_taps (hardware_id, fingerprint);

CREATE INDEX IF NOT EXISTS pending_taps_status_idx
  ON pending_taps (status, announced_at DESC);

-- Audit-Log: jede Announce-Action + Admin-Action landet hier.
CREATE TABLE IF NOT EXISTS tap_audit_log (
  id            BIGSERIAL    PRIMARY KEY,
  ts            TIMESTAMPTZ  NOT NULL DEFAULT now(),
  event         TEXT         NOT NULL,                  -- announce | rejected_ip_not_private | rejected_ip_not_known | rejected_rate_limit | approved | rejected | poll
  source_ip     INET,
  hardware_id   TEXT,
  name          TEXT,
  pending_id    UUID,                                   -- → pending_taps.id wenn vorhanden
  details       JSONB                                   -- frei strukturiert: hostname, version, fingerprint, admin user, ...
);

CREATE INDEX IF NOT EXISTS tap_audit_log_ts_idx ON tap_audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS tap_audit_log_event_ts_idx ON tap_audit_log (event, ts DESC);
