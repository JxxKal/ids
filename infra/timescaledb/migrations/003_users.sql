-- ══════════════════════════════════════════════════════════════════════════════
-- Migration 003: User-Management
--
-- Lokale Benutzer (Passwort bcrypt-gehasht) und SAML-synchronisierte Benutzer
-- in einer gemeinsamen Tabelle. SAML-Benutzer werden beim ersten SSO-Login
-- automatisch angelegt und bei jedem Login aktualisiert.
-- ══════════════════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS users (
  id            UUID        PRIMARY KEY DEFAULT uuid_generate_v4(),
  username      TEXT        NOT NULL UNIQUE,
  email         TEXT,
  display_name  TEXT,
  role          TEXT        NOT NULL DEFAULT 'viewer'
                            CHECK (role IN ('admin', 'viewer')),
  source        TEXT        NOT NULL DEFAULT 'local'
                            CHECK (source IN ('local', 'saml')),
  -- Nur für lokale User; NULL bei SAML-Usern
  password_hash TEXT,
  -- SAML NameID (eindeutig, nur für SAML-User)
  saml_subject  TEXT        UNIQUE,
  active        BOOLEAN     NOT NULL DEFAULT true,
  created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_login    TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS users_source_idx ON users (source);
CREATE INDEX IF NOT EXISTS users_role_idx   ON users (role);

-- Standard-Admin – Passwort: 'admin-change-me' (muss nach Erstlogin geändert werden).
-- Der frühere Hash war als 'changeme' kommentiert, verifizierte aber gegen kein
-- bekanntes Klartext-Passwort → Login schlug für Endnutzer immer fehl.
-- Hash unten via `bcrypt.hashpw(b'admin-change-me', bcrypt.gensalt(rounds=12))` erzeugt.
INSERT INTO users (username, email, display_name, role, source, password_hash)
VALUES (
  'admin',
  'admin@local',
  'Administrator',
  'admin',
  'local',
  '$2b$12$elau977bxqD/pi/LOLtNx.3ibGUC.rP.IOoOFxbQyU9U5wFm6GQPm'
)
ON CONFLICT (username) DO NOTHING;

-- SAML-Standardkonfiguration (wird über /api/config/saml bearbeitet)
INSERT INTO system_config (key, value) VALUES (
  'saml',
  '{
    "enabled": false,
    "idp_metadata_url": "",
    "sp_entity_id": "https://ids.local",
    "acs_url": "https://ids.local/api/auth/saml/acs",
    "attribute_username": "uid",
    "attribute_email": "email",
    "attribute_display_name": "displayName",
    "default_role": "viewer"
  }'
)
ON CONFLICT (key) DO NOTHING;
