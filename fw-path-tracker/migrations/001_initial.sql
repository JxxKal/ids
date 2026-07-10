-- fw-path-tracker – Initiales Schema
-- Läuft über den Migrations-Runner (api/src/migrate.py) beim API-Startup.

CREATE TABLE IF NOT EXISTS users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'viewer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Zentraler Config-Store (ids-Muster): ein JSONB-Dokument pro Key.
-- Keys: fmg, itop, dns, sites, tracker
CREATE TABLE IF NOT EXISTS system_config (
    key   TEXT PRIMARY KEY,
    value JSONB NOT NULL
);

-- Cache der FortiManager-DB. kind: device | package | policy | address |
-- addrgrp | service | servicegrp | vip | zone | interface | route
CREATE TABLE IF NOT EXISTS fmg_snapshot (
    adom      TEXT NOT NULL,
    kind      TEXT NOT NULL,
    key       TEXT NOT NULL,
    data      JSONB NOT NULL,
    synced_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (adom, kind, key)
);

CREATE TABLE IF NOT EXISTS traces (
    id          SERIAL PRIMARY KEY,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    username    TEXT NOT NULL,
    request     JSONB NOT NULL,
    result      JSONB NOT NULL,
    verdict     TEXT NOT NULL,
    duration_ms INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS traces_created_idx ON traces (created_at DESC);

-- Default-Konfiguration (idempotent)
INSERT INTO system_config (key, value) VALUES
    ('tracker', '{"max_hops": 8, "sync_interval_s": 1800, "resolver_ttl_s": 900, "overlay_pattern": "(?i)(vpn|ovl|sdwan|tun|ipsec)"}'),
    ('dns',     '{"resolvers": [], "search_domains": []}'),
    ('sites',   '{"overrides": []}')
ON CONFLICT (key) DO NOTHING;
