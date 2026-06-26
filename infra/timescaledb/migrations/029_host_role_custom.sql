-- Benutzerdefinierte Host-Rollen (Custom-Rollen). Werden im UI angelegt,
-- über Ports/Port-Ranges definiert und vom host-role-detector wie die
-- Built-in-Katalog-Rollen ausgewertet (Auto-Match an allen passenden Hosts,
-- plus manuelles Setzen/Unterdrücken pro Host wie gehabt).
--
-- DB-gespeichert (nicht als YAML-Host-File), damit der Katalog ohne
-- Host-Dateisystem-Sync auskommt — der Detektor liest die Tabelle über seine
-- bestehende DB-Verbindung pro Cycle.
--
-- match-Shape (wie YAML-Katalog §2, plus Port-Ranges):
--   { "required_ports": [{"port":2010,"proto":"TCP"},
--                        {"from":9100,"to":9110,"proto":"TCP"}],
--     "any_ports": {"min_any": 1, "ports": [...]} }

CREATE TABLE IF NOT EXISTS host_role_custom (
  id                 TEXT        PRIMARY KEY,        -- z.B. "custom_drucker"
  label              TEXT        NOT NULL,
  category           TEXT        NOT NULL DEFAULT 'custom',
  match              JSONB       NOT NULL,
  min_flows_per_port INT         NOT NULL DEFAULT 1,
  base_confidence    REAL        NOT NULL DEFAULT 0.7,
  enabled            BOOLEAN     NOT NULL DEFAULT true,
  created_by         TEXT,
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);
