-- Migration 017: alerts.boundary_{src,dst}_zone + V2-Priority-Map
--
-- Phase-B-Ergänzung zur OT-Boundary-Klassifikation: statt nur 2 Klassen
-- (in known_networks oder nicht) führen wir 3 Zonen ein:
--   • 'ot'       — known_networks.kind='ot' (OT-Scope)
--   • 'it'       — known_networks.kind='it' (corporate IT, nicht im OT-Scope)
--   • 'internet' — alles außerhalb von known_networks
--
-- Die alten Spalten boundary_net_known/_src_known/_dst_known + boundary_priority
-- bleiben erhalten und werden vom enrichment-service weiter befüllt
-- (net_known = dst_zone IN ('ot','it')) — Alert-Detail-View nutzt sie aktuell.
--
-- Priority-Berechnung läuft V2-first: Map-Lookup per "src_zone/dst_zone"-Schlüssel
-- (z.B. "ot/internet" → P0). Falls die V2-Map fehlt, fällt der Code auf den
-- In-Code-Default zurück (definiert in enrichment-service/src/boundary.py).

ALTER TABLE alerts
  ADD COLUMN IF NOT EXISTS boundary_src_zone TEXT
    CHECK (boundary_src_zone IS NULL OR boundary_src_zone IN ('ot','it','internet')),
  ADD COLUMN IF NOT EXISTS boundary_dst_zone TEXT
    CHECK (boundary_dst_zone IS NULL OR boundary_dst_zone IN ('ot','it','internet'));

-- Lookup-Index für die OT-Boundary-Reports/Aggregates: Zonen-basierte Filter
-- ergänzen den bestehenden alerts_boundary_priority_ts_idx. Sparse-Index
-- (nur wenn beide Zonen gesetzt) hält den Index klein.
CREATE INDEX IF NOT EXISTS alerts_boundary_zones_ts_idx
  ON alerts (boundary_src_zone, boundary_dst_zone, ts DESC)
  WHERE boundary_src_zone IS NOT NULL AND boundary_dst_zone IS NOT NULL;

-- ──────────────────────────────────────────────────────────────────────────────
-- system_config: Default für die V2-Priority-Map. Schlüssel sind Strings
-- "<src_zone>/<dst_zone>"; Werte 'P0'..'P3' oder null für "kein Alert".
-- User kann später in der GUI (Settings → OT-Boundary, kommt in Phase C)
-- Werte überschreiben — beim Insert hier nur wenn der Key noch nicht
-- existiert (kein Stomp auf manuelle Anpassungen).
-- ──────────────────────────────────────────────────────────────────────────────

INSERT INTO system_config (key, value, updated_at)
VALUES (
  'boundary_priority_map_v2',
  '{
    "ot/ot":           null,
    "ot/it":           "P2",
    "ot/internet":     "P0",
    "it/ot":           "P1",
    "it/it":           null,
    "it/internet":     "P2",
    "internet/ot":     "P0",
    "internet/it":     "P2",
    "internet/internet": null
  }'::jsonb,
  now()
)
ON CONFLICT (key) DO NOTHING;
