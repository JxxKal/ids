-- Migration 016: known_networks.kind
--
-- Erweitert known_networks um einen `kind`-Tag (`ot` | `it`), um die
-- OT-Boundary-Klassifikation in 3 Zonen aufzulösen statt heute nur 2:
--   • OT — operational technology, der eigentliche IDS-Scope
--   • IT — corporate-managed, aber nicht im OT-Scope (Office, Mgmt-Trunks)
--   • Internet — alles was nicht in known_networks ist (computed, kein DB-Eintrag)
--
-- Default 'ot' für Bestandseinträge: vor dieser Migration galt die implizite
-- Annahme, dass alle known_networks im OT-Scope liegen. User kann betroffene
-- Einträge danach via UI/CSV-Import auf 'it' ummarkieren.
--
-- Phase B (separater Migrations-Schritt) wird zusätzlich
-- alerts.boundary_src_zone + boundary_dst_zone einführen, plus eine V2-Priority-
-- Map in system_config (Schlüssel boundary_priority_map_v2). Diese Migration
-- bereitet nur die Quelle der Wahrheit vor.

ALTER TABLE known_networks
  ADD COLUMN IF NOT EXISTS kind TEXT NOT NULL DEFAULT 'ot'
    CHECK (kind IN ('ot', 'it'));

-- Lookup-Index: enrichment-service joint pro Alert auf "wo liegt die IP"
-- gegen known_networks. Mit dem zusätzlichen Filter auf kind=ot|it bleibt der
-- GiST-Index auf cidr der Hauptindex; ein zusätzlicher Btree auf kind hilft
-- nicht (low cardinality). Wir lassen es bei dem bestehenden CIDR-Index.
