-- Migration 004: tags-Spalte zur alerts-Tabelle hinzufügen
-- Tags werden vom Alert-Manager gespeichert und beim Laden aus der DB zurückgegeben.

ALTER TABLE alerts ADD COLUMN IF NOT EXISTS tags TEXT[] NOT NULL DEFAULT '{}';

-- Index für Tag-Suche (z.B. WHERE 'scan' = ANY(tags))
CREATE INDEX IF NOT EXISTS idx_alerts_tags ON alerts USING GIN (tags);
