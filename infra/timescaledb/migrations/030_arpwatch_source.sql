-- Migration 030: 'arpwatch' als gültige Alert-Quelle
-- Der arpwatch-Bridge setzt source = 'arpwatch' (Duplicate-IP / ARP-Spoof).
-- Ohne diesen Constraint-Update würden die Alerts live per WS sichtbar sein,
-- aber am CHECK-Constraint scheitern und nie in der DB landen (gleiche Falle
-- wie Migration 006 für suricata).

DO $$
DECLARE
  cname TEXT;
BEGIN
  SELECT conname INTO cname
  FROM pg_constraint
  WHERE conrelid = 'alerts'::regclass
    AND contype   = 'c'
    AND pg_get_constraintdef(oid) LIKE '%source%';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE alerts DROP CONSTRAINT %I', cname);
  END IF;
END $$;

ALTER TABLE alerts
  ADD CONSTRAINT alerts_source_check
  CHECK (source IN ('signature', 'ml', 'correlation', 'test', 'suricata', 'external', 'arpwatch'));
