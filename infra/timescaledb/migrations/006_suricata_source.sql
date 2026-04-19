-- Migration 006: 'suricata' als gültige Alert-Quelle
-- Der snort-bridge setzt source = 'suricata', was bisher am CHECK-Constraint
-- scheiterte – Alerts waren nur live sichtbar, nie in der DB gespeichert.

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
  CHECK (source IN ('signature', 'ml', 'correlation', 'test', 'suricata'));
