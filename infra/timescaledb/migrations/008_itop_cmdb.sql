-- Migration 008: 'cmdb' als gültigen trust_source-Wert hinzufügen
-- Wird vom iTop-CMDB-Sync für automatisch importierte Hosts verwendet.

DO $$
DECLARE
  cname TEXT;
BEGIN
  SELECT conname INTO cname
  FROM pg_constraint
  WHERE conrelid = 'host_info'::regclass
    AND contype   = 'c'
    AND pg_get_constraintdef(oid) LIKE '%trust_source%';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE host_info DROP CONSTRAINT %I', cname);
  END IF;
END $$;

ALTER TABLE host_info
  ADD CONSTRAINT host_info_trust_source_check
  CHECK (trust_source IS NULL OR trust_source IN ('dns', 'csv', 'manual', 'cmdb'));
