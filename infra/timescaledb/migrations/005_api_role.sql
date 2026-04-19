-- Migration 005: API-Rolle für Service-Account-User
-- Fügt 'api' als gültige Rolle zur users-Tabelle hinzu.

-- CHECK-Constraint neu setzen (PostgreSQL benennt ihn automatisch)
DO $$
DECLARE
  cname TEXT;
BEGIN
  SELECT conname INTO cname
  FROM pg_constraint
  WHERE conrelid = 'users'::regclass
    AND contype   = 'c'
    AND pg_get_constraintdef(oid) LIKE '%role%';
  IF cname IS NOT NULL THEN
    EXECUTE format('ALTER TABLE users DROP CONSTRAINT %I', cname);
  END IF;
END $$;

ALTER TABLE users
  ADD CONSTRAINT users_role_check
  CHECK (role IN ('admin', 'viewer', 'api'));
