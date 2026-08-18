-- Migration 031: Default-Retention für die Hypertables
--
-- Bis hierher legte KEINE Migration eine Retention-Policy an. Der einzige
-- add_retention_policy-Aufruf im Projekt steht in der Wartungs-API und läuft
-- nur, wenn ein Admin in der GUI etwas einstellt. Auf jeder Installation, wo
-- das nie jemand getan hat, wachsen flows und alerts unbegrenzt — der
-- Retention-Monitor warnt dann irgendwann über die Katalogliste, ohne dass
-- jemals eine Vorgabe existiert hätte.
--
-- WICHTIG — diese Migration löscht nichts.
-- Auf einem Bestandssystem mit zwei Jahren Historie wäre eine 90-Tage-Policy
-- ein stiller Datenverlust, den niemand angeordnet hat. Deshalb wird eine
-- Policy nur gesetzt, wenn sie beim ersten Lauf GAR KEINE Chunks droppen
-- würde (jüngster Datenbestand als der Zeitraum). Andernfalls bleibt die
-- Tabelle unangetastet und es gibt einen NOTICE — die Entscheidung gehört
-- dann dem Betreiber unter Einstellungen → Wartung → Retention.
--
-- Bereits vorhandene (auch manuell gesetzte) Policies werden nie überschrieben.

DO $$
DECLARE
  t       RECORD;
  n       INT;
  oldest  TIMESTAMPTZ;
BEGIN
  FOR t IN
    SELECT * FROM (VALUES
      -- Der Mengentreiber: eine Zeile je Flow.
      ('flows',                    90),
      -- Der eigentliche Wert des Systems, dafür klein. Großzügig.
      ('alerts',                  365),
      ('test_runs',                90),
      -- Reines Zustellprotokoll (auch gefilterte/gedrosselte Versuche).
      ('notification_deliveries',  30),
      ('redteam_results',          90),
      ('redteam_audit_log',       365)
    ) AS v(tbl, days)
  LOOP
    BEGIN
      -- Tabelle existiert als Hypertable? (redteam_* nur mit Lab-Migrations)
      PERFORM 1 FROM timescaledb_information.hypertables
       WHERE hypertable_name = t.tbl;
      CONTINUE WHEN NOT FOUND;

      SELECT count(*) INTO n FROM timescaledb_information.jobs
       WHERE proc_name = 'policy_retention' AND hypertable_name = t.tbl;
      IF n > 0 THEN
        RAISE NOTICE 'Retention %: Policy existiert bereits — unverändert.', t.tbl;
        CONTINUE;
      END IF;

      -- Ältesten Chunk über den Katalog bestimmen: kein Tabellenscan, und es
      -- ist genau das Kriterium, nach dem drop_chunks später entscheidet.
      SELECT min(range_start) INTO oldest
        FROM timescaledb_information.chunks
       WHERE hypertable_name = t.tbl;

      IF oldest IS NOT NULL AND oldest < now() - (t.days || ' days')::INTERVAL THEN
        RAISE NOTICE
          'Retention %: NICHT gesetzt — Daten reichen bis % zurück, % Tage würden '
          'sofort Chunks löschen. Bitte bewusst in der GUI setzen.',
          t.tbl, oldest::date, t.days;
        CONTINUE;
      END IF;

      PERFORM add_retention_policy(t.tbl::regclass,
                                   (t.days || ' days')::INTERVAL,
                                   if_not_exists => TRUE);
      RAISE NOTICE 'Retention %: % Tage gesetzt.', t.tbl, t.days;

    EXCEPTION WHEN OTHERS THEN
      -- Eine einzelne Tabelle darf die Migration nicht scheitern lassen —
      -- sonst blockiert ein Katalog-Detail den API-Start.
      RAISE WARNING 'Retention % übersprungen: %', t.tbl, SQLERRM;
    END;
  END LOOP;
END $$;
