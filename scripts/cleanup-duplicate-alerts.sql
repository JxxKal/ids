-- Entfernt Alarm-Duplikate aus der Giftnachricht-Schleife (v2.7.3-Changelog).
--
-- Hintergrund: bis v2.7.2 konnte eine fehlerhafte Kafka-Nachricht den
-- alert-manager in eine Absturz-Schleife bringen. Jede Runde verarbeitete
-- dasselbe Zeitfenster erneut und fügte bereits vorhandene Alarme mit neuer
-- alert_id noch einmal ein — auf einem betroffenen System lagen über 200
-- Kopien desselben Ereignisses.
--
-- Duplikat heißt hier: gleiche Regel, gleiche Quelle, gleiches Ziel, gleiche
-- Sekunde. Behalten wird je Gruppe die älteste Kopie (kleinste alert_id bei
-- identischem ts) — und ausdrücklich jede Kopie, die bereits Feedback trägt:
-- eine Triage-Entscheidung wird nie stillschweigend gelöscht.
--
-- Läuft bewusst NICHT automatisch beim Update. Alarme löscht dieses System
-- nur auf ausdrückliche Anweisung. Ausführen auf dem Master:
--
--   docker exec -i ids-timescaledb psql -U ids -d ids \
--     < /opt/ids/scripts/cleanup-duplicate-alerts.sql
--
-- Vorher ansehen, was gelöscht würde: den SELECT am Ende zuerst ausführen.

BEGIN;

WITH kopien AS (
  SELECT alert_id,
         ROW_NUMBER() OVER (
           PARTITION BY rule_id, src_ip, dst_ip, dst_port, date_trunc('second', ts)
           ORDER BY ts ASC, alert_id ASC
         ) AS reihe,
         feedback
  FROM alerts
)
DELETE FROM alerts
WHERE alert_id IN (
  SELECT alert_id FROM kopien
  WHERE reihe > 1
    AND feedback IS NULL
);

COMMIT;

-- Kontrolle: verbleibende Gruppen mit mehr als einer Kopie (erwartet: nur
-- solche, deren Kopien Feedback tragen und deshalb bewusst stehen bleiben).
SELECT rule_id, src_ip, dst_ip, date_trunc('second', ts) AS sekunde, count(*)
FROM alerts
GROUP BY 1, 2, 3, 4
HAVING count(*) > 1
ORDER BY count(*) DESC
LIMIT 20;
