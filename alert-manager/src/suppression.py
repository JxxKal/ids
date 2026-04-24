"""
Adaptive ML-basierte Suppression.

Zwei Schichten:

Layer 1 — MANUAL (Tag 'auto-suppressed'):
  User hat einen Alert mit feedback='fp' markiert. Alle passenden Tupel
  (rule_id, ip_pair) werden permanent herabgestuft bis TP-Override.

Layer 2 — ML-ADAPTIVE (Tag 'ml-suppressed'):
  Für jedes (rule_id, ip_pair) wird eine Baseline aus den letzten
  LEARN_WINDOW_D Tagen gelernt (Mittelwert + Standardabweichung der
  Alerts/Stunde). Suppression greift NUR wenn die aktuelle Stunde
  statistisch unauffällig ist (z-Score < Z_THRESHOLD). Ein Spike
  durchbricht die Suppression automatisch — das Muster bleibt gelernt,
  aber der Burst wird wieder sichtbar weil er eben NICHT normal ist.

Sicherheit:
  - Ein TP-Feedback entfernt das Muster permanent aus der Lernliste
  - Spikes (z-Score >= Z_THRESHOLD) durchbrechen die Suppression — ein
    plötzlicher Anstieg wird IMMER durchgelassen, auch wenn das Muster
    zuvor als gelernt klassifiziert war
  - Manuelle FP-Regeln haben Vorrang vor ML-Adaptive

Refresh alle REFRESH_INTERVAL_S Sekunden aus der DB.
"""
from __future__ import annotations

import logging
import os
import time
from dataclasses import dataclass

import psycopg2

log = logging.getLogger(__name__)

REFRESH_INTERVAL_S = 60.0

# ── Adaptive Thresholds (ENV-konfigurierbar) ─────────────────────────────────
LEARN_WINDOW_D      = int(os.environ.get("SUPPRESSION_LEARN_WINDOW_D", "14"))
MIN_HOURS_WITH_DATA = int(os.environ.get("SUPPRESSION_MIN_HOURS",      "24"))
Z_THRESHOLD         = float(os.environ.get("SUPPRESSION_Z_THRESHOLD",  "2.0"))


@dataclass
class LearnedStat:
    mean_h:  float   # Baseline: mittlere Alerts pro Stunde
    std_h:   float   # Baseline: Standardabweichung
    hours:   int     # Stunden mit Daten in der Baseline
    recent:  int     # Alerts in der letzten Stunde
    z_score: float   # (recent - mean) / max(std, 1)


def _session_key(rule_id: str, ip_a: str, ip_b: str) -> tuple[str, str, str]:
    """Bidirektionale Normalisierung des IP-Paars."""
    if ip_a <= ip_b:
        return (rule_id, ip_a, ip_b)
    return (rule_id, ip_b, ip_a)


class SuppressionCache:
    def __init__(self, postgres_dsn: str) -> None:
        self._dsn = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None
        self._manual:  set[tuple[str, str, str]] = set()
        self._learned: dict[tuple[str, str, str], LearnedStat] = {}
        self._last_refresh = 0.0

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = True

    def refresh(self) -> None:
        try:
            self._connect()
            cur = self._conn.cursor()  # type: ignore[union-attr]

            # Layer 1: Manuell markierte FPs (bidirektional).
            # host() statt ::text — sonst hätte der String CIDR-Suffix "/32"
            # und würde nicht mit den CIDR-losen IPs aus dem Kafka-Alert matchen.
            cur.execute("""
                SELECT DISTINCT
                    rule_id,
                    host(LEAST(src_ip, dst_ip))    AS ip_a,
                    host(GREATEST(src_ip, dst_ip)) AS ip_b
                FROM alerts
                WHERE feedback = 'fp'
                  AND rule_id IS NOT NULL
                  AND src_ip  IS NOT NULL
                  AND dst_ip  IS NOT NULL
            """)
            manual = {(r[0], r[1], r[2]) for r in cur.fetchall()}

            # Layer 2: ML-Adaptive Baseline + aktuelle Rate + z-Score
            cur.execute("""
                WITH hourly AS (
                    SELECT
                        rule_id,
                        LEAST(src_ip, dst_ip)    AS ip_a,
                        GREATEST(src_ip, dst_ip) AS ip_b,
                        date_trunc('hour', ts)   AS hour_bucket,
                        COUNT(*)                 AS cnt
                    FROM alerts
                    WHERE ts > NOW() - (%s * INTERVAL '1 day')
                      AND ts < date_trunc('hour', NOW())
                      AND is_test = false
                      AND rule_id IS NOT NULL
                      AND src_ip  IS NOT NULL
                      AND dst_ip  IS NOT NULL
                    GROUP BY 1, 2, 3, 4
                ),
                baseline AS (
                    SELECT
                        rule_id, ip_a, ip_b,
                        AVG(cnt)::float                 AS mean_h,
                        COALESCE(STDDEV(cnt), 0)::float AS std_h,
                        COUNT(*)::int                   AS hours_with_data
                    FROM hourly
                    GROUP BY rule_id, ip_a, ip_b
                    HAVING COUNT(*) >= %s
                ),
                recent AS (
                    SELECT
                        rule_id,
                        LEAST(src_ip, dst_ip)    AS ip_a,
                        GREATEST(src_ip, dst_ip) AS ip_b,
                        COUNT(*)::int            AS cnt_1h
                    FROM alerts
                    WHERE ts > NOW() - INTERVAL '1 hour'
                      AND is_test = false
                    GROUP BY 1, 2, 3
                ),
                tp_pat AS (
                    SELECT DISTINCT
                        rule_id,
                        LEAST(src_ip, dst_ip)    AS ip_a,
                        GREATEST(src_ip, dst_ip) AS ip_b
                    FROM alerts
                    WHERE feedback = 'tp'
                )
                SELECT
                    b.rule_id,
                    host(b.ip_a)  AS ip_a_text,
                    host(b.ip_b)  AS ip_b_text,
                    b.mean_h,
                    b.std_h,
                    b.hours_with_data,
                    COALESCE(r.cnt_1h, 0) AS recent,
                    CASE
                        WHEN b.std_h > 0
                          THEN (COALESCE(r.cnt_1h, 0) - b.mean_h) / b.std_h
                        WHEN COALESCE(r.cnt_1h, 0) > b.mean_h
                          THEN 99.0
                        ELSE 0.0
                    END AS z_score
                FROM baseline b
                LEFT JOIN recent  r  ON r.rule_id  = b.rule_id AND r.ip_a  = b.ip_a AND r.ip_b  = b.ip_b
                LEFT JOIN tp_pat  tp ON tp.rule_id = b.rule_id AND tp.ip_a = b.ip_a AND tp.ip_b = b.ip_b
                WHERE tp.rule_id IS NULL
            """, (LEARN_WINDOW_D, MIN_HOURS_WITH_DATA))

            learned: dict[tuple[str, str, str], LearnedStat] = {}
            for row in cur.fetchall():
                key = (row[0], row[1], row[2])
                if key in manual:
                    continue  # manuelle FP hat Vorrang
                learned[key] = LearnedStat(
                    mean_h  = float(row[3]),
                    std_h   = float(row[4]),
                    hours   = int(row[5]),
                    recent  = int(row[6]),
                    z_score = float(row[7]),
                )

            self._manual  = manual
            self._learned = learned
            self._last_refresh = time.monotonic()

            active = sum(1 for s in learned.values() if s.z_score < Z_THRESHOLD)
            spikes = len(learned) - active
            log.info(
                "Suppression cache: %d manuell (fp) + %d ML-gelernt "
                "[%d aktiv suppressed, %d spike-through] "
                "(window=%dd min_hours=%d z=%.1f)",
                len(self._manual), len(self._learned),
                active, spikes,
                LEARN_WINDOW_D, MIN_HOURS_WITH_DATA, Z_THRESHOLD,
            )
        except Exception as exc:
            log.warning("Suppression-Cache-Refresh fehlgeschlagen: %s", exc)
            self._conn = None

    def maybe_refresh(self) -> None:
        if time.monotonic() - self._last_refresh > REFRESH_INTERVAL_S:
            self.refresh()

    def classify(self, rule_id: str | None, src_ip: str | None, dst_ip: str | None) -> str | None:
        """Gibt 'manual', 'learned' oder None zurück.

        - 'manual': User hat FP markiert → immer suppressen.
        - 'learned': ML-Baseline vorhanden UND aktuelle Stunde statistisch
          unauffällig (z < Z_THRESHOLD) → suppressen.
        - None: entweder unbekanntes Muster ODER gelerntes Muster mit Spike
          (z ≥ Z_THRESHOLD) → NICHT suppressen, durchlassen."""
        if not rule_id or not src_ip or not dst_ip:
            return None
        key = _session_key(rule_id, src_ip, dst_ip)
        if key in self._manual:
            return "manual"
        stat = self._learned.get(key)
        if stat is not None and stat.z_score < Z_THRESHOLD:
            return "learned"
        return None

    def should_suppress(self, rule_id: str | None, src_ip: str | None, dst_ip: str | None) -> bool:
        return self.classify(rule_id, src_ip, dst_ip) is not None

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
