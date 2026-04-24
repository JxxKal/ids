"""
Adaptive ML-basierte Suppression.

Zwei Schichten:

Layer 1 — MANUAL (Tag 'auto-suppressed'):
  User hat einen Alert mit feedback='fp' markiert. Alle passenden Tupel
  (rule_id, ip_pair) werden permanent herabgestuft.

Layer 2 — ML-ADAPTIVE (Tag 'ml-suppressed'):
  Für jedes (rule_id, ip_pair) wird eine Baseline aus den letzten
  LEARN_WINDOW_D Tagen gelernt (Mittelwert + Standardabweichung der
  Alerts/Stunde). Suppression greift NUR wenn die aktuelle Stunde
  statistisch unauffällig ist (z-Score < Z_THRESHOLD).

Spike-Durchbruch für BEIDE Schichten:
  Wenn genug Baseline-Daten vorhanden sind und die aktuelle Rate
  signifikant über dem Durchschnitt liegt (z >= Z_THRESHOLD), wird
  die Suppression AUFGEHOBEN — auch für manuell als FP markierte
  Verbindungen. Begründung: eine früher als gutartig eingestufte
  Verbindung kann später zum Angriffspfad werden (C2, Exfil).
  Ein plötzlicher Anstieg ist genau das Signal das der Analyst
  dann sehen MUSS.

Sicherheit:
  - TP-Feedback entfernt das Muster komplett aus der Baseline-Lernung
  - Spike-Durchbruch gilt nur wenn Baseline genug Daten hat
    (>= MIN_HOURS_WITH_DATA), sonst greift die normale Suppression
  - Manuelle FP-Regeln haben weiterhin Vorrang über ML-Learning
    (sie werden sichtbar als Layer 1 klassifiziert)

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
        # _stats enthält Baselines für ALLE Muster mit genug Daten
        # (inkl. manual FPs, exkl. TP-markierter Muster).
        self._stats:   dict[tuple[str, str, str], LearnedStat] = {}
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

            # Baseline + aktuelle Rate + z-Score für ALLE Muster
            # (ohne TP-Markierung). Das umfasst sowohl manuell als FP markierte
            # Verbindungen als auch rein aus dem Traffic gelernte Muster —
            # damit der Spike-Durchbruch auch für manual FPs greift.
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

            stats: dict[tuple[str, str, str], LearnedStat] = {}
            for row in cur.fetchall():
                key = (row[0], row[1], row[2])
                stats[key] = LearnedStat(
                    mean_h  = float(row[3]),
                    std_h   = float(row[4]),
                    hours   = int(row[5]),
                    recent  = int(row[6]),
                    z_score = float(row[7]),
                )

            self._manual = manual
            self._stats  = stats
            self._last_refresh = time.monotonic()

            # Statistik fürs Log
            manual_with_stats = sum(1 for k in manual if k in stats)
            manual_spikes     = sum(
                1 for k in manual
                if k in stats and stats[k].z_score >= Z_THRESHOLD
            )
            learned_only = {k: s for k, s in stats.items() if k not in manual}
            learned_active = sum(1 for s in learned_only.values() if s.z_score < Z_THRESHOLD)
            learned_spikes = len(learned_only) - learned_active

            log.info(
                "Suppression cache: %d manual FPs (%d mit Baseline, %d aktuell Spike) + "
                "%d ML-Learned [%d aktiv suppressed, %d Spike-Durchbruch] "
                "(window=%dd min_hours=%d z=%.1f)",
                len(manual), manual_with_stats, manual_spikes,
                len(learned_only), learned_active, learned_spikes,
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

        Logik (in dieser Reihenfolge geprüft):

        1. Spike-Durchbruch: Wenn eine belastbare Baseline existiert
           (stat vorhanden) und die aktuelle Rate signifikant über dem
           Mittelwert liegt (z >= Z_THRESHOLD) → None (Alert durchlassen).
           Dies gilt AUCH für manuell als FP markierte Muster — eine
           früher unauffällige Verbindung kann später auffällig werden,
           und dann muss der Analyst sie sehen.

        2. Manual FP: In _manual eingetragen → 'manual' (immer suppressen
           wenn kein Spike, auch ohne Baseline).

        3. ML-Learned: Baseline vorhanden und unauffällig → 'learned'.

        4. Keine Regel greift → None.
        """
        if not rule_id or not src_ip or not dst_ip:
            return None
        key = _session_key(rule_id, src_ip, dst_ip)
        stat = self._stats.get(key)

        # Spike-Durchbruch – gilt für Layer 1 UND Layer 2
        if stat is not None and stat.z_score >= Z_THRESHOLD:
            return None

        if key in self._manual:
            return "manual"

        if stat is not None:  # z < Z_THRESHOLD bereits oben gecheckt
            return "learned"

        return None

    def should_suppress(self, rule_id: str | None, src_ip: str | None, dst_ip: str | None) -> bool:
        return self.classify(rule_id, src_ip, dst_ip) is not None

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
