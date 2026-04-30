"""
Bootstrap: Lädt historische Flows aus TimescaleDB für das initiale Training.

Liest bis zu MAX_ROWS Flows aus der `flows`-Tabelle (neueste zuerst),
gibt sie als Liste von Dicts zurück (kompatibel mit features.extract).
"""
from __future__ import annotations

import logging

import psycopg2
import psycopg2.extras

log = logging.getLogger(__name__)

MAX_ROWS = 50_000


def load_flows(postgres_dsn: str, limit: int = MAX_ROWS) -> list[dict]:
    """
    Lädt Flow-Dicts aus TimescaleDB.
    Gibt leere Liste zurück bei Fehler (Engine startet trotzdem).
    """
    try:
        conn = psycopg2.connect(postgres_dsn)
        conn.autocommit = True
    except Exception as exc:
        log.warning("DB connect failed for bootstrap: %s", exc)
        return []

    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Bereinigt: nur Flows die mind. 2h alt sind (kein Test-Bias) und
            # die nicht mit einem Heuristik-/ML-Alert verknüpft waren.
            # Statistik-Felder leben in der JSONB-Spalte `stats`.
            cur.execute(
                """
                SELECT
                    EXTRACT(EPOCH FROM (f.end_ts - f.start_ts))     AS duration_s,
                    f.pkt_count,
                    f.byte_count,
                    (f.stats->>'pps')::float                        AS pps,
                    (f.stats->>'bps')::float                        AS bps,
                    (f.stats->'pkt_size'->>'mean')::float           AS pkt_size_mean,
                    (f.stats->'pkt_size'->>'std')::float            AS pkt_size_std,
                    (f.stats->'iat'->>'mean')::float                AS iat_mean,
                    (f.stats->'iat'->>'std')::float                 AS iat_std,
                    (f.stats->>'entropy_iat')::float                AS entropy_iat,
                    (f.stats->'tcp_flags'->>'SYN')::float           AS syn_ratio,
                    (f.stats->'tcp_flags'->>'RST')::float           AS rst_ratio,
                    (f.stats->'tcp_flags'->>'FIN')::float           AS fin_ratio,
                    f.dst_port
                FROM flows f
                WHERE f.start_ts < now() - interval '2 hours'
                  AND f.stats IS NOT NULL
                  AND NOT EXISTS (
                      SELECT 1 FROM alerts a
                      WHERE a.flow_id = f.flow_id
                  )
                ORDER BY f.start_ts DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
    except Exception as exc:
        log.warning("DB query failed for bootstrap: %s", exc)
        return []
    finally:
        conn.close()

    # Zeilen in flache Dicts umwandeln die features.extract versteht
    flows = []
    for row in rows:
        flows.append({
            "duration_s":   row.get("duration_s"),
            "pkt_count":    row.get("pkt_count"),
            "byte_count":   row.get("byte_count"),
            "pps":          row.get("pps"),
            "bps":          row.get("bps"),
            "pkt_size":     {
                "mean": row.get("pkt_size_mean"),
                "std":  row.get("pkt_size_std"),
            },
            "iat":          {
                "mean": row.get("iat_mean"),
                "std":  row.get("iat_std"),
            },
            "entropy_iat":  row.get("entropy_iat"),
            "tcp_flags":    {
                "SYN": row.get("syn_ratio"),
                "RST": row.get("rst_ratio"),
                "FIN": row.get("fin_ratio"),
            },
            "dst_port":     row.get("dst_port"),
        })

    log.info("Bootstrap: loaded %d flows from DB", len(flows))
    return flows
