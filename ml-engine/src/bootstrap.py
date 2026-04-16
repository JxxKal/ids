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
            cur.execute(
                """
                SELECT
                    EXTRACT(EPOCH FROM (end_ts - start_ts)) AS duration_s,
                    pkt_count,
                    byte_count,
                    pps,
                    bps,
                    pkt_size_mean   AS "pkt_size.mean",
                    pkt_size_std    AS "pkt_size.std",
                    iat_mean        AS "iat.mean",
                    iat_std         AS "iat.std",
                    entropy_iat,
                    syn_ratio       AS "tcp_flags.SYN",
                    rst_ratio       AS "tcp_flags.RST",
                    fin_ratio       AS "tcp_flags.FIN",
                    dst_port
                FROM flows
                ORDER BY start_ts DESC
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
                "mean": row.get("pkt_size.mean"),
                "std":  row.get("pkt_size.std"),
            },
            "iat":          {
                "mean": row.get("iat.mean"),
                "std":  row.get("iat.std"),
            },
            "entropy_iat":  row.get("entropy_iat"),
            "tcp_flags":    {
                "SYN": row.get("tcp_flags.SYN"),
                "RST": row.get("tcp_flags.RST"),
                "FIN": row.get("tcp_flags.FIN"),
            },
            "dst_port":     row.get("dst_port"),
        })

    log.info("Bootstrap: loaded %d flows from DB", len(flows))
    return flows
