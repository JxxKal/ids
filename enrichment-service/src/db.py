"""
Datenbankzugriffe für den Enrichment-Service.

  update_alert_enrichment()  – Schreibt Enrichment-JSON in alerts.enrichment
  upsert_host_info()         – Aktualisiert/legt Eintrag in host_info an
  get_network_for_ip()       – Known-Network-Lookup via DB-Funktion
"""
from __future__ import annotations

import logging
import time

import orjson
import psycopg2
import psycopg2.extras

log = logging.getLogger(__name__)


class EnrichmentDB:
    def __init__(self, postgres_dsn: str) -> None:
        self._dsn  = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = False

    def _execute(self, sql: str, params: tuple, retries: int = 3) -> None:
        for attempt in range(retries):
            try:
                self._connect()
                with self._conn.cursor() as cur:   # type: ignore[union-attr]
                    cur.execute(sql, params)
                self._conn.commit()                # type: ignore[union-attr]
                return
            except Exception as exc:
                log.error("DB execute attempt %d: %s", attempt + 1, exc)
                if self._conn:
                    try:
                        self._conn.rollback()
                    except Exception:
                        pass
                    self._conn = None
                if attempt < retries - 1:
                    time.sleep(2 ** attempt)

    def update_alert_enrichment(self, alert_id: str, enrichment: dict) -> None:
        self._execute(
            """
            UPDATE alerts
            SET enrichment = %s
            WHERE alert_id = %s
            """,
            (orjson.dumps(enrichment).decode(), alert_id),
        )

    def upsert_host_info(self, ip: str, info: dict) -> None:
        self._execute(
            """
            INSERT INTO host_info (ip, hostname, asn, geo, ping_ms, last_seen, updated_at)
            VALUES (%s, %s, %s, %s, %s, now(), now())
            ON CONFLICT (ip) DO UPDATE SET
              hostname   = EXCLUDED.hostname,
              asn        = EXCLUDED.asn,
              geo        = EXCLUDED.geo,
              ping_ms    = EXCLUDED.ping_ms,
              last_seen  = EXCLUDED.last_seen,
              updated_at = EXCLUDED.updated_at
            """,
            (
                ip,
                info.get("hostname"),
                orjson.dumps(info["asn"]).decode()  if info.get("asn")  else None,
                orjson.dumps(info["geo"]).decode()  if info.get("geo")  else None,
                info.get("ping_ms"),
            ),
        )

    def get_network_for_ip(self, ip: str) -> dict | None:
        """Nutzt die SQL-Funktion get_network_for_ip() aus dem DB-Schema."""
        for attempt in range(2):
            try:
                self._connect()
                with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:  # type: ignore[union-attr]
                    cur.execute("SELECT * FROM get_network_for_ip(%s)", (ip,))
                    row = cur.fetchone()
                if row:
                    return {
                        "cidr":  str(row["cidr"]),
                        "name":  row["name"],
                        "color": row.get("color"),
                    }
                return None
            except Exception as exc:
                log.debug("get_network_for_ip(%s): %s", ip, exc)
                self._conn = None
                if attempt == 0:
                    time.sleep(0.5)
        return None

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
