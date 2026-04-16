"""
Datenbankzugriffe für den Enrichment-Service.

  update_alert_enrichment()    – Schreibt Enrichment-JSON in alerts.enrichment
  upsert_host_info()           – Aktualisiert/legt Eintrag in host_info an
  get_host_trust()             – Liest trusted/trust_source/display_name
  get_network_for_ip()         – Known-Network-Lookup via DB-Funktion
  should_alert_unknown_host()  – Dedup-Check für UNKNOWN_HOST-Alerts
  insert_unknown_host_alert()  – Erzeugt UNKNOWN_HOST_001-Alert direkt in DB
"""
from __future__ import annotations

import logging
import time
import uuid

import orjson
import psycopg2
import psycopg2.extras

log = logging.getLogger(__name__)

# Wie lange kein neuer UNKNOWN_HOST-Alert für dieselbe IP (Sekunden)
UNKNOWN_HOST_DEDUP_S = 3600


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
        """
        Schreibt DNS/Ping/Geo-Daten.
        Trust-Felder werden NUR gesetzt wenn der Host noch nicht trusted ist
        (manuelle oder CSV-Einträge werden nicht überschrieben).
        Wenn DNS einen Hostnamen auflöst → trusted=true, trust_source='dns'.
        """
        has_hostname = bool(info.get("hostname"))
        self._execute(
            """
            INSERT INTO host_info
              (ip, hostname, asn, geo, ping_ms, last_seen, updated_at,
               trusted, trust_source)
            VALUES
              (%s, %s, %s, %s, %s, now(), now(),
               %s, %s)
            ON CONFLICT (ip) DO UPDATE SET
              hostname     = COALESCE(EXCLUDED.hostname, host_info.hostname),
              asn          = COALESCE(EXCLUDED.asn,      host_info.asn),
              geo          = COALESCE(EXCLUDED.geo,      host_info.geo),
              ping_ms      = COALESCE(EXCLUDED.ping_ms,  host_info.ping_ms),
              last_seen    = now(),
              updated_at   = now(),
              -- Trust nur hochstufen, nie herunter
              trusted      = GREATEST(host_info.trusted::int,
                                      EXCLUDED.trusted::int)::boolean,
              trust_source = CASE
                WHEN host_info.trusted THEN host_info.trust_source
                WHEN EXCLUDED.trusted  THEN EXCLUDED.trust_source
                ELSE host_info.trust_source
              END
            """,
            (
                ip,
                info.get("hostname"),
                orjson.dumps(info["asn"]).decode() if info.get("asn") else None,
                orjson.dumps(info["geo"]).decode() if info.get("geo") else None,
                info.get("ping_ms"),
                has_hostname,                      # trusted wenn DNS aufgelöst
                "dns" if has_hostname else None,
            ),
        )

    def get_host_trust(self, ip: str) -> dict:
        """
        Gibt { trusted, trust_source, display_name } zurück.
        Gibt { trusted: False } zurück wenn IP unbekannt.
        """
        try:
            self._connect()
            with self._conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:  # type: ignore[union-attr]
                cur.execute(
                    "SELECT trusted, trust_source, display_name FROM host_info WHERE ip = %s::inet",
                    (ip,),
                )
                row = cur.fetchone()
            if row:
                return {
                    "trusted":      row["trusted"],
                    "trust_source": row["trust_source"],
                    "display_name": row["display_name"],
                }
        except Exception as exc:
            log.debug("get_host_trust(%s): %s", ip, exc)
            self._conn = None
        return {"trusted": False, "trust_source": None, "display_name": None}

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

    def should_alert_unknown_host(self, ip: str) -> bool:
        """
        True wenn für diese IP noch kein UNKNOWN_HOST-Alert innerhalb
        von UNKNOWN_HOST_DEDUP_S existiert (Dedup-Check).
        Setzt gleichzeitig den Dedup-Eintrag.
        """
        try:
            self._connect()
            with self._conn.cursor() as cur:   # type: ignore[union-attr]
                cur.execute(
                    """
                    INSERT INTO unknown_host_alert_dedup (ip, last_alerted)
                    VALUES (%s::inet, now())
                    ON CONFLICT (ip) DO UPDATE
                      SET last_alerted = now()
                    WHERE unknown_host_alert_dedup.last_alerted
                          < now() - make_interval(secs => %s)
                    """,
                    (ip, float(UNKNOWN_HOST_DEDUP_S)),
                )
                inserted = cur.rowcount > 0
            self._conn.commit()                # type: ignore[union-attr]
            return inserted
        except Exception as exc:
            log.debug("should_alert_unknown_host(%s): %s", ip, exc)
            if self._conn:
                try: self._conn.rollback()
                except Exception: pass
                self._conn = None
            return False

    def insert_unknown_host_alert(self, ip: str, direction: str) -> None:
        """
        Erzeugt direkt einen UNKNOWN_HOST_001-Alert in der alerts-Tabelle.
        direction: 'src' oder 'dst'
        """
        alert_id = str(uuid.uuid4())
        self._execute(
            """
            INSERT INTO alerts
              (alert_id, ts, source, rule_id, severity, score,
               src_ip, description, tags, is_test)
            VALUES
              (%s::uuid, now(), 'enrichment', 'UNKNOWN_HOST_001', 'low', 0.3,
               %s::inet,
               %s,
               %s,
               false)
            """,
            (
                alert_id,
                ip,
                f"Unbekannter interner Host ({direction}_ip: {ip}) – nicht in host_info als trusted",
                '{"unknown-host","internal"}',
            ),
        )
        log.info("UNKNOWN_HOST_001 alert created for %s (%s)", ip, direction)

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
