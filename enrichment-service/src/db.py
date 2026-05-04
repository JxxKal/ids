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

    def update_alert_boundary(
        self,
        alert_id:        str,
        net_known:       bool | None,
        src_known:       bool | None,
        dst_known:       bool | None,
        priority:        str | None,
        src_zone:        str | None = None,
        dst_zone:        str | None = None,
    ) -> None:
        """Schreibt die Egress-Boundary-Felder auf den Alert-Record.

        priority darf P0/P1/P2/P3 oder NULL sein. NULL = nicht in Egress-View
        (Diagonale ot/ot bzw. it/it, oder ✓✓✓-Konstellation aus V1).

        src_zone/dst_zone (V2, Phase B) sind 'ot'|'it'|'internet'|None. Auf
        bestehenden Spalten boundary_src_zone/_dst_zone — Migration 017
        legt sie an, aber wir setzen sie nur wenn übergeben (Backwards-Compat
        falls dieser Code vor der Migration läuft, dann sind src/dst_zone
        einfach NULL).
        """
        self._execute(
            """
            UPDATE alerts
            SET boundary_net_known = %s,
                boundary_src_known = %s,
                boundary_dst_known = %s,
                boundary_priority  = %s,
                boundary_src_zone  = %s,
                boundary_dst_zone  = %s
            WHERE alert_id = %s
            """,
            (net_known, src_known, dst_known, priority, src_zone, dst_zone, alert_id),
        )

    def is_known_network(self, ip: str | None) -> bool:
        """True wenn die IP in einem konfigurierten known_networks-CIDR liegt.
        Wird für Backwards-Compat-Felder boundary_net_known weiterhin genutzt."""
        if not ip:
            return False
        try:
            self._connect()
            with self._conn.cursor() as cur:  # type: ignore[union-attr]
                cur.execute(
                    "SELECT 1 FROM known_networks WHERE %s::inet <<= cidr LIMIT 1",
                    (ip,),
                )
                row = cur.fetchone()
            return row is not None
        except Exception as exc:
            log.debug("is_known_network(%s): %s", ip, exc)
            self._conn = None
            return False

    def get_zone(self, ip: str | None) -> str:
        """V2-Zone-Lookup (Migration 017): 'ot' | 'it' | 'internet'.

        Mehrfache Match-Treffer (überlappende CIDRs) werden über masklen
        sortiert — der spezifischste CIDR gewinnt. Das ist relevant wenn
        z.B. ein /16 als 'it' getaggt ist und ein /24 darin als 'ot':
        IPs im /24 werden korrekt als 'ot' klassifiziert.

        Bei nicht-IP / leerem Input oder DB-Fehler → 'internet' (failsafe:
        unbekanntes Ziel sieht aus wie Internet, keine versehentlichen
        OT-Klassifikationen).
        """
        if not ip:
            return "internet"
        try:
            self._connect()
            with self._conn.cursor() as cur:  # type: ignore[union-attr]
                cur.execute(
                    """
                    SELECT kind
                      FROM known_networks
                     WHERE %s::inet <<= cidr
                     ORDER BY masklen(cidr) DESC
                     LIMIT 1
                    """,
                    (ip,),
                )
                row = cur.fetchone()
            if row and row[0] in ("ot", "it"):
                return row[0]
            return "internet"
        except Exception as exc:
            log.debug("get_zone(%s): %s", ip, exc)
            self._conn = None
            return "internet"

    def get_boundary_priority_map(self) -> dict | None:
        """Liest die system_config-Konfiguration für boundary_priority_map (V1).

        Gibt None zurück wenn der Key nicht existiert oder nicht parsebar ist
        – Caller fällt dann auf den In-Code-Default zurück.
        """
        try:
            self._connect()
            with self._conn.cursor() as cur:  # type: ignore[union-attr]
                cur.execute(
                    "SELECT value FROM system_config WHERE key = %s",
                    ("boundary_priority_map",),
                )
                row = cur.fetchone()
            if row and isinstance(row[0], dict):
                return row[0]
            return None
        except Exception as exc:
            log.debug("get_boundary_priority_map: %s", exc)
            self._conn = None
            return None

    def get_boundary_priority_map_v2(self) -> dict | None:
        """Liest die V2-Map (Migration 017) aus system_config. Format:
        {"ot/internet": "P0", ...}. None wenn Key fehlt → Caller fällt auf
        DEFAULT_PRIORITY_MAP_V2 zurück."""
        try:
            self._connect()
            with self._conn.cursor() as cur:  # type: ignore[union-attr]
                cur.execute(
                    "SELECT value FROM system_config WHERE key = %s",
                    ("boundary_priority_map_v2",),
                )
                row = cur.fetchone()
            if row and isinstance(row[0], dict):
                return row[0]
            return None
        except Exception as exc:
            log.debug("get_boundary_priority_map_v2: %s", exc)
            self._conn = None
            return None

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
               src_ip, description, is_test)
            VALUES
              (%s::uuid, now(), 'correlation', 'UNKNOWN_HOST_001', 'low', 0.3,
               %s::inet,
               %s,
               false)
            """,
            (
                alert_id,
                ip,
                f"Unbekannter interner Host ({direction}_ip: {ip}) – nicht in host_info als trusted",
            ),
        )
        log.info("UNKNOWN_HOST_001 alert created for %s (%s)", ip, direction)

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
