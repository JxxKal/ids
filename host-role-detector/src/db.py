"""DB-Layer für den host-role-detector.

Liest aus der `flows`-Hypertable (Aggregation servierter Ports + Mode-MAC
pro Host) und ist der **alleinige Schreiber** von `host_info.detected_roles`.
Schreibe-Pfad nimmt das dict direkt (asyncpg-jsonb-Codec) — KEIN json.dumps,
KEIN ::jsonb-Cast (siehe MEMORY: asyncpg jsonb-codec).
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone

import asyncpg

log = logging.getLogger(__name__)


async def _init_conn(conn: asyncpg.Connection) -> None:
    """json/jsonb-Codec registrieren — Python-dicts wandern direkt nach
    $-Parametern, gelesene Werte kommen direkt als dict zurück."""
    for pg_type in ("json", "jsonb"):
        await conn.set_type_codec(
            pg_type,
            encoder=json.dumps,
            decoder=json.loads,
            schema="pg_catalog",
        )


class Db:
    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None

    async def connect(self) -> None:
        self._pool = await asyncpg.create_pool(
            self._dsn, min_size=1, max_size=4, init=_init_conn,
        )

    async def close(self) -> None:
        if self._pool:
            await self._pool.close()

    # ── Aggregation aus flows ─────────────────────────────────────────────

    async def served_ports(
        self, window_days: int, min_flows_per_port: int,
    ) -> dict[str, dict[tuple[int, str], int]]:
        """Servierte Ports pro Host über das Beobachtungsfenster.

        Host = Responder = dst_ip; ein Flow zählt für einen Port nur, wenn
        die Verbindung als beantwortet gilt (connection_state ∈
        ESTABLISHED|CLOSED — half-open/SYN-only werden nicht als 'serviert'
        gewertet, sonst zählt jeder Portscan-Probe als Service).

        Zusätzlich Bidirektionalitäts-Check: pkt_count_rev > 0 verlangt, dass
        der Host (dst_ip=Server) tatsächlich mindestens ein Paket zurück-
        geschickt hat. Nötig, weil UDP/ICMP-Flows bereits nach dem ersten
        Paket auf ESTABLISHED gesetzt werden (flow.py) — ohne diesen Filter
        würde eine einzelne unbeantwortete UDP-Probe (`nmap -sU`) dem Ziel
        einen 'servierten' Port und damit eine Rolle verpassen. Bei TCP ist
        ESTABLISHED implizit schon bidirektional (SYN+ACK ist ein Rev-Paket),
        der Filter ist dort ein No-Op.

        Rückgabe: {host_ip: {(dst_port, proto): flow_count}}, gefiltert auf
        flow_count >= min_flows_per_port.
        """
        assert self._pool is not None
        since = datetime.now(timezone.utc) - timedelta(days=window_days)
        rows = await self._pool.fetch(
            """
            SELECT host(dst_ip) AS host, dst_port, proto, COUNT(*) AS n
              FROM flows
             WHERE start_ts >= $1
               AND dst_port IS NOT NULL
               AND (stats->>'connection_state') IN ('ESTABLISHED', 'CLOSED')
               AND COALESCE((stats->>'pkt_count_rev')::int, 0) > 0
             GROUP BY host(dst_ip), dst_port, proto
            HAVING COUNT(*) >= $2
            """,
            since, min_flows_per_port,
        )
        out: dict[str, dict[tuple[int, str], int]] = {}
        for r in rows:
            host = str(r["host"])
            out.setdefault(host, {})[(int(r["dst_port"]), str(r["proto"]))] = int(r["n"])
        return out

    async def host_first_seen(self, window_days: int) -> dict[str, datetime]:
        """Ältester servierter Flow pro Host im Fenster — für den
        long_lived-Bonus. Gleiche 'serviert'-Semantik wie served_ports:
        beantwortete Verbindung (ESTABLISHED|CLOSED) UND Bidirektionalität
        (pkt_count_rev > 0), damit eine unbeantwortete UDP-Probe den
        first_seen nicht künstlich nach vorne zieht."""
        assert self._pool is not None
        since = datetime.now(timezone.utc) - timedelta(days=window_days)
        rows = await self._pool.fetch(
            """
            SELECT host(dst_ip) AS host, MIN(start_ts) AS first_seen
              FROM flows
             WHERE start_ts >= $1
               AND (stats->>'connection_state') IN ('ESTABLISHED', 'CLOSED')
               AND COALESCE((stats->>'pkt_count_rev')::int, 0) > 0
             GROUP BY host(dst_ip)
            """,
            since,
        )
        return {str(r["host"]): r["first_seen"] for r in rows}

    async def mode_macs(self, window_days: int) -> dict[str, str]:
        """Mode-MAC pro Host. Ein Host kann sowohl als src (src_mac) wie als
        dst (dst_mac) aufgetaucht sein — wir zählen beide Vorkommen und
        nehmen die häufigste MAC. NULL-MACs werden ignoriert.

        Rückgabe: {host_ip: 'aa:bb:cc:dd:ee:ff'} (Original-Format aus stats).
        """
        assert self._pool is not None
        since = datetime.now(timezone.utc) - timedelta(days=window_days)
        # UNION ALL beider Perspektiven, dann pro Host die häufigste MAC via
        # DISTINCT ON + Count-Sortierung.
        rows = await self._pool.fetch(
            """
            SELECT DISTINCT ON (host) host, mac
              FROM (
                SELECT host, mac, COUNT(*) AS n
                  FROM (
                    SELECT host(src_ip) AS host, stats->>'src_mac' AS mac
                      FROM flows
                     WHERE start_ts >= $1 AND stats->>'src_mac' IS NOT NULL
                    UNION ALL
                    SELECT host(dst_ip) AS host, stats->>'dst_mac' AS mac
                      FROM flows
                     WHERE start_ts >= $1 AND stats->>'dst_mac' IS NOT NULL
                  ) macs
                 GROUP BY host, mac
              ) counted
             ORDER BY host, n DESC
            """,
            since,
        )
        return {str(r["host"]): str(r["mac"]) for r in rows if r["mac"]}

    async def tap_profiles(
        self, window_days: int,
    ) -> dict[str, dict]:
        """Von Remote-Taps gemeldete Port-Profile (tap_host_profiles), nur
        recent (updated_at im Fenster). Über mehrere Taps hinweg pro Host
        aggregiert: Ports vereinigt (Counts summiert), MAC = erste nicht-leere,
        first_seen = früheste.

        Rückgabe: {host_ip: {"ports": {(port, proto): count}, "mac": str|None,
                              "first_seen": datetime|None}}.
        jsonb kommt dank _init_conn-Codec bereits als Python-Liste zurück.
        """
        assert self._pool is not None
        since = datetime.now(timezone.utc) - timedelta(days=window_days)
        try:
            rows = await self._pool.fetch(
                """
                SELECT host(host_ip) AS host, ports, mac, first_seen
                  FROM tap_host_profiles
                 WHERE updated_at >= $1
                """,
                since,
            )
        except asyncpg.UndefinedTableError:
            return {}   # Migration 028 noch nicht eingespielt — failsoft.
        out: dict[str, dict] = {}
        for r in rows:
            host = str(r["host"])
            entry = out.setdefault(host, {"ports": {}, "mac": None, "first_seen": None})
            for p in (r["ports"] or []):
                try:
                    key = (int(p["port"]), str(p.get("proto") or ""))
                except (KeyError, TypeError, ValueError):
                    continue
                entry["ports"][key] = entry["ports"].get(key, 0) + int(p.get("count", 1))
            if entry["mac"] is None and r["mac"]:
                entry["mac"] = r["mac"]
            fs = r["first_seen"]
            if fs is not None and (entry["first_seen"] is None or fs < entry["first_seen"]):
                entry["first_seen"] = fs
        return out

    async def load_custom_roles(self) -> list[dict]:
        """Aktivierte benutzerdefinierte Rollen (host_role_custom). Liefert
        dicts im selben Schema wie ein YAML-Katalog-Eintrag, damit
        catalog.parse_role() sie direkt in RoleDef wandelt. `match` kommt dank
        jsonb-Codec bereits als dict. failsoft, wenn die Tabelle noch fehlt."""
        assert self._pool is not None
        try:
            rows = await self._pool.fetch(
                """
                SELECT id, label, category, match, min_flows_per_port, base_confidence
                  FROM host_role_custom
                 WHERE enabled = true
                """,
            )
        except asyncpg.UndefinedTableError:
            return []   # Migration 029 noch nicht eingespielt.
        out: list[dict] = []
        for r in rows:
            out.append({
                "id":       r["id"],
                "label":    r["label"],
                "category": r["category"],
                "match":    r["match"] if isinstance(r["match"], dict) else {},
                "min_flows_per_port": int(r["min_flows_per_port"] or 1),
                "base_confidence":    float(r["base_confidence"] or 0.0),
            })
        return out

    async def hosts_with_roles(self) -> list[tuple[str, dict | None]]:
        """(IP, detected_roles) für Hosts mit mindestens einer erkannten Rolle —
        Kandidaten fürs Aging. Enthält auch Hosts, die im aktuellen
        Beobachtungsfenster gar nicht mehr als Responder auftauchen (die
        build_profiles nie zurückgibt).

        Liefert den detected_roles-Snapshot gleich mit, damit der Aging-Pass
        billig (ohne Transaktion) vorprüfen kann, ob überhaupt etwas veraltet
        ist, und nur für echte Treffer den FOR-UPDATE-Schreibpfad betritt."""
        assert self._pool is not None
        rows = await self._pool.fetch(
            """
            SELECT host(ip) AS host, detected_roles
              FROM host_info
             WHERE detected_roles IS NOT NULL
               AND jsonb_typeof(detected_roles->'roles') = 'object'
               AND detected_roles->'roles' <> '{}'::jsonb
            """,
        )
        out: list[tuple[str, dict | None]] = []
        for r in rows:
            val = r["detected_roles"]
            out.append((str(r["host"]), val if isinstance(val, dict) else None))
        return out

    # ── Schreiber: host_info.detected_roles ───────────────────────────────

    async def update_detected_roles(self, host_ip: str, build_payload):
        """Alleiniger Schreiber von detected_roles — Read-Modify-Write in EINER
        Transaktion mit `SELECT ... FOR UPDATE`.

        TOCTOU-Schutz: Der Merge (manual-Locks respektieren, auto-Rollen neu
        berechnen) muss auf dem FRISCH GESPERRTEN Zustand laufen. Läse der
        Detektor den detected_roles-Stand außerhalb der Schreib-Transaktion
        (wie zuvor über einen zweiten Pool-Connect), könnte ein zeitgleicher
        manueller Roles-PUT (`action=suppress`/lock) zwischen Read und Write
        rutschen und würde vom Detektor mit dem Vor-Edit-Stand überschrieben.
        Durch die Zeilen-Sperre serialisiert der Detektor gegen die API.

        `build_payload` ist ein Callable(existing: dict | None) -> dict | None,
        das den Merge auf dem gesperrten `existing` durchführt. Gibt es None
        zurück (nichts zu ändern, z.B. Aging ohne veraltete Rolle), wird kein
        Schreib-Roundtrip gemacht und None zurückgegeben — sonst das
        geschriebene Payload (für den ≥1-Rolle-Zähler in main.py).

        Payloads gehen als dict rein (jsonb-Codec) — kein json.dumps,
        kein ::jsonb-Cast.
        """
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            async with conn.transaction():
                locked = await conn.fetchrow(
                    "SELECT detected_roles FROM host_info WHERE ip = $1::inet FOR UPDATE",
                    host_ip,
                )
                existing = None
                if locked is not None:
                    val = locked["detected_roles"]
                    existing = val if isinstance(val, dict) else None

                payload = build_payload(existing)

                # Build-Funktion signalisiert "keine Änderung" → nicht schreiben
                # (spart updated_at-Berührung + WAL für unveränderte Hosts).
                if payload is None:
                    return None

                if locked is None:
                    await conn.execute(
                        """
                        INSERT INTO host_info (ip, detected_roles)
                        VALUES ($1::inet, $2)
                        ON CONFLICT (ip) DO UPDATE
                          SET detected_roles = EXCLUDED.detected_roles,
                              updated_at = now()
                        """,
                        host_ip, payload,
                    )
                else:
                    await conn.execute(
                        """
                        UPDATE host_info
                           SET detected_roles = $2,
                               updated_at = now()
                         WHERE ip = $1::inet
                        """,
                        host_ip, payload,
                    )
                return payload
