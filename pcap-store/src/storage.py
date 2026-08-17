"""
MinIO-Upload und TimescaleDB-Update für fertige PCAP-Dateien.
"""
from __future__ import annotations

import io
import logging
import time

import psycopg2
from minio import Minio
from minio.error import S3Error

log = logging.getLogger(__name__)


class PcapStorage:
    def __init__(
        self,
        minio_endpoint: str,
        minio_access_key: str,
        minio_secret_key: str,
        bucket: str,
        postgres_dsn: str,
    ) -> None:
        self._bucket = bucket
        self._dsn    = postgres_dsn
        self._conn: psycopg2.extensions.connection | None = None

        self._minio = Minio(
            minio_endpoint,
            access_key=minio_access_key,
            secret_key=minio_secret_key,
            secure=False,
        )
        self._ensure_bucket()

    def _ensure_bucket(self) -> None:
        try:
            if not self._minio.bucket_exists(self._bucket):
                self._minio.make_bucket(self._bucket)
                log.info("Created MinIO bucket: %s", self._bucket)
        except S3Error as exc:
            log.error("MinIO bucket init failed: %s", exc)

    def upload_pcap(self, alert_id: str, pcap_bytes: bytes) -> str | None:
        """
        Lädt PCAP-Bytes nach MinIO hoch.
        Gibt den Object-Key zurück oder None bei Fehler.
        """
        key = f"alerts/{alert_id}.pcap"
        try:
            self._minio.put_object(
                self._bucket,
                key,
                io.BytesIO(pcap_bytes),
                length=len(pcap_bytes),
                content_type="application/vnd.tcpdump.pcap",
            )
            log.debug("Uploaded %s (%d bytes)", key, len(pcap_bytes))
            return key
        except S3Error as exc:
            log.error("MinIO upload failed for %s: %s", alert_id, exc)
            return None

    def mark_pcap_available(self, alert_id: str, pcap_key: str) -> None:
        """Setzt pcap_available=true und pcap_key in der alerts-Tabelle."""
        for attempt in range(3):
            try:
                self._connect()
                with self._conn.cursor() as cur:      # type: ignore[union-attr]
                    cur.execute(
                        """
                        UPDATE alerts
                        SET pcap_available = true, pcap_key = %s
                        WHERE alert_id = %s
                        """,
                        (pcap_key, alert_id),
                    )
                self._conn.commit()                   # type: ignore[union-attr]
                return
            except Exception as exc:
                log.error("DB update attempt %d: %s", attempt + 1, exc)
                if self._conn:
                    try:
                        self._conn.rollback()
                    except Exception:
                        pass
                    self._conn = None
                if attempt < 2:
                    time.sleep(2 ** attempt)

    def expire_stale_pcaps(self, retention_days: int) -> int:
        """Nimmt die Verfügbarkeits-Zusage zurück, sobald MinIO geräumt hat.

        MinIO löscht die Objekte per Lifecycle-Regel nach PCAP_RETENTION_DAYS
        (infra/minio/init-buckets.sh). An der alerts-Tabelle ging das bisher
        spurlos vorbei: `pcap_available` blieb true, `pcap_key` zeigte auf ein
        Objekt, das es nicht mehr gab. Die API lief in `minio.get_object` auf
        einen Fehler und lieferte 404 — ununterscheidbar von „dieser Alarm
        hatte nie einen Mitschnitt". Clients boten den Download trotzdem an.

        Bewusst über das **Alter** statt über eine Objektabfrage: die
        Lifecycle-Regel arbeitet nach genau demselben Maß, und ein
        `stat_object` je Alarm wäre bei sechsstelligen Zeilenzahlen nicht
        tragbar. Der Alert-Zeitstempel liegt minimal vor der Objekt-Erzeugung
        (Upload passiert erst nach dem ±window_s-Fenster), wir räumen also
        eher ein paar Minuten zu früh als zu spät auf — das ist die richtige
        Richtung: lieber nichts versprechen als ein leeres Versprechen.

        Gibt die Anzahl bereinigter Zeilen zurück, 0 auch im Fehlerfall.
        """
        if retention_days <= 0:
            return 0

        for attempt in range(3):
            try:
                self._connect()
                with self._conn.cursor() as cur:      # type: ignore[union-attr]
                    cur.execute(
                        """
                        UPDATE alerts
                        SET pcap_available = false, pcap_key = NULL
                        WHERE pcap_available
                          AND ts < now() - make_interval(days => %s)
                        """,
                        (retention_days,),
                    )
                    cleared = cur.rowcount
                self._conn.commit()                   # type: ignore[union-attr]
                return cleared if cleared > 0 else 0
            except Exception as exc:
                log.error("PCAP-Retention-Sweep, Versuch %d: %s", attempt + 1, exc)
                if self._conn:
                    try:
                        self._conn.rollback()
                    except Exception:
                        pass
                    self._conn = None
                if attempt < 2:
                    time.sleep(2 ** attempt)
        return 0

    def _connect(self) -> None:
        if self._conn is None or self._conn.closed:
            self._conn = psycopg2.connect(self._dsn)
            self._conn.autocommit = False

    def close(self) -> None:
        if self._conn and not self._conn.closed:
            self._conn.close()
