#!/bin/sh
# ══════════════════════════════════════════════════════════════════════════════
# MinIO Bucket Initialisierung
#
# Idempotent: läuft bei JEDEM Stack-Start neu durch (bei `docker compose up -d
# --force-recreate` automatisch). Stellt sicher dass Buckets + Lifecycle-Rules
# da sind. Falls die Konfiguration zwischendurch verloren ging (Volume-Reset,
# manuelle ilm rule rm, MinIO-Reinstall), wird sie hier wieder aufgesetzt.
#
# Retention via env-Vars, Defaults sind bewusst aggressiv:
#   PCAP_RETENTION_DAYS    – Default 7 (PCAPs sind groß: 10-20 GB/Tag typisch)
#   EXPORTS_RETENTION_DAYS – Default 7 (CSV-Exporte, klein)
# ══════════════════════════════════════════════════════════════════════════════
set -e

PCAP_DAYS="${PCAP_RETENTION_DAYS:-7}"
EXPORTS_DAYS="${EXPORTS_RETENTION_DAYS:-7}"

echo "[minio-init] Konfiguriere MinIO Client..."
mc alias set local http://"${MINIO_ENDPOINT:-minio:9000}" \
  "$MINIO_ACCESS_KEY" \
  "$MINIO_SECRET_KEY" \
  --api S3v4

ensure_bucket() {
  bucket="$1"
  mc mb --ignore-existing "local/$bucket" >/dev/null
}

# Idempotente Lifecycle-Verwaltung: prüft den aktuellen Zustand, gleicht ab.
# Wenn keine Rule da ist oder die Days-Anzahl abweicht, alle Rules entfernen +
# eine frische setzen. Verhindert Doppel-Rules nach mehreren Re-Inits.
ensure_lifecycle() {
  bucket="$1"
  days="$2"

  # mc ilm rule ls --json hat verschiedene Outputs je nach Version. Wir
  # parsen "Days":N — auf älteren Versionen kommt ein "Expiration":{"Days":N}-
  # Block, neuere flatten es. Simpler grep matcht beide.
  current=$(mc ilm rule ls --json "local/$bucket" 2>/dev/null \
            | grep -oE '"Days"[ :]*[0-9]+' | head -1 | grep -oE '[0-9]+' || true)

  if [ "$current" = "$days" ]; then
    echo "  $bucket: Lifecycle bereits auf $days Tage."
    return
  fi

  if [ -n "$current" ]; then
    echo "  $bucket: Lifecycle wird angepasst ($current → $days Tage)."
    # mc ilm rule rm --all-rules entfernt alle bestehenden Rules.
    # Älteres mc kennt nur '--all-rules' nicht, fallback auf das alte
    # 'mc ilm rule clear' bzw. 'mc ilm rule rm --id <id>'.
    mc ilm rule rm --force --all-rules "local/$bucket" >/dev/null 2>&1 \
      || mc ilm rule clear --force "local/$bucket" >/dev/null 2>&1 \
      || true
  else
    echo "  $bucket: Lifecycle wird gesetzt ($days Tage)."
  fi

  mc ilm rule add --expiry-days "$days" "local/$bucket" >/dev/null
}

# ──────────────────────────────────────────────────────────────────────────────
# Bucket: ids-pcaps  – Header-only PCAPs für Alert-Downloads
# ──────────────────────────────────────────────────────────────────────────────
echo "[minio-init] Bucket ids-pcaps..."
ensure_bucket   "ids-pcaps"
ensure_lifecycle "ids-pcaps" "$PCAP_DAYS"

# ──────────────────────────────────────────────────────────────────────────────
# Bucket: ids-models  – ML-Modell-Snapshots, KEIN Auto-Expiry
# ──────────────────────────────────────────────────────────────────────────────
echo "[minio-init] Bucket ids-models..."
ensure_bucket "ids-models"

# ──────────────────────────────────────────────────────────────────────────────
# Bucket: ids-exports – temporäre CSV-Downloads
# ──────────────────────────────────────────────────────────────────────────────
echo "[minio-init] Bucket ids-exports..."
ensure_bucket   "ids-exports"
ensure_lifecycle "ids-exports" "$EXPORTS_DAYS"

# ──────────────────────────────────────────────────────────────────────────────
# Status
# ──────────────────────────────────────────────────────────────────────────────
echo
echo "[minio-init] Buckets:"
mc ls local | sed 's/^/  /'

echo
echo "[minio-init] Lifecycle-Status:"
for b in ids-pcaps ids-exports; do
  echo "  $b:"
  mc ilm rule ls "local/$b" 2>&1 | sed 's/^/    /' | head -10
done

echo
echo "[minio-init] Fertig."
