#!/bin/sh
# ══════════════════════════════════════════════════════════════════════════════
# MinIO Bucket Initialisierung
# Wird einmalig beim Stack-Start ausgeführt (minio-init Service)
# ══════════════════════════════════════════════════════════════════════════════
set -e

echo "[minio-init] Konfiguriere MinIO Client..."
mc alias set local http://"${MINIO_ENDPOINT:-minio:9000}" \
  "$MINIO_ACCESS_KEY" \
  "$MINIO_SECRET_KEY" \
  --api S3v4

# ──────────────────────────────────────────────────────────────────────────────
# Bucket: ids-pcaps
# Speichert Header-only PCAPs (kein Payload) für Alert-Downloads
# Lifecycle: automatisches Löschen nach 30 Tagen
# ──────────────────────────────────────────────────────────────────────────────
echo "[minio-init] Erstelle Bucket 'ids-pcaps'..."
mc mb --ignore-existing local/ids-pcaps

echo "[minio-init] Setze Lifecycle auf 30 Tage..."
mc ilm add \
  --expiry-days 30 \
  local/ids-pcaps

# ──────────────────────────────────────────────────────────────────────────────
# Bucket: ids-models
# Speichert ML-Modell-Snapshots (Versionierung)
# Kein automatisches Löschen – manuelle Verwaltung
# ──────────────────────────────────────────────────────────────────────────────
echo "[minio-init] Erstelle Bucket 'ids-models'..."
mc mb --ignore-existing local/ids-models

# ──────────────────────────────────────────────────────────────────────────────
# Bucket: ids-exports
# Temporäre Exporte (CSV-Downloads, Reports)
# Lifecycle: automatisches Löschen nach 7 Tagen
# ──────────────────────────────────────────────────────────────────────────────
echo "[minio-init] Erstelle Bucket 'ids-exports'..."
mc mb --ignore-existing local/ids-exports

echo "[minio-init] Setze Lifecycle auf 7 Tage..."
mc ilm add \
  --expiry-days 7 \
  local/ids-exports

# ──────────────────────────────────────────────────────────────────────────────
# Status-Ausgabe
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo "[minio-init] Buckets angelegt:"
mc ls local | sed 's/^/  /'

echo ""
echo "[minio-init] Lifecycle-Regeln:"
echo "  ids-pcaps:   30 Tage"
echo "  ids-models:  unbegrenzt"
echo "  ids-exports: 7 Tage"
echo "[minio-init] Fertig."
