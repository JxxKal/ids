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

# WICHTIG: KEIN `mc alias set` mit Secret als CLI-Argument. Wenn der
# MINIO_SECRET_KEY mit `--` beginnt (random-generierter Wert), interpretiert
# mc das als Flag → Init bricht ab und Lifecycle wird nie gesetzt.
#
# Stattdessen: MC_HOST_<alias>-Env-Var. Das Secret landet in der URL-
# Userinfo-Section, wo `--` keine Sonderbedeutung hat.
#
# URL-Encoding: das mc-Image (minio/mc:latest) ist ein minimaler busybox-
# scratch-Build, hat weder sed noch awk noch python. Wir prüfen darum nur
# auf URL-kritische Zeichen und brechen mit klarer Meldung ab statt halbgar
# weiterzumachen. Typische Random-Generators (openssl rand -base64,
# url-safe-base64) liefern alphanumerisch + `_-+/=` — alles davon ist
# in der Userinfo-Section legal AUSSER `:` und `@` und `/`. Wenn doch
# eines davon im Secret steckt, muss der User in .env quoten oder neu
# generieren.
EP="${MINIO_ENDPOINT:-minio:9000}"
case "$MINIO_SECRET_KEY" in
  *:*|*@*|*/*|*\?*|*\#*|*%*)
    echo "[minio-init] FEHLER: MINIO_SECRET_KEY enthält URL-kritisches Zeichen."
    echo "[minio-init]    Erlaubt: alphanumerisch + _-+=. Secret in .env neu erzeugen, z.B.:"
    echo "[minio-init]    openssl rand -hex 32   bzw.   openssl rand -base64 32 | tr -d /+="
    exit 1
    ;;
esac
case "$MINIO_ACCESS_KEY" in
  *:*|*@*|*/*|*\?*|*\#*|*%*)
    echo "[minio-init] FEHLER: MINIO_ACCESS_KEY enthält URL-kritisches Zeichen."
    exit 1
    ;;
esac
export MC_HOST_local="http://${MINIO_ACCESS_KEY}:${MINIO_SECRET_KEY}@${EP}"

# Smoke-Test: erste Anfrage gegen den Server. Wenn Auth/Endpoint kaputt
# ist, scheitert mc hier und das Skript bricht via `set -e` ab — besser
# als später einen halbgaren Bucket zu hinterlassen.
if ! mc admin info local >/dev/null 2>&1; then
  echo "[minio-init] FEHLER: mc kann sich nicht zu MinIO verbinden."
  echo "[minio-init]    Endpoint: $EP"
  echo "[minio-init]    Access-Key: ${MINIO_ACCESS_KEY:-<unset>}"
  echo "[minio-init]    Secret gesetzt: $([ -n "$MINIO_SECRET_KEY" ] && echo ja || echo NEIN)"
  exit 1
fi

ensure_bucket() {
  bucket="$1"
  mc mb --ignore-existing "local/$bucket" >/dev/null
}

# Idempotente Lifecycle-Verwaltung: das mc-Image (busybox-scratch) hat
# weder sed noch grep, daher kein content-basierter Diff möglich. Lösung:
# unconditional reset — alle bestehenden Rules wegnehmen, frische setzen.
# Nach jedem Run ist der State garantiert "$days Tage", egal was vorher
# war. Doppel-Rules nach mehreren Re-Inits sind damit auch ausgeschlossen.
ensure_lifecycle() {
  bucket="$1"
  days="$2"

  # mc ilm rule rm --all-rules entfernt alle bestehenden Rules.
  # Falls keine da sind: exit non-zero, ignorieren wir.
  # Falls die Sub-Variante --all-rules nicht unterstützt wird, fällt auf
  # das alte 'mc ilm rule clear' zurück.
  mc ilm rule rm --force --all-rules "local/$bucket" >/dev/null 2>&1 \
    || mc ilm rule clear --force "local/$bucket" >/dev/null 2>&1 \
    || true

  mc ilm rule add --expiry-days "$days" "local/$bucket" >/dev/null
  echo "  $bucket: Lifecycle gesetzt ($days Tage Expiry)."
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
mc ls local

echo
echo "[minio-init] Lifecycle-Status pro Bucket:"
for b in ids-pcaps ids-exports; do
  echo "--- $b ---"
  mc ilm rule ls "local/$b" 2>&1
done

echo
echo "[minio-init] Fertig."
