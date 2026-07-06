#!/bin/bash
# Refreshe /opt/ids/tap-update/ auf den aktuellen Repo-Stand.
#
# Wird typisch nach `git pull && docker compose build` am Master
# aufgerufen, wenn man den Stack-Code aktualisiert hat aber kein
# komplettes Update-ZIP eingespielt wurde. Nach dem Refresh können
# die gepairten Taps via `sudo cyjan-tap update --from-master`
# das aktuelle Bundle ziehen.
#
# Idempotent: kann beliebig oft laufen. Re-baut das Tap-Bundle aus
# den Images die aktuell im Daemon sind, schreibt frische manifest.json
# + scripts/.

set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Bitte als root ausführen (sudo)." >&2
  exit 1
fi

IDS_DIR="${CYJAN_DIR:-/opt/ids}"
cd "$IDS_DIR"

VERSION=$(cat VERSION 2>/dev/null || echo dev)
echo "Repo-Stand: $VERSION"

mkdir -p tap-update/scripts

echo "=== Tap-Compose + Skripte aktualisieren ==="
cp docker-compose.tap.yml                                                       tap-update/docker-compose.tap.yml
cp distro/config/includes.chroot/etc/docker/daemon.json                         tap-update/scripts/daemon.json
cp distro/config/includes.chroot/usr/local/bin/cyjan-maintenance                tap-update/scripts/cyjan-maintenance
cp distro/config/includes.chroot/etc/systemd/system/cyjan-maintenance.service   tap-update/scripts/cyjan-maintenance.service
cp distro/config/includes.chroot/etc/systemd/system/cyjan-maintenance.timer     tap-update/scripts/cyjan-maintenance.timer
cp distro/config/includes.chroot/usr/local/bin/cyjan-mirror-tune                tap-update/scripts/cyjan-mirror-tune
cp distro/config/includes.chroot/etc/systemd/system/cyjan-mirror-tune.service   tap-update/scripts/cyjan-mirror-tune.service
cp distro/config/includes.chroot/usr/local/bin/cyjan-tap                        tap-update/scripts/cyjan-tap
cp distro/config/includes.chroot/etc/systemd/system/cyjan-tap-update.path       tap-update/scripts/cyjan-tap-update.path
cp distro/config/includes.chroot/etc/systemd/system/cyjan-tap-update.service    tap-update/scripts/cyjan-tap-update.service
cp distro/config/includes.chroot/etc/tmpfiles.d/cyjan-update.conf               tap-update/scripts/cyjan-update.tmpfiles
cp scripts/post-update.sh                                                       tap-update/scripts/post-update.sh
chmod +x tap-update/scripts/post-update.sh tap-update/scripts/cyjan-maintenance \
         tap-update/scripts/cyjan-mirror-tune tap-update/scripts/cyjan-tap

echo "=== Tap-Bundle (docker save + zstd) ==="
# Sniffer/flow-aggregator/signature-engine sind master + tap geteilt — am
# Master ohnehin gebaut. tap-uplink + tap-api müssen extra beschafft werden,
# falls sie nicht im Daemon sind (Master baut sie nicht im normalen
# prod-Profil).
#
# Reihenfolge:
#   1. Falls beide schon im Daemon → nichts tun.
#   2. Sonst aus existierendem tap-update/images-tap.tar.zst nachladen
#      — der wurde via Update-ZIP/CI mitgeliefert und enthält genau diese
#      Images. Offline-safe, kein Internet nötig.
#   3. Falls auch das fehlt (Dev-Master ohne ZIP-Apply, oder corrupted) →
#      docker compose build (braucht Internet wegen python:3.12-slim Base).
need_tap_images=0
for img in ids-tap-uplink:latest ids-tap-api:latest; do
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    need_tap_images=1
    break
  fi
done

if [ "$need_tap_images" -eq 1 ] && [ -r tap-update/images-tap.tar.zst ]; then
  echo "  Tap-Images fehlen im Daemon — lade aus tap-update/images-tap.tar.zst (offline-safe) …"
  zstd -dc tap-update/images-tap.tar.zst | docker load
  # Re-check
  need_tap_images=0
  for img in ids-tap-uplink:latest ids-tap-api:latest; do
    if ! docker image inspect "$img" >/dev/null 2>&1; then need_tap_images=1; break; fi
  done
fi

if [ "$need_tap_images" -eq 1 ]; then
  echo "  Tap-Images noch immer nicht da — versuche docker compose build (braucht Internet wegen Base-Images):"
  MIRROR_INTERFACE=eth0 MASTER_URL=wss://placeholder.example/uplink POSTGRES_PASSWORD=placeholder \
    docker compose -f docker-compose.tap.yml build tap-uplink tap-api
fi

# Kafka-Image-Tag aus dem Tap-Compose ableiten, NICHT hardcoden. Seit v2.5.48
# pinnt docker-compose.tap.yml apache/kafka auf eine feste Version; ein
# hardgecodetes apache/kafka:latest im Bundle ließ den Tap offline am Pull
# scheitern ("failed to resolve apache/kafka:4.2.0"), weil compose den
# gepinnten Tag verlangt, das Bundle aber nur :latest mitbrachte.
# '|| true' hält den Fallback erreichbar: unter set -o pipefail failt sonst
# schon die Zuweisung (grep-Exit 1 bei keinem Treffer), bevor die [ -z ]-
# Bedingung greift → Skript bräche ab statt auf :latest zurückzufallen.
KAFKA_IMG=$(grep -oE 'apache/kafka:[A-Za-z0-9._-]+' docker-compose.tap.yml | head -1 || true)
[ -z "$KAFKA_IMG" ] && KAFKA_IMG="apache/kafka:latest"
# Falls am Master nur apache/kafka:latest vorliegt (älterer Stand), unter dem
# gepinnten Tag aliasen — so trägt das Bundle garantiert den Tag, den der
# Tap-Compose erwartet.
if ! docker image inspect "$KAFKA_IMG" >/dev/null 2>&1 \
     && docker image inspect apache/kafka:latest >/dev/null 2>&1; then
  echo "  apache/kafka:latest → $KAFKA_IMG aliasen (gepinnter Tag fehlte im Daemon)"
  docker tag apache/kafka:latest "$KAFKA_IMG"
fi
echo "  Kafka-Image fürs Bundle: $KAFKA_IMG"

# Atomar schreiben: erst in temp-Dateien, dann per mv umbenennen. Ein
# mittendrin abgebrochenes 'docker save | zstd' (pipefail) hinterließ sonst
# ein korruptes images-tap.tar.zst am finalen Pfad, während manifest.json noch
# den alten sha256 referenziert — ein pullender Tap bekäme dann dauerhaft
# SHA256-Mismatch. Mit temp+mv bleibt bei Abbruch der alte, konsistente Stand
# erhalten (Bundle + Manifest passen zusammen), und der Re-Run repariert.
BUNDLE_FINAL="tap-update/images-tap.tar.zst"
MANIFEST_FINAL="tap-update/manifest.json"
BUNDLE_TMP="${BUNDLE_FINAL}.tmp.$$"
MANIFEST_TMP="${MANIFEST_FINAL}.tmp.$$"
trap 'rm -f "$BUNDLE_TMP" "$MANIFEST_TMP"' EXIT

# --force: überschreibt eine bestehende temp-Datei stillschweigend.
docker save \
  ids-sniffer:latest ids-flow-aggregator:latest ids-signature-engine:latest \
  ids-tap-uplink:latest ids-tap-api:latest "$KAFKA_IMG" \
  | zstd -3 -T0 --force -o "$BUNDLE_TMP"

SHA=$(sha256sum "$BUNDLE_TMP" | cut -d' ' -f1)
SIZE=$(stat -c%s "$BUNDLE_TMP")
CSHA=$(sha256sum tap-update/docker-compose.tap.yml | cut -d' ' -f1)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > "$MANIFEST_TMP" <<MANIFEST
{
  "version": "${VERSION}",
  "created_at": "${TS}",
  "bundle":  { "file": "images-tap.tar.zst",     "sha256": "${SHA}",  "size": ${SIZE} },
  "compose": { "file": "docker-compose.tap.yml", "sha256": "${CSHA}" }
}
MANIFEST

# Fertiges Bundle einschwenken, danach das Manifest — so referenziert das
# Manifest nie ein noch nicht vorhandenes/halbes Bundle.
mv -f "$BUNDLE_TMP" "$BUNDLE_FINAL"
mv -f "$MANIFEST_TMP" "$MANIFEST_FINAL"

echo
echo "Fertig. tap-update/ ist auf $VERSION."
echo "  Bundle: $(du -sh tap-update/images-tap.tar.zst | cut -f1)"
echo
cat tap-update/manifest.json
echo
echo "Gepairte Taps können nun ziehen:  sudo cyjan-tap update --from-master"
