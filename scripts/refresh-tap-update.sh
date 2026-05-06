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
cp scripts/post-update.sh                                                       tap-update/scripts/post-update.sh
chmod +x tap-update/scripts/post-update.sh tap-update/scripts/cyjan-maintenance \
         tap-update/scripts/cyjan-mirror-tune tap-update/scripts/cyjan-tap

echo "=== Tap-Bundle (docker save + zstd) ==="
# Sniffer/flow-aggregator/signature-engine sind master + tap geteilt — am
# Master ohnehin gebaut. tap-uplink + tap-api müssen extra gebaut werden,
# falls sie noch fehlen (Master baut sie nicht im normalen prod-Profil).
for img in ids-tap-uplink:latest ids-tap-api:latest; do
  if ! docker image inspect "$img" >/dev/null 2>&1; then
    echo "  $img fehlt — baue tap-uplink + tap-api einmalig:"
    MIRROR_INTERFACE=eth0 MASTER_URL=wss://placeholder.example/uplink POSTGRES_PASSWORD=placeholder \
      docker compose -f docker-compose.tap.yml build tap-uplink tap-api
    break
  fi
done

# --force: überschreibt eine bestehende images-tap.tar.zst stillschweigend.
docker save \
  ids-sniffer:latest ids-flow-aggregator:latest ids-signature-engine:latest \
  ids-tap-uplink:latest ids-tap-api:latest apache/kafka:latest \
  | zstd -3 -T0 --force -o tap-update/images-tap.tar.zst

SHA=$(sha256sum tap-update/images-tap.tar.zst | cut -d' ' -f1)
SIZE=$(stat -c%s tap-update/images-tap.tar.zst)
CSHA=$(sha256sum tap-update/docker-compose.tap.yml | cut -d' ' -f1)
TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

cat > tap-update/manifest.json <<MANIFEST
{
  "version": "${VERSION}",
  "created_at": "${TS}",
  "bundle":  { "file": "images-tap.tar.zst",     "sha256": "${SHA}",  "size": ${SIZE} },
  "compose": { "file": "docker-compose.tap.yml", "sha256": "${CSHA}" }
}
MANIFEST

echo
echo "Fertig. tap-update/ ist auf $VERSION."
echo "  Bundle: $(du -sh tap-update/images-tap.tar.zst | cut -f1)"
echo
cat tap-update/manifest.json
echo
echo "Gepairte Taps können nun ziehen:  sudo cyjan-tap update --from-master"
