#!/bin/sh
# Cyjan IDS – Notfall-Wiederherstellung nach gescheitertem GUI-Update.
# Lädt das Image-Bundle aus /opt/ids und startet den Stack neu.
set -eu
IDS_DIR="/opt/ids"
cd "$IDS_DIR"

PROFILE="$(cat /etc/cyjan/profile 2>/dev/null || echo prod)"
echo "Compose-Profil: $PROFILE"

if [ -f images.tar.zst ]; then
  if ! command -v zstd >/dev/null 2>&1; then
    echo "FEHLER: zstd fehlt auf dem Host."
    echo "  - Online: sudo apt install -y zstd"
    echo "  - Offline: zstd-Binary von einer anderen Maschine nach"
    echo "    /usr/local/bin/ kopieren und chmod +x setzen."
    exit 1
  fi
  echo "Lade images.tar.zst via zstd -dc | docker load ..."
  zstd -dc images.tar.zst | docker load
  rm -f images.tar.zst
elif [ -f images.tar.gz ]; then
  echo "Lade images.tar.gz via gunzip -c | docker load ..."
  gunzip -c images.tar.gz | docker load
  rm -f images.tar.gz
elif [ -f images.tar ]; then
  echo "Lade images.tar ..."
  docker load -i images.tar
  rm -f images.tar
else
  echo "Kein Image-Bundle gefunden – fahre nur mit compose up fort."
fi

echo "Starte Stack mit Profil $PROFILE ..."
docker compose --project-directory "$IDS_DIR" --profile "$PROFILE" up -d
echo "Fertig."
