#!/usr/bin/env bash
# ============================================================
# Baut das Update-ZIP für „Einstellungen → System-Update".
#
# Läuft auf einem Dockerhost mit gebautem Stack (z. B. dem Dev-Master) —
# NICHT auf dem Mac, dort gibt es kein Docker. Das Layout entspricht exakt
# dem v2.7.2-Paket; was der Import damit tut, steht in UPDATE.md im ZIP.
#
#   cd /opt/ids && git fetch --tags && git checkout vX.Y.Z
#   docker compose build
#   bash scripts/build-update-zip.sh [/pfad/ausgabe]
#
# Inhalt:
#   images.tar.zst      docker save aller Compose-Images (auch Runtime-Images
#                       wie Kafka/Redis/TimescaleDB — Air-Gap heißt: nichts
#                       wird nachgeladen)
#   tap-update/         wird von scripts/refresh-tap-update.sh erzeugt und
#                       hier unverändert übernommen
#   docker-compose.yml, .env.example, VERSION, UPDATE.md, recover.sh,
#   infra/, scripts/, signature-engine/rules/, geoip/
# ============================================================
set -euo pipefail

IDS_DIR="$(cd "$(dirname "$0")/.." && pwd)"
OUT_DIR="${1:-/tmp}"
VERSION="$(tr -d '[:space:]' < "$IDS_DIR/VERSION")"
NAME="cyjan-ids-update-${VERSION}"
STAGE="$(mktemp -d)/${NAME}"
mkdir -p "$STAGE"

echo "── ${NAME} ──"

# ── 1. Image-Liste aus dem Compose ziehen ─────────────────────
# `docker compose config --images` löst Profiles/Env auf und nennt genau die
# Images, die der Zielhost laden können muss. Dedupliziert, weil mehrere
# Services dasselbe Basis-Image teilen können.
cd "$IDS_DIR"
mapfile -t IMAGES < <(docker compose config --images 2>/dev/null | sort -u)
if [ "${#IMAGES[@]}" -lt 5 ]; then
  echo "FEHLER: Compose nennt nur ${#IMAGES[@]} Images — falsches Verzeichnis?" >&2
  exit 1
fi
echo "Images: ${#IMAGES[@]}"

MISSING=0
for img in "${IMAGES[@]}"; do
  docker image inspect "$img" >/dev/null 2>&1 || { echo "  fehlt lokal: $img" >&2; MISSING=1; }
done
if [ "$MISSING" = 1 ]; then
  echo "FEHLER: Erst 'docker compose build' bzw. 'docker compose pull' ausführen." >&2
  exit 1
fi

echo "── docker save → zstd (dauert; ~1 GB) ──"
docker save "${IMAGES[@]}" | zstd -T0 -3 -q -o "$STAGE/images.tar.zst"

# ── 2. Dateien aus dem Repo ───────────────────────────────────
cp "$IDS_DIR/docker-compose.yml"      "$STAGE/"
cp "$IDS_DIR/docker-compose.tap.yml"  "$STAGE/"
cp "$IDS_DIR/.env.example"            "$STAGE/"
cp "$IDS_DIR/VERSION"                 "$STAGE/"
cp "$IDS_DIR/distro/update/UPDATE.md" "$STAGE/UPDATE.md" 2>/dev/null \
  || cp "$IDS_DIR/UPDATE.md" "$STAGE/UPDATE.md" 2>/dev/null \
  || { echo "FEHLER: UPDATE.md nicht gefunden." >&2; exit 1; }
cp "$IDS_DIR/distro/update/recover.sh" "$STAGE/recover.sh" 2>/dev/null \
  || cp "$IDS_DIR/recover.sh" "$STAGE/recover.sh" 2>/dev/null \
  || { echo "FEHLER: recover.sh nicht gefunden." >&2; exit 1; }

cp -R "$IDS_DIR/infra"                       "$STAGE/infra"
cp -R "$IDS_DIR/scripts"                     "$STAGE/scripts"
mkdir -p "$STAGE/signature-engine"
cp -R "$IDS_DIR/signature-engine/rules"      "$STAGE/signature-engine/rules"

# GeoIP liegt nicht im Repo (Lizenz), sondern auf dem Host.
if [ -d "$IDS_DIR/geoip" ]; then
  mkdir -p "$STAGE/geoip"
  cp "$IDS_DIR"/geoip/*.mmdb "$STAGE/geoip/" 2>/dev/null || true
fi

# ── 3. Tap-Bundle ─────────────────────────────────────────────
# refresh-tap-update.sh erzeugt /opt/ids/tap-update/ (Images + Manifest +
# Compose). Ohne aktuelles Bundle kein ZIP — sonst verteilte das Update
# stillschweigend alte Tap-Images.
bash "$IDS_DIR/scripts/refresh-tap-update.sh"
cp -R "$IDS_DIR/tap-update" "$STAGE/tap-update"

# ── 4. Packen ─────────────────────────────────────────────────
cd "$(dirname "$STAGE")"
ZIP="$OUT_DIR/${NAME}.zip"
rm -f "$ZIP"
zip -q -r "$ZIP" "$NAME"
echo "Fertig: $ZIP ($(du -h "$ZIP" | cut -f1))"
rm -rf "$(dirname "$STAGE")"
