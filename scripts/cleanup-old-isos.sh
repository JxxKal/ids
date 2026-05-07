#!/bin/bash
# Räumt alte ISO- und Update-ZIP-Assets aus GitHub-Releases.
#
# Policy:
# - ISO: nur Assets im KEEP_TAG bleiben, alles andere wird gelöscht
# - ZIP: die KEEP_ZIPS neuesten Releases mit ZIP-Asset bleiben (Default 2 —
#        aktuelles Release + ein Backup für Rollback), Rest wird gelöscht
#
# Voraussetzung: GitHub-PAT mit `repo`-Scope. Entweder via env-Var oder
# über `gh auth login` (der gh-Variante wenn das CLI installiert ist).
#
# Usage:
#   GITHUB_TOKEN=ghp_xxx scripts/cleanup-old-isos.sh        # dry-run
#   GITHUB_TOKEN=ghp_xxx scripts/cleanup-old-isos.sh --go   # tatsächlich löschen
#   KEEP_TAG=v2.4.0 KEEP_ZIPS=3 scripts/cleanup-old-isos.sh # explizit steuern

set -euo pipefail

REPO="${REPO:-JxxKal/ids}"
DRY=1
[ "${1:-}" = "--go" ] && DRY=0

if [ -z "${GITHUB_TOKEN:-}" ]; then
  if command -v gh >/dev/null 2>&1; then
    GITHUB_TOKEN=$(gh auth token 2>/dev/null || true)
  fi
fi
if [ -z "${GITHUB_TOKEN:-}" ]; then
  echo "FEHLER: kein GITHUB_TOKEN. Setze env-Var oder 'gh auth login' vorher." >&2
  exit 1
fi

API="https://api.github.com/repos/$REPO"
HDR=(-H "Authorization: Bearer $GITHUB_TOKEN" -H "Accept: application/vnd.github+json")

# KEEP_TAG bestimmen (für ISO-Cleanup):
# - explizit via env-Var (z.B. "v2.4.0") oder als 2. Argument → vorrangig
# - sonst: neuestes Release das mindestens ein ISO-Asset hat
KEEP_TAG="${KEEP_TAG:-${2:-}}"
if [ -z "$KEEP_TAG" ]; then
  KEEP_TAG=$(curl -sS "${HDR[@]}" "$API/releases?per_page=100" | python3 -c "
import json, sys
d = json.load(sys.stdin)
for r in d:
    if any(a['name'].endswith('.iso') for a in r.get('assets', [])):
        print(r['tag_name']); break
")
fi
if [ -z "$KEEP_TAG" ]; then
  echo "FEHLER: kein Release mit ISO-Assets gefunden — was soll behalten werden?" >&2
  exit 1
fi
export KEEP_TAG

# KEEP_ZIPS: wieviele der neuesten Releases mit ZIP-Asset bleiben sollen
KEEP_ZIPS="${KEEP_ZIPS:-2}"
export KEEP_ZIPS

echo "Repo:      $REPO"
echo "Keep-Tag:  $KEEP_TAG (ISO)"
echo "Keep-Zips: $KEEP_ZIPS neueste Release(s) mit Update-ZIP"
echo "Modus:     $([ $DRY -eq 0 ] && echo LÖSCHEN || echo DRY-RUN)"
echo

# Alle Releases sammeln (inkl. Pagination — bis 100 Releases reicht uns)
RELEASES=$(curl -sS "${HDR[@]}" "$API/releases?per_page=100")

echo "=== ISO-Plan ==="
echo "$RELEASES" | python3 -c "
import json, sys, os
d = json.load(sys.stdin)
keep = os.environ['KEEP_TAG']
for r in d:
    tag = r['tag_name']
    isos = [a for a in r.get('assets', []) if a['name'].endswith('.iso')]
    if not isos:
        continue
    if tag == keep:
        size = sum(a['size'] for a in isos) // 1024 // 1024
        print(f'KEEP  {tag:18s}  {size}M  ({len(isos)} ISOs)')
    else:
        for a in isos:
            print(f'DEL   {tag:18s}  {a[\"size\"]//1024//1024:5d}M  {a[\"name\"]}  asset_id={a[\"id\"]}')
"

echo
echo "=== ZIP-Plan ==="
echo "$RELEASES" | python3 -c "
import json, sys, os
d = json.load(sys.stdin)
keep_n = int(os.environ['KEEP_ZIPS'])
# API liefert Releases sortiert nach created_at desc — erste = neueste.
zip_releases = [r for r in d if any(a['name'].endswith('.zip') for a in r.get('assets', []))]
keep_tags = {r['tag_name'] for r in zip_releases[:keep_n]}
for r in zip_releases:
    tag = r['tag_name']
    zips = [a for a in r['assets'] if a['name'].endswith('.zip')]
    if tag in keep_tags:
        size = sum(a['size'] for a in zips) // 1024 // 1024
        print(f'KEEP  {tag:18s}  {size}M  ({len(zips)} ZIPs)')
    else:
        for a in zips:
            print(f'DEL   {tag:18s}  {a[\"size\"]//1024//1024:5d}M  {a[\"name\"]}  asset_id={a[\"id\"]}')
"

[ $DRY -eq 1 ] && {
  echo
  echo "Dry-Run. Mit --go zum tatsächlichen Löschen aufrufen."
  exit 0
}

echo
echo "=== Lösche alte ISO-Assets ==="
freed_total=0
for asset_line in $(echo "$RELEASES" | python3 -c "
import json, sys, os
d = json.load(sys.stdin)
keep = os.environ['KEEP_TAG']
for r in d:
    if r['tag_name'] == keep:
        continue
    for a in r.get('assets', []):
        if a['name'].endswith('.iso'):
            print(f'{a[\"id\"]}|{a[\"size\"]}|{a[\"name\"]}|{r[\"tag_name\"]}')
"); do
  IFS='|' read -r aid size name tag <<< "$asset_line"
  size_mb=$((size / 1024 / 1024))
  printf 'rm  %-12s  %5dM  %s\n' "$tag" "$size_mb" "$name"
  curl -sS -X DELETE "${HDR[@]}" "$API/releases/assets/$aid" >/dev/null \
    && freed_total=$((freed_total + size_mb)) \
    || echo "  FAIL"
done

echo
echo "=== Lösche alte ZIP-Assets ==="
for asset_line in $(echo "$RELEASES" | python3 -c "
import json, sys, os
d = json.load(sys.stdin)
keep_n = int(os.environ['KEEP_ZIPS'])
zip_releases = [r for r in d if any(a['name'].endswith('.zip') for a in r.get('assets', []))]
keep_tags = {r['tag_name'] for r in zip_releases[:keep_n]}
for r in zip_releases:
    if r['tag_name'] in keep_tags:
        continue
    for a in r['assets']:
        if a['name'].endswith('.zip'):
            print(f'{a[\"id\"]}|{a[\"size\"]}|{a[\"name\"]}|{r[\"tag_name\"]}')
"); do
  IFS='|' read -r aid size name tag <<< "$asset_line"
  size_mb=$((size / 1024 / 1024))
  printf 'rm  %-12s  %5dM  %s\n' "$tag" "$size_mb" "$name"
  curl -sS -X DELETE "${HDR[@]}" "$API/releases/assets/$aid" >/dev/null \
    && freed_total=$((freed_total + size_mb)) \
    || echo "  FAIL"
done

echo
echo "Freigegeben: ${freed_total} MB"
