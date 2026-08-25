# Cyjan IDS Update-Paket

Dieses ZIP enthält vorgebaute Docker-Images (images.tar.zst, inkl. der
externen Runtime-Images) und wird über Einstellungen → System-Update
importiert.

Beim Import werden:
- images.tar.zst via `zstd -dc | docker load` geladen (kein Build, kein Internet)
- docker-compose.yml und infra/ aktualisiert
- Container mit `docker compose up -d` neu gestartet
- .env, .git und Datenbank bleiben unverändert

## Empfohlen nach dem ersten Import dieses Updates

Einmalig auf dem Host als root ausführen, damit die Container-Log-
Rotation (50m × 5) und der wöchentliche Docker-Maintenance-Cron
aktiv werden:

    sudo bash /opt/ids/scripts/post-update.sh

Idempotent — kann beliebig oft laufen, ändert nur Pfade unter
/etc/docker/ und /etc/systemd/system/ die der API-Container nicht
selbst bedienen kann.

## Remote-Taps mit-versorgen

Nach dem Master-Update enthält /opt/ids/tap-update/ das passende
Tap-Image-Bundle, ein Manifest und das aktuelle docker-compose.tap.yml.
master-uplink serviert sie via mTLS unter /tap-update/<file>. Auf
jedem gepairten Tap reicht dann:

    sudo cyjan-tap update --from-master

Pull-basiert — der Tap zieht selbst, kein Master-Push. Hash-
Verifikation gegen das Manifest, anschließend `docker load` +
`compose up -d --force-recreate`. Outage-Buffer fängt die ~30 s
Restart-Lücke ab.

## Notfall-Wiederherstellung

Falls die GUI-Update-Pipeline scheitert (z.B. weil eine sehr alte
API-Version im Container das aktuelle Bundle-Format nicht erkennt
und daraufhin in den Build-Pfad fällt), liegt nach der Extraktion
alles unter /opt/ids/ und das Recovery-Script erledigt den Rest:

    sudo bash /opt/ids/recover.sh
