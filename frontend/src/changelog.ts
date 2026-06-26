// Versionshistorie — als Text gepflegt. Bei jedem Release-Tag hier oben einen
// neuen Eintrag ergänzen (neueste Version zuerst). Wird in zwei Stellen genutzt:
//   1. Settings → Versionsinformation (vollständige Historie mit Sprungmarken)
//   2. Versions-Popup beim ersten Login in eine neue Version (zeigt den Eintrag
//      der laufenden Version; changelogFor() matcht auf den exakten Versionsstring)
//
// `notes` sind reine Textzeilen (kein Markdown) — bewusst, damit kein Renderer
// nötig ist und nichts per innerHTML interpretiert wird.

export interface ChangelogEntry {
  version: string;   // exakt wie im VERSION-File / GET /api/system/version, z.B. "v2.5.40"
  date:    string;   // ISO-Datum, z.B. "2026-06-18"
  title:   string;   // Kurztitel der Version
  notes:   string[]; // Stichpunkte, nutzerverständlich
}

export const CHANGELOG: ChangelogEntry[] = [
  {
    version: 'v2.5.57',
    date: '2026-06-26',
    title: 'Eigene Host-Rollen (Custom-Rollen)',
    notes: [
      'Unter Hosts → „Custom-Rollen" lassen sich jetzt eigene Rollen anlegen, definiert über Ports und Port-Ranges (z.B. „2010, 9100-9110"). Die Erkennung taggt damit automatisch alle Hosts, die diese Ports bedienen — genau wie die mitgelieferten Rollen.',
      'Pro Rolle wählbar: Treffer-Modus (alle Ports erforderlich oder mindestens N), Protokoll und Konfidenz. Custom-Rollen erscheinen automatisch im Rollen-Filter, als Badge und sind pro Host manuell überschreib- und unterdrückbar.',
    ],
  },
  {
    version: 'v2.5.56',
    date: '2026-06-24',
    title: 'CLI-Update aktualisiert auch das Tap-Bundle',
    notes: [
      'Behebt, dass nach einem Konsolen-Update (`cyjan-update apply`) am Master das an die Taps ausgelieferte Bundle (`/opt/ids/tap-update/`) veraltet blieb — das GUI-System-Update tat das schon, die CLI nicht. Dadurch zog ein „Update pushen" auf einen Tap bisher die alte Version.',
      'Ab jetzt hält der Konsolen-Updater das Tap-Bundle genauso frisch wie das GUI-Update. Greift ab dem nächsten `cyjan-update apply` nach Einspielen dieser Version.',
    ],
  },
  {
    version: 'v2.5.55',
    date: '2026-06-23',
    title: 'Tap-MOTD: Update-Befehl korrigiert',
    notes: [
      'Das Login-Banner auf Remote-Tap-Hosts zeigt jetzt das korrekte Update-Kommando „cyjan-tap update --from-master" statt des generischen „ids-update". Kommt auf bestehende Taps mit dem nächsten Update.',
    ],
  },
  {
    version: 'v2.5.54',
    date: '2026-06-23',
    title: 'Host-Rollen auch für Tap-Hosts',
    notes: [
      'Die Host-Rollenerkennung erfasst jetzt auch Geräte, die nur ein Remote-Tap sieht (und nicht der Master selbst). Der Tap fasst dafür laufend zusammen, welche Ports seine beobachteten Hosts bedienen, und schickt dieses kompakte Profil über die bestehende verschlüsselte Tap-Verbindung an den Master — ganz ohne den vollen Netzwerk-Mitschnitt zu übertragen.',
      'Der Master führt Tap- und eigene Beobachtungen pro Host zusammen und klassifiziert sie identisch (gleiche Badges, Filter, manuelles Überschreiben/Unterdrücken). Standardmäßig aktiv; pro Tap abschaltbar.',
    ],
  },
  {
    version: 'v2.5.53',
    date: '2026-06-23',
    title: 'Fix: Host-Rollen auf Offline-Hosts',
    notes: [
      'Behebt leere Rollen-Spalten auf Hosts, die per Offline-Update (statt frischem ISO) auf v2.5.50+ gebracht wurden: der Rollen-Katalog liegt als Datei neben den Heuristik-Regeln und wurde bisher nicht ins Update-Paket gelegt — dadurch fand die Erkennung keine Rollen und es ließ sich auch manuell keine setzen.',
      'Das Update-Paket enthält jetzt die Regel-/Katalog-Dateien (signature-engine/rules). Nebeneffekt: auch Änderungen an den normalen Heuristik-Regeln erreichen Air-Gap-Hosts künftig über das Update statt nur über ein neues ISO.',
      'Nach Einspielen erscheinen die Rollen automatisch innerhalb des nächsten Detektor-Durchlaufs; das manuelle Setzen/Unterdrücken pro Host funktioniert wieder.',
    ],
  },
  {
    version: 'v2.5.52',
    date: '2026-06-23',
    title: 'Host-Rollen: dauerhaft unterdrücken (Negativ-Lock)',
    notes: [
      'Eine fälschlich erkannte Host-Rolle lässt sich jetzt dauerhaft unterdrücken — im Host-Editor (Hosts → Bearbeiten) gibt es neben „Entfernen" einen „🚫 Unterdrücken"-Button. „Entfernen" wirkte nur einmalig (die automatische Erkennung fügte die Rolle im nächsten Durchlauf wieder hinzu); „Unterdrücken" hält sie dauerhaft fern.',
      'Unterdrückte Rollen werden im Editor separat (durchgestrichen) gelistet und lassen sich mit „Aufheben" wieder der Auto-Erkennung übergeben.',
    ],
  },
  {
    version: 'v2.5.51',
    date: '2026-06-22',
    title: 'Host-Rollen im Dashboard-Alarmfeed',
    notes: [
      'Die erkannten Host-Rollen (Domain Controller, Web-/DB-/Mail-Server, SCADA/PLC …) erscheinen jetzt auch direkt im Alarm-Feed des Dashboards — als kompakte Badges neben Quell- und Ziel-IP, mit Konfidenz und Begründung im Tooltip. So sieht man auf einen Blick, welche Art von System an einem Alarm beteiligt ist, ohne in die Hosts-Ansicht wechseln zu müssen.',
    ],
  },
  {
    version: 'v2.5.50',
    date: '2026-06-22',
    title: 'Host-Rollenerkennung',
    notes: [
      'Cyjan erkennt jetzt automatisch, welche Rolle ein Host im Netz spielt — z.B. Domain Controller, DNS-, Web-, Datenbank- oder Mail-Server, RDP-/SSH-Host, sowie OT-Geräte wie Siemens-S7-/Modbus-/BACnet-SPS und WinCC/iFix-SCADA. Grundlage sind die tatsächlich bedienten Ports (über 7 Tage beobachtet) plus, wo möglich, der MAC-Hersteller (OUI).',
      'In der Hosts-Ansicht erscheinen die Rollen als Badges (mit Konfidenz und Begründung im Tooltip), und es lässt sich nach Rolle filtern.',
      'Rollen sind manuell überschreibbar: eine selbst gesetzte Rolle wird gesperrt und von der automatischen Erkennung nicht mehr angefasst, bis man sie wieder freigibt — analog zum bekannten Sperr-Prinzip beim Schwellwert-Tuning.',
      'Der Rollen-Katalog (23 Rollen) ist als YAML gepflegt und erweiterbar; er wird über den Reverse-Channel auch an gepairte Remote-Taps verteilt.',
    ],
  },
  {
    version: 'v2.5.49',
    date: '2026-06-22',
    title: 'Schnelleres Laden (Code-Splitting)',
    notes: [
      'Das Web-UI lädt beim Start spürbar weniger: die einzelnen Seiten (Einstellungen, Hosts, Netzwerke, Berichte, …) werden erst beim Öffnen nachgeladen statt alles vorab. Der Erst-Ladevorgang ist rund 40 % kleiner.',
    ],
  },
  {
    version: 'v2.5.48',
    date: '2026-06-22',
    title: 'Reproduzierbare Builds (Image-Pinning)',
    notes: [
      'Die externen Basis-Images (TimescaleDB, Kafka, Redis, MinIO, Kafka-UI) sind jetzt auf feste Versionen gepinnt statt „latest" — damit liefert jeder Build dasselbe, und es gibt keine unbemerkte Versions-Drift mehr zwischen Releases.',
    ],
  },
  {
    version: 'v2.5.47',
    date: '2026-06-19',
    title: 'Reliability-Feinschliff',
    notes: [
      'Live-Verbindung: Reconnect mit exponentiellem Backoff (1s→30s, mit Jitter) statt festem 3-Sekunden-Takt — schont Server und Netz, wenn viele Clients nach einem Neustart gleichzeitig zurückkommen.',
      'Redis-Verbindung im API-Dienst wird wiederverwendet statt pro Cache-Invalidierung neu aufgebaut; alle Kafka-Producer nutzen jetzt einheitlich LZ4-Kompression.',
    ],
  },
  {
    version: 'v2.5.46',
    date: '2026-06-19',
    title: 'Service-Token-Härtung & Sicherheits-Doku',
    notes: [
      'Der rule-tuner nutzt jetzt kurzlebige Service-Tokens (5 Minuten, pro Anfrage frisch) statt eines unwiderruflichen 365-Tage-Admin-Tokens — ein geleaktes Token ist damit nur Minuten gültig.',
      'Sicherheits- und Trust-Boundary-Dokumentation im README ergänzt (Docker-Socket, Service-Auth, mTLS, CSP).',
    ],
  },
  {
    version: 'v2.5.45',
    date: '2026-06-19',
    title: 'Sicherheits-Härtung & kein Alarm-Verlust',
    notes: [
      'Alarme gehen bei einem DB-Ausfall nicht mehr verloren: der alert-manager puffert sie (gedeckelt) und schreibt sie nach, sobald die Datenbank zurück ist — statt sie nach wenigen Sekunden zu verwerfen.',
      'Sicherheits-Härtung: Content-Security-Policy-Header gegen XSS, Brute-Force-Bremse am Login (5 Fehlversuche/Minute pro IP), und Absicherung des iTop-Org-Filters gegen Query-Injection.',
    ],
  },
  {
    version: 'v2.5.44',
    date: '2026-06-19',
    title: '504-Fix Datenbank-Sektion (große Systeme)',
    notes: [
      'Die Datenbank-Sektion lief auf großen Installationen in einen 504 Gateway Timeout — der zur Laufzeit erzeugten nginx-Konfig fehlte das Proxy-Timeout (60s-Default). Jetzt 180s, plus pro-Statement-Timeout in der Statistik-Abfrage, damit eine langsame Teilabfrage Teildaten liefert statt zu hängen.',
    ],
  },
  {
    version: 'v2.5.43',
    date: '2026-06-19',
    title: 'Versionshistorie überarbeitet',
    notes: [
      'Ausführliche, verständliche Beschreibungen für die älteren Marken-Releases (v2.5.0 RedTeam, v2.4.0 Major, die v1.0.x ISO-/Installer-Linie).',
    ],
  },
  {
    version: 'v2.5.42',
    date: '2026-06-19',
    title: 'Vollständige Versionshistorie',
    notes: [
      'Die Versionsinformation listet jetzt die komplette Historie (alle Versionen seit v1.0.2).',
      'Die Sprungmarken-Leiste zeigt die 10 neuesten Versionen; ältere lassen sich per „+N ältere" aufklappen, damit die Leiste nicht überläuft.',
    ],
  },
  {
    version: 'v2.5.41',
    date: '2026-06-19',
    title: 'Versionsinformation & Update-Hinweise',
    notes: [
      'Neue Sektion „Versionsinformation" (unter Einstellungen → System) mit der vollständigen Versionshistorie und Sprungmarken pro Version.',
      'Beim ersten Login nach einem Update erscheint ein Hinweis mit den Neuerungen der Version; per „Gelesen — nicht mehr anzeigen" verschwindet er bis zum nächsten Update.',
    ],
  },
  {
    version: 'v2.5.40',
    date: '2026-06-18',
    title: 'Retention-Verwaltung & Notfall-Cleanup',
    notes: [
      'Neue Sektion „Datenbank → Retention": Aufbewahrungsfrist pro Datentyp (flows, alerts, …) setzen oder entfernen, mit Größenübersicht je Tabelle.',
      'Notfall-Cleanup: Läuft die Festplatte trotz Retention über 92 % voll, werden automatisch die ältesten Daten gelöscht (mit Schutz-Fristen je Tabelle), bis wieder Platz ist — alarmiert dabei sichtbar.',
    ],
  },
  {
    version: 'v2.5.39',
    date: '2026-06-18',
    title: 'Retention-/Disk-Monitor',
    notes: [
      'Überwacht alle 6 Stunden Festplatten-Auslastung, Datenbankgröße und die TimescaleDB-Aufräum-Jobs.',
      'Alarmiert frühzeitig (DISK_SPACE_001 / RETENTION_001), bevor die Platte volläuft — inklusive Hinweis, welche Datentypen keine Aufbewahrungsfrist haben.',
    ],
  },
  {
    version: 'v2.5.38',
    date: '2026-06-18',
    title: 'Speicher-Limits',
    notes: [
      'Arbeitsspeicher-Obergrenzen für alle Dienste, damit ein einzelner Amok-Dienst (z. B. Kafka, ML-Training) nicht den ganzen Host lahmlegt.',
      'Kafka-Heap und Redis-Cache zusätzlich passend begrenzt.',
    ],
  },
  {
    version: 'v2.5.37',
    date: '2026-06-16',
    title: 'Update-Cache-Fix',
    notes: [
      'Nach einem Update lädt der Browser sofort die neue Oberfläche — der bisher nötige manuelle Hard-Reload entfällt.',
    ],
  },
  {
    version: 'v2.5.36',
    date: '2026-06-15',
    title: 'Dashboard-Filter & Live-Stabilität',
    notes: [
      'Neuer Schalter „Unterdrückte anzeigen" blendet automatisch heruntergestufte (ml-/auto-suppressed) Alarme aus oder ein.',
      'Der Live-Modus verbindet sich nach dem Login zuverlässig und heilt eine hängende Verbindung selbst — kein „offline" mehr bis zum manuellen Reload.',
    ],
  },
  {
    version: 'v2.5.35',
    date: '2026-06-12',
    title: 'Health-Checks',
    notes: [
      'Alle Pipeline-Dienste melden ihren Gesundheitszustand — ein hängender, aber nicht abgestürzter Dienst fällt jetzt auf.',
    ],
  },
  {
    version: 'v2.5.34',
    date: '2026-06-12',
    title: 'Sicherheit: Signing-Key',
    notes: [
      'Die API startet nicht mehr mit dem unveränderten Default-Signing-Key — verhindert fälschbare Admin-Tokens auf Hand-Installationen.',
    ],
  },
  {
    version: 'v2.5.33',
    date: '2026-06-12',
    title: 'Update- & Anzeige-Korrekturen',
    notes: [
      'Updates berücksichtigen jetzt alle aktiven Compose-Profile — Suricata/snort lief sonst nach Updates auf altem Stand weiter.',
      'System Details: doppelte Lab-Gruppe und der Init-Container-Zähler korrigiert.',
    ],
  },
  {
    version: 'v2.5.32',
    date: '2026-06-11',
    title: 'Boot-Recovery',
    notes: [
      'Nach jedem Neustart wird geprüft, ob der komplette Stack hochkommt; fehlende oder unhealthy Dienste lösen Alarm aus (Journal, Konsolen-Banner und Web-UI).',
    ],
  },
  {
    version: 'v2.5.31',
    date: '2026-06-11',
    title: 'Tap-Disk-Watch-Fix',
    notes: [
      'Das automatische Aufräumen lief fälschlich auf Master-Hosts und war defekt — jetzt nur auf Taps und funktionsfähig.',
    ],
  },
  {
    version: 'v2.5.30',
    date: '2026-06-11',
    title: 'System Details',
    notes: [
      'Neuer Tab „System Details" mit profilbewusstem Container-Status (prod vs. lab).',
    ],
  },
  {
    version: 'v2.5.29',
    date: '2026-06-03',
    title: 'Traffic-Generator offline',
    notes: [
      'Das Test-Feature (synthetischer Verkehr) ist jetzt auch ohne Internet im Produktiv-Bundle nutzbar.',
    ],
  },
  {
    version: 'v2.5.28',
    date: '2026-06-03',
    title: 'Reboot-Härtung',
    notes: [
      'Reboot-Recovery sowie Schutz gegen versehentlichen Ctrl-Alt-Del-Neustart über angeschlossene IP-KVMs.',
    ],
  },
  { version: 'v2.5.27', date: '2026-05-26', title: 'ids-setup – sichtbare Meldung beim docker-restart + Proxy-Sanity', notes: [] },
  { version: 'v2.5.26', date: '2026-05-26', title: 'Migration – JSONB doppelt-encoded (CRITICAL DATA-LOSS)', notes: [] },
  { version: 'v2.5.25', date: '2026-05-26', title: 'Migration – Web-SSL-Zertifikate (ids-certs) + Detail-Anzeige', notes: [] },
  { version: 'v2.5.24', date: '2026-05-21', title: 'Migration – Werte vor Insert in native Python-Typen wandeln', notes: [] },
  { version: 'v2.5.23', date: '2026-05-21', title: 'Migration-Apply – Cast-Map für TIMESTAMPTZ/UUID/etc.', notes: [] },
  { version: 'v2.5.22', date: '2026-05-21', title: 'ids-setup – /etc/network/interfaces nicht mehr append\'en', notes: [] },
  { version: 'v2.5.21', date: '2026-05-21', title: 'Migration-Apply – Savepoint pro Row gegen silent-Insert-Loss', notes: [] },
  { version: 'v2.5.20', date: '2026-05-21', title: 'Tap-Push-Update — Path-Watcher überlebt dockerd-Restarts', notes: [] },
  { version: 'v2.5.19', date: '2026-05-21', title: 'Backup-Download – Busy-State + Live-Byte-Counter', notes: [] },
  { version: 'v2.5.18', date: '2026-05-21', title: 'Re-Auth-Eignung jetzt auch in DB-Maintenance', notes: [] },
  { version: 'v2.5.17', date: '2026-05-21', title: 'Hostmigration – Re-Auth-Eignung im UI vorab prüfen', notes: [] },
  { version: 'v2.5.16', date: '2026-05-21', title: 'refresh-tap-update – Tap-Images offline aus images-tap.tar.zst laden', notes: [] },
  { version: 'v2.5.15', date: '2026-05-20', title: 'cyjan-update – EXIT-Trap-Variable außerhalb des Funktions-Scopes', notes: [] },
  { version: 'v2.5.14', date: '2026-05-20', title: 'post-update.sh installiert ids-banner.sh nach + Bundle-Copy', notes: [] },
  { version: 'v2.5.13', date: '2026-05-20', title: 'cyjan-update im Login-Banner + README + CLAUDE.md prominent machen', notes: [] },
  { version: 'v2.5.12', date: '2026-05-20', title: 'cyjan-update – Wrapper-Subdir im ZIP korrekt behandeln', notes: [] },
  { version: 'v2.5.11', date: '2026-05-20', title: 'Re-Auth – username statt sub aus JWT-Payload lesen', notes: [] },
  { version: 'v2.5.10', date: '2026-05-20', title: 'cyjan-update — Console-Updater für den Master-Host', notes: [] },
  { version: 'v2.5.9', date: '2026-05-20', title: 'Settings-Migration + 504-Fix für DB-Stats + Syslog-Forwarder-Fix', notes: [] },
  { version: 'v2.5.8', date: '2026-05-12', title: 'bump VERSION to v2.5.8', notes: [] },
  { version: 'v2.5.7', date: '2026-05-12', title: 'notification-dispatcher ins Master-Image-Bundle aufnehmen', notes: [] },
  { version: 'v2.5.6', date: '2026-05-12', title: 'VERSION-File mit Tag-Namen überschreiben (vorher stale aus Repo)', notes: [] },
  { version: 'v2.5.5', date: '2026-05-11', title: 'test_for_channel-Check vor empty-cache-exit', notes: [] },
  { version: 'v2.5.4', date: '2026-05-11', title: 'Audit-Log Card-Layout statt Tabelle — keine fixed widths, mobile-fit', notes: [] },
  { version: 'v2.5.3', date: '2026-05-11', title: 'RedTeam-Live-Härtung + ICMP-Direction-Fix', notes: [] },
  { version: 'v2.5.2', date: '2026-05-11', title: 'RedTeam-Härtungs-Patches + Lab-veth-Setup-Doku', notes: [] },
  { version: 'v2.5.1', date: '2026-05-11', title: 'RedTeam-Bedienlandschaft komplett', notes: [] },
  {
    version: 'v2.5.0',
    date: '2026-05-10',
    title: 'Pattern-Federation & RedTeam-Tooling',
    notes: [
      'Heuristik-Regeln und Overrides lassen sich als signiertes Bundle zwischen Lab- und Kunden-Installationen austauschen (Pattern-Federation).',
      'Integriertes RedTeam-Tooling: Angriffsszenarien aus einem Kali-Container testen die Erkennung, gesteuert über den Master. Standardmäßig deaktiviert.',
    ],
  },
  { version: 'v2.4.3', date: '2026-05-09', title: 'Hotfix-Bundle nach v2.4.2-Deploy', notes: [] },
  { version: 'v2.4.2', date: '2026-05-08', title: 'MQTT-Bridge V1 + Mobile UI + Hardening', notes: [] },
  { version: 'v2.4.1', date: '2026-05-07', title: 'PCAPs auch für Tap-Alerts (V1: tap-uplink als Mini-Store)', notes: [] },
  {
    version: 'v2.4.0',
    date: '2026-05-07',
    title: 'Container-Betrieb & Remote-Tap-Updates (Major)',
    notes: [
      'Remote-Taps werden jetzt zentral vom Master aus aktualisiert (Reverse-Pull über mTLS) statt einzeln von Hand.',
      'Überarbeitete Container-Operationen und Update-Mechanik — Grundlage für die spätere Offline-Update-Pipeline.',
    ],
  },
  { version: 'v1.3.16', date: '2026-04-29', title: 'Egress-Toggle und nahe Hilfetexte → OT-Boundary', notes: [] },
  { version: 'v1.3.15', date: '2026-04-29', title: 'Help-Tooltip für Boundary-Cell (P0–P3 + N/S/D-Pillen)', notes: [] },
  { version: 'v1.3.14', date: '2026-04-29', title: 'Hilfe-Modus mit Text-Tooltips für Dashboard', notes: [] },
  { version: 'v1.3.13', date: '2026-04-29', title: 'Connection-Direction-Normalisierung für Suricata-Alerts', notes: [] },
  { version: 'v1.3.12', date: '2026-04-29', title: 'bump VERSION to v1.3.12', notes: [] },
  { version: 'v1.3.11', date: '2026-04-28', title: 'bump VERSION to v1.3.11', notes: [] },
  { version: 'v1.3.10', date: '2026-04-27', title: 'bump VERSION to v1.3.10', notes: [] },
  { version: 'v1.2.1', date: '2026-04-26', title: 'Inline-Editor für Suricata-Regeln in Settings', notes: [] },
  { version: 'v1.2.0', date: '2026-04-26', title: 'Suricata Offline-Regelimport via GUI-Upload', notes: [] },
  { version: 'v1.1.13', date: '2026-04-26', title: 'asyncpg DataError im /api/hosts/unknown – int statt String-Konkat', notes: [] },
  { version: 'v1.1.3', date: '2026-04-26', title: 'ids-snort fehlt im Offline-Bundle + systemd-timesyncd nachrüsten', notes: [] },
  { version: 'v1.1.2', date: '2026-04-26', title: 'zstd statt gzip für Image-Bundle, fits unter GitHub-2-GiB-Limit', notes: [] },
  { version: 'v1.1.1', date: '2026-04-26', title: 'Tastatur, Zeitzone und NTP-Server im Wizard + Doku-Korrektur', notes: [] },
  { version: 'v1.0.36', date: '2026-04-25', title: 'Interfaces-Seite leer wegen Symlink-Mount + Sniffer-Crashloop', notes: [] },
  {
    version: 'v1.0.35',
    date: '2026-04-25',
    title: 'Konsolen-Spam, der Wizard/Login überlagerte, abgestellt',
    notes: [],
  },
  {
    version: 'v1.0.34',
    date: '2026-04-25',
    title: 'Wizard: Passwort-Schritt bleibt nicht mehr hängen',
    notes: [],
  },
  {
    version: 'v1.0.33',
    date: '2026-04-25',
    title: 'ISO-Release-Notes aktualisiert',
    notes: [],
  },
  {
    version: 'v1.0.32',
    date: '2026-04-25',
    title: 'Boot-Splash mit Cyjan-Schild-Logo',
    notes: [],
  },
  {
    version: 'v1.0.31',
    date: '2026-04-25',
    title: 'Einheitliches Boot-Menü & Splash',
    notes: [
      'Vereinheitlichtes Boot-Menü mit Cyjan-Splash; passwortloser Start des Installers.',
    ],
  },
  {
    version: 'v1.0.30',
    date: '2026-04-25',
    title: 'Funktionierender Erst-Login nach der Installation',
    notes: [
      'URL-sichere Zufalls-Secrets, funktionaler Admin-Login, ids-/root-Passwörter im Wizard setzbar.',
    ],
  },
  {
    version: 'v1.0.29',
    date: '2026-04-25',
    title: 'Setup-Wizard: Mirror-Auswahl & Fortschrittsanzeige',
    notes: [
      'Mirror-Interface im Wizard wählbar, Build-Fortschritt pro Dienst, Versionsheader im Installer.',
    ],
  },
  {
    version: 'v1.0.28',
    date: '2026-04-25',
    title: 'Installer zeigt Build-Fehler sichtbar an',
    notes: [],
  },
  {
    version: 'v1.0.27',
    date: '2026-04-25',
    title: 'Installer-Hänger bei 70 % behoben',
    notes: [],
  },
  {
    version: 'v1.0.26',
    date: '2026-04-25',
    title: 'Live-ISO wird zum vollwertigen Installer',
    notes: [
      'Das Live-ISO installiert das System dauerhaft auf Festplatte, statt nur flüchtig live zu laufen.',
    ],
  },
  {
    version: 'v1.0.25',
    date: '2026-04-25',
    title: 'Installer: .env-Variablennamen an docker-compose angeglichen',
    notes: [],
  },
  {
    version: 'v1.0.24',
    date: '2026-04-25',
    title: 'Wizard-Absturz bei der ersten Passworteingabe behoben',
    notes: [],
  },
  {
    version: 'v1.0.23',
    date: '2026-04-25',
    title: 'Autologin & CI-Tag-Handling im ISO',
    notes: [],
  },
  {
    version: 'v1.0.22',
    date: '2026-04-25',
    title: 'Versionskennung im ISO & SSH-Härtung',
    notes: [
      'Versions-Tag im ISO sichtbar, Boot-Status auf der Konsole, gehärtete SSH-Konfiguration.',
    ],
  },
  {
    version: 'v1.0.21',
    date: '2026-04-25',
    title: 'SSH-Server im ISO + sauberes Login-Banner',
    notes: [],
  },
  {
    version: 'v1.0.20',
    date: '2026-04-24',
    title: 'Bootloader: korrekter initrd-Pfad',
    notes: [],
  },
  {
    version: 'v1.0.19',
    date: '2026-04-24',
    title: 'Bootloader auf robusten Text-Modus reduziert',
    notes: [],
  },
  {
    version: 'v1.0.18',
    date: '2026-04-24',
    title: 'Bootloader-Hook: Pfade korrigiert',
    notes: [],
  },
  { version: 'v1.0.17', date: '2026-04-24', title: 'ausführliche ML-Engine-Dokumentation', notes: [] },
  { version: 'v1.0.16', date: '2026-04-24', title: 'asyncpg-Typing für Interval-Parameter in /api/ml/learned-patterns', notes: [] },
  {
    version: 'v1.0.15',
    date: '2026-04-24',
    title: 'Bootmenü bleibt zuverlässig sichtbar',
    notes: [],
  },
  {
    version: 'v1.0.14',
    date: '2026-04-24',
    title: 'Boot-Splash, Menü & TTY-Stabilität',
    notes: [],
  },
  { version: 'v1.0.13', date: '2026-04-24', title: 'Badge + Drawer für unbekannte Hosts im Dashboard-Header', notes: [] },
  {
    version: 'v1.0.12',
    date: '2026-04-24',
    title: 'Wartungs-Release',
    notes: [],
  },
  {
    version: 'v1.0.11',
    date: '2026-04-24',
    title: 'Wartungs-Release',
    notes: [],
  },
  {
    version: 'v1.0.10',
    date: '2026-04-24',
    title: 'Wartungs-Release',
    notes: [],
  },
  { version: 'v1.0.8', date: '2026-04-23', title: 'iTop-Assets grün markieren (known_networks color + TrustBadge cmdb-Label)', notes: [] },
  { version: 'v1.0.6', date: '2026-04-23', title: 'Management-IP aus managementip_id_friendlyname lesen (TeemIP IPv4Address-Referenz)', notes: [] },
  {
    version: 'v1.0.2',
    date: '2026-04-20',
    title: 'Erstes bootfähiges ISO mit Festplatten-Installer',
    notes: [
      'Bootfähiges Live-ISO, das sich auf eine echte Festplatte installieren lässt.',
    ],
  },
];

/** Eintrag zur laufenden Version finden (toleriert führendes „v"). */
export function changelogFor(version: string | null | undefined): ChangelogEntry | undefined {
  if (!version) return undefined;
  const norm = (s: string) => s.replace(/^v/i, '');
  return CHANGELOG.find(e => norm(e.version) === norm(version));
}
