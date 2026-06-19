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
    date: '2026-06-12',
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
    date: '2026-04-29',
    title: 'System Details',
    notes: [
      'Neuer Tab „System Details" mit profilbewusstem Container-Status (prod vs. lab).',
    ],
  },
  {
    version: 'v2.5.29',
    date: '2026-04-29',
    title: 'Traffic-Generator offline',
    notes: [
      'Das Test-Feature (synthetischer Verkehr) ist jetzt auch ohne Internet im Produktiv-Bundle nutzbar.',
    ],
  },
  {
    version: 'v2.5.28',
    date: '2026-04-29',
    title: 'Reboot-Härtung',
    notes: [
      'Reboot-Recovery sowie Schutz gegen versehentlichen Ctrl-Alt-Del-Neustart über angeschlossene IP-KVMs.',
    ],
  },
];

/** Eintrag zur laufenden Version finden (toleriert führendes „v"). */
export function changelogFor(version: string | null | undefined): ChangelogEntry | undefined {
  if (!version) return undefined;
  const norm = (s: string) => s.replace(/^v/i, '');
  return CHANGELOG.find(e => norm(e.version) === norm(version));
}
