// Hot-pluggable i18n-Bundles für Features die später dazukommen, ohne dass
// wir die großen de.json/en.json patchen müssen. addResourceBundle merged
// in die bestehenden Translation-Keys; bei Konflikten gewinnt der bestehende
// Eintrag (deepMerge=true, overwrite=false).
//
// Sobald die Strings stabil sind, dürfen sie in die Locale-Hauptdateien
// rüberwandern und der Eintrag hier wieder raus — das ist nur ein
// Übergangsmechanismus.

import i18n from './index';

const DE = {
  common: {
    empty: 'leer',
  },
  sidebar: {
    reports: 'Wochenbericht',
  },
  tabs: {
    reports: 'Wochenbericht',
    gettingStarted: 'Erste Schritte',
  },
  topbar: {
    tap: {
      liveTitle:    '{{name}} · letzter Kontakt vor {{age}} (online)',
      staleTitle:   '{{name}} · letzter Kontakt vor {{age}} (Verbindung wackelt)',
      offlineTitle: '{{name}} · letzter Kontakt vor {{age}} (offline)',
      never:        '{{name}} · noch nie kontaktiert seit Pairing',
    },
  },
  weeklyReport: {
    title: 'Wochenbericht',
    prev: 'Vorherige Woche',
    next: 'Nächste Woche',
    current: 'Aktuelle Woche springen',
    currentLabel: 'Aktuell',
    print: 'Drucken / als PDF speichern (Browser-Druck)',
    printLabel: 'Drucken',
    downloadJson: 'Vollständigen Bericht als JSON herunterladen',
    downloadCsv: 'Bericht als CSV-Bundle (ZIP) für Excel/Power-BI',
    historyLabel: 'Archiv',
    historyTitle: 'Archivierte Wochen anzeigen',
    historyEmpty: 'Noch keine archivierten Wochen vorhanden.',
    archivedHint: 'Archiv-Snapshot — eingefroren am ',
    summary: {
      title: 'Zusammenfassung',
      totalLabel: 'Alerts gesamt',
    },
    detection: {
      title: 'Detection',
      dailyTitle: 'Alerts pro Tag (gestapelt nach Severity)',
      topRulesTitle: 'Top-10 Regeln',
      topSourcesTitle: 'Top-10 Source-IPs',
      topExternalTitle: 'Top-10 externe Ziele',
      noExternal: 'Keine Public-IP-Ziele in dieser Woche.',
    },
    ops: {
      title: 'Betrieb & Infrastruktur',
      tapsTitle: 'Remote-Taps',
      noTaps: 'Keine Taps registriert.',
      mlTitle: 'ML/Tuning-Aktivität',
      fpMarked: 'FP-Markierungen',
      tpMarked: 'TP-Markierungen',
      tunerCycles: 'Rule-Tuner-Cycles',
      suricataTitle: 'Top-5 Suricata-SIDs',
    },
    boundary: {
      title: 'OT-Boundary Breaches',
      totalLabel: 'Aktive Breaches',
      whitelistedLabel: 'Whitelisted (suppressed)',
      none: 'Keine Egress-Boundary-Breaches in dieser Woche.',
      topTalkersTitle: 'Top-Talker → unbekannte Netze',
      topPairsTitle: 'Top-Verbindungen Source → Ziel (unbekannt)',
      priorityHint: 'P0 = vollständig unbekannt · P1 = bekannt → unbekannt (C2/Exfil) · P2 = Rogue/Routing · P3 = Inventory-Lücke',
    },
    audit: {
      title: 'Audit',
      activeUsersTitle: 'Aktive User (in der Woche eingeloggt)',
      noUsers: 'Keine Logins in dieser Woche.',
      changesTitle: 'Konfigurations-Änderungen',
      whitelistAdds: 'Whitelist-Einträge hinzugefügt',
    },
  },
  help: {
    dashboard: {
      topbarTaps: 'Heartbeat aller gepairten Remote-Sniffer (Taps). Grün = letzter Kontakt < 90 s, Gelb = 90 s–5 min (Verbindung wackelt), Rot = > 5 min (offline). Hover zeigt das genaue Alter.',
    },
  },
  settings: {
    items: {
      geoip: 'GeoIP-Datenbanken',
    },
    geoip: {
      title: 'GeoIP-Datenbanken',
      intro: 'Der enrichment-service nutzt zwei <code>.mmdb</code>-Dateien (City + ASN) für Land/ASN-Lookup. Frei und ohne Account: <a>DB-IP Lite</a> (monatliches Update). Auch MaxMind GeoLite2 funktioniert. System-Updates über das Update-ZIP enthalten automatisch eine aktuelle Version — der manuelle Upload hier ist für Offline-Maschinen oder Custom-Datenbanken.',
      statusTitle: 'Aktueller Stand',
      uploadTitle: 'Hochladen',
      uploadHint: 'Beide Dateien sind optional — du kannst auch nur eine ersetzen. Akzeptiert .mmdb roh oder .gz. Nach erfolgreichem Upload wird der enrichment-service automatisch neu geladen.',
      statusOk: 'geladen',
      statusInvalid: 'Datei vorhanden, aber kein gültiger MaxMind-Marker',
      statusMissing: 'fehlt — kein GeoIP-Lookup möglich',
      mtimeAge: 'aktualisiert vor {{age}}',
      path: 'Pfad: {{path}}',
      optional: '(optional)',
      uploadBtn: 'Hochladen + Reload',
      uploading: 'Lade hoch …',
      restartHint: 'enrichment-service wird neu gestartet — kann ein paar Sekunden dauern.',
    },
  },
};

const EN = {
  common: {
    empty: 'empty',
  },
  sidebar: {
    reports: 'Weekly Report',
  },
  tabs: {
    reports: 'Weekly report',
    gettingStarted: 'Getting started',
  },
  topbar: {
    tap: {
      liveTitle:    '{{name}} · last contact {{age}} ago (online)',
      staleTitle:   '{{name}} · last contact {{age}} ago (connection unstable)',
      offlineTitle: '{{name}} · last contact {{age}} ago (offline)',
      never:        '{{name}} · no contact since pairing',
    },
  },
  weeklyReport: {
    title: 'Weekly report',
    prev: 'Previous week',
    next: 'Next week',
    current: 'Jump to current week',
    currentLabel: 'Current',
    print: 'Print / save as PDF (browser print)',
    printLabel: 'Print',
    downloadJson: 'Download full report as JSON',
    downloadCsv: 'Download report as CSV bundle (ZIP) for Excel/Power-BI',
    historyLabel: 'Archive',
    historyTitle: 'Show archived weeks',
    historyEmpty: 'No archived weeks yet.',
    archivedHint: 'Archived snapshot — frozen at ',
    summary: {
      title: 'Summary',
      totalLabel: 'Alerts total',
    },
    detection: {
      title: 'Detection',
      dailyTitle: 'Alerts per day (stacked by severity)',
      topRulesTitle: 'Top-10 rules',
      topSourcesTitle: 'Top-10 source IPs',
      topExternalTitle: 'Top-10 external destinations',
      noExternal: 'No public-IP destinations this week.',
    },
    ops: {
      title: 'Operations & infrastructure',
      tapsTitle: 'Remote taps',
      noTaps: 'No taps registered.',
      mlTitle: 'ML/tuning activity',
      fpMarked: 'FP markings',
      tpMarked: 'TP markings',
      tunerCycles: 'Rule-tuner cycles',
      suricataTitle: 'Top-5 Suricata SIDs',
    },
    boundary: {
      title: 'OT-Boundary breaches',
      totalLabel: 'Active breaches',
      whitelistedLabel: 'Whitelisted (suppressed)',
      none: 'No egress-boundary breaches this week.',
      topTalkersTitle: 'Top talkers → unknown networks',
      topPairsTitle: 'Top connections source → unknown destination',
      priorityHint: 'P0 = fully unknown · P1 = known → unknown (C2/exfil) · P2 = rogue/routing · P3 = inventory gap',
    },
    audit: {
      title: 'Audit',
      activeUsersTitle: 'Active users (signed in this week)',
      noUsers: 'No logins this week.',
      changesTitle: 'Configuration changes',
      whitelistAdds: 'Whitelist entries added',
    },
  },
  help: {
    dashboard: {
      topbarTaps: 'Heartbeat of all paired remote sniffers (taps). Green = last contact < 90 s, amber = 90 s–5 min (link unstable), red = > 5 min (offline). Hover for the exact age.',
    },
  },
  settings: {
    items: {
      geoip: 'GeoIP databases',
    },
    geoip: {
      title: 'GeoIP databases',
      intro: 'The enrichment-service uses two <code>.mmdb</code> files (City + ASN) for country/ASN lookups. Free without account: <a>DB-IP Lite</a> (monthly update). MaxMind GeoLite2 also works. System-Update ZIPs ship a fresh copy automatically — this manual upload is for air-gapped hosts or custom databases.',
      statusTitle: 'Current status',
      uploadTitle: 'Upload',
      uploadHint: 'Both files are optional — you can replace just one. Accepts raw .mmdb or .gz. After a successful upload the enrichment-service is reloaded automatically.',
      statusOk: 'loaded',
      statusInvalid: 'file present, but no valid MaxMind marker',
      statusMissing: 'missing — no GeoIP lookup',
      mtimeAge: 'updated {{age}} ago',
      path: 'Path: {{path}}',
      optional: '(optional)',
      uploadBtn: 'Upload + reload',
      uploading: 'Uploading …',
      restartHint: 'enrichment-service is being restarted — may take a few seconds.',
    },
  },
};

// addResourceBundle(lng, namespace, resources, deep, overwrite). overwrite=false
// schützt bereits in de.json/en.json gepflegte Keys — Extras füllen nur Lücken.
i18n.addResourceBundle('de', 'translation', DE, true, false);
i18n.addResourceBundle('en', 'translation', EN, true, false);
