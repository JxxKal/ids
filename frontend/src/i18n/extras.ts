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
};

// addResourceBundle(lng, namespace, resources, deep, overwrite). overwrite=false
// schützt bereits in de.json/en.json gepflegte Keys — Extras füllen nur Lücken.
i18n.addResourceBundle('de', 'translation', DE, true, false);
i18n.addResourceBundle('en', 'translation', EN, true, false);
