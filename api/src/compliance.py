"""MITRE-ATT&CK → Compliance-Framework Mapping.

Eingesetzt vom Wochenbericht + Pattern-Export-Evidence — gibt für eine
getestete MITRE-Technique eine Liste von relevanten Compliance-Controls
(NIS-2 / ISO 27001 / BSI IT-Grundschutz) zurück.

Hinweis: das Mapping ist BEWUSST eine eingebettete Konstante (kein
extern bearbeitbares File). Der Customer kriegt damit eine Cyjan-curated
Default-Liste. Customer-spezifische Erweiterungen (eigene Compliance-
Frameworks) können später als Override-YAML im /sig-rules-Volume nach-
gezogen werden — V2-Feature, jetzt nicht.

Quellen:
- MITRE ATT&CK Enterprise + ICS Matrix (attack.mitre.org)
- NIS-2 Directive (EU) 2022/2555, Art. 21 Security Requirements
- ISO/IEC 27001:2022 Annex A Controls
- BSI IT-Grundschutz-Kompendium 2024 (APP/ORP/NET/CON-Bausteine)
"""
from __future__ import annotations

from typing import Any


# Format: technique_id → [(framework, control_id, control_name), …]
# Mehrere Frameworks pro Technique sind die Regel — Compliance-Reports
# brauchen den Cross-Map damit eine Pen-Test-Coverage gegen MEHRERE
# Standards auswertbar wird.
COMPLIANCE_MAPPING: dict[str, list[tuple[str, str, str]]] = {

    # ───── Initial Access / Reconnaissance ──────────────────────────────
    "T1018": [   # Remote System Discovery
        ("NIS-2",     "Art-21(2)(e)",  "Procurement, development & maintenance of network systems"),
        ("ISO-27001", "A.8.16",        "Monitoring activities"),
        ("BSI",       "DER.1.A4",      "Erkennung von Angriffen auf Netz-Komponenten"),
    ],
    "T1046": [   # Network Service Discovery
        ("NIS-2",     "Art-21(2)(e)",  "Network monitoring"),
        ("ISO-27001", "A.8.16",        "Monitoring activities"),
        ("BSI",       "DER.1.A4",      "Erkennung von Angriffen auf Netz-Komponenten"),
    ],
    "T1187": [   # Forced Authentication
        ("NIS-2",     "Art-21(2)(i)",  "Identity & access management"),
        ("ISO-27001", "A.5.17",        "Authentication information"),
        ("BSI",       "ORP.4.A23",     "Regelung des Passwortgebrauchs"),
    ],
    "T1210": [   # Exploitation of Remote Services (lateral via SMB/etc.)
        ("NIS-2",     "Art-21(2)(d)",  "Supply chain security"),
        ("ISO-27001", "A.8.8",         "Management of technical vulnerabilities"),
        ("BSI",       "NET.1.1.A14",   "Schutz vor Schadcode in Netzen"),
    ],

    # ───── Credential Access ─────────────────────────────────────────────
    "T1110":     [
        ("NIS-2",     "Art-21(2)(i)",  "Strong authentication"),
        ("ISO-27001", "A.8.5",         "Secure authentication"),
        ("BSI",       "ORP.4.A22",     "Schutz vor Brute-Force-Angriffen"),
    ],
    "T1110.003": [   # Password Spraying
        ("NIS-2",     "Art-21(2)(i)",  "Identity & access management"),
        ("ISO-27001", "A.8.5",         "Secure authentication"),
        ("BSI",       "ORP.4.A22",     "Schutz vor Brute-Force-Angriffen"),
    ],
    "T1558":     [   # Steal or Forge Kerberos Tickets
        ("NIS-2",     "Art-21(2)(i)",  "Cryptographic controls"),
        ("ISO-27001", "A.8.24",        "Use of cryptography"),
        ("BSI",       "APP.2.2.A8",    "Sichere Kerberos-Konfiguration"),
    ],
    "T1558.003": [   # Kerberoasting
        ("NIS-2",     "Art-21(2)(i)",  "Identity & access management"),
        ("ISO-27001", "A.8.5",         "Secure authentication"),
        ("BSI",       "APP.2.2.A18",   "AS-REP-Roasting-Schutz"),
    ],
    "T1558.004": [   # AS-REP Roasting
        ("NIS-2",     "Art-21(2)(i)",  "Identity & access management — preauth required"),
        ("ISO-27001", "A.8.5",         "Secure authentication"),
        ("BSI",       "APP.2.2.A18",   "AS-REP-Roasting-Schutz"),
    ],
    "T1557.001": [   # LLMNR/NBT-NS Poisoning + SMB Relay
        ("NIS-2",     "Art-21(2)(g)",  "Cybersecurity in business continuity"),
        ("ISO-27001", "A.8.16",        "Monitoring activities"),
        ("BSI",       "NET.1.1.A8",    "Sichere Netzkonfig"),
    ],

    # ───── Command and Control / Exfil ──────────────────────────────────
    "T1041":     [   # Exfiltration over C2 Channel
        ("NIS-2",     "Art-21(2)(j)",  "Asset management / DLP"),
        ("ISO-27001", "A.8.12",        "Data leakage prevention"),
        ("BSI",       "DER.2.1.A6",    "Datenexfiltration-Erkennung"),
    ],
    "T1071.001": [   # Web Protocols (C2 via HTTP/S)
        ("NIS-2",     "Art-21(2)(g)",  "Network security monitoring"),
        ("ISO-27001", "A.8.16",        "Monitoring activities"),
        ("BSI",       "DER.1.A4",      "Erkennung von Angriffen — HTTP/S"),
    ],

    # ───── ICS / OT (Siemens, GE iFix) ──────────────────────────────────
    "T0842": [   # ICS Network Sniffing
        ("NIS-2",     "Art-21(2)(g)",  "OT network monitoring"),
        ("ISO-27001", "A.8.16",        "Monitoring activities (OT scope)"),
        ("BSI",       "IND.1.A12",     "Netzwerk-Monitoring im IND-Segment"),
    ],
    "T0846": [   # Remote System Discovery (ICS)
        ("NIS-2",     "Art-21(2)(c)",  "Vulnerability management"),
        ("NIS-2",     "Art-21(2)(g)",  "OT network monitoring"),
        ("ISO-27001", "A.8.32",        "Change management"),
        ("BSI",       "IND.2.2.A8",    "PLC Discovery erkennen"),
    ],
    "T0855": [   # Unauthorized Command Message (Modbus FC1/etc.)
        ("NIS-2",     "Art-21(2)(c)",  "Vulnerability management for OT"),
        ("ISO-27001", "A.8.7",         "Protection against malware (OT)"),
        ("BSI",       "IND.2.2.A11",   "Modbus-Befehlsfilterung"),
    ],
    "T0814": [   # Denial of Service (ICS)
        ("NIS-2",     "Art-21(2)(c)",  "Service availability"),
        ("ISO-27001", "A.8.6",         "Capacity management"),
        ("BSI",       "IND.2.2.A14",   "DoS-Schutz im ICS-Segment"),
    ],
    "T0859": [   # Valid Accounts (ICS, e.g. default Modbus auth bypass)
        ("NIS-2",     "Art-21(2)(i)",  "Identity & access management"),
        ("ISO-27001", "A.5.16",        "Identity management"),
        ("BSI",       "IND.2.1.A7",    "Authentisierung im ICS"),
    ],
    "T0860": [   # Wireless Compromise (BACnet/MQTT etc.)
        ("NIS-2",     "Art-21(2)(g)",  "OT communications security"),
        ("ISO-27001", "A.8.20",        "Network security"),
        ("BSI",       "IND.2.2.A4",    "Funkstrecken im IND-Bereich"),
    ],

    # ───── Discovery / Recon (Enterprise) ───────────────────────────────
    "T1018":     [   # Remote System Discovery
        ("NIS-2",     "Art-21(2)(e)",  "Network monitoring"),
        ("ISO-27001", "A.8.16",        "Monitoring activities"),
        ("BSI",       "DER.1.A4",      "Erkennung von Angriffen — Discovery"),
    ],
    "T1087":     [   # Account Discovery
        ("NIS-2",     "Art-21(2)(i)",  "Account enumeration prevention"),
        ("ISO-27001", "A.5.18",        "Access rights"),
        ("BSI",       "ORP.4.A20",     "Schutz vor unerlaubter Konten-Enumeration"),
    ],

    # ───── Crypto / Confidentiality (NIS-2 h) ────────────────────────────
    "T1040":     [   # Network Sniffing — adversary capturing plaintext
        ("NIS-2",     "Art-21(2)(h)",  "Cryptography & encryption"),
        ("ISO-27001", "A.8.24",        "Use of cryptography"),
        ("BSI",       "CON.1.A1",      "Auswahl kryptografischer Verfahren"),
    ],
    "T1573":     [   # Encrypted Channel (Cryptography baseline)
        ("NIS-2",     "Art-21(2)(h)",  "Cryptography & encryption"),
        ("ISO-27001", "A.8.24",        "Use of cryptography"),
        ("BSI",       "CON.1.A2",      "Sichere Konfiguration der Verfahren"),
    ],
    "T1573.002": [   # Asymmetric Cryptography (weak TLS/SSH)
        ("NIS-2",     "Art-21(2)(h)",  "Strong cryptography enforcement"),
        ("ISO-27001", "A.8.24",        "Use of cryptography"),
        ("BSI",       "NET.3.3.A4",    "Sichere TLS-Konfiguration"),
    ],
    "T1078":     [   # Valid Accounts (incl. default/anonymous bind)
        ("NIS-2",     "Art-21(2)(i)",  "Identity & access management"),
        ("ISO-27001", "A.5.16",        "Identity management"),
        ("BSI",       "ORP.4.A7",      "Vermeidung anonymer/ungeschützter Konten"),
    ],

    # ───── Lateral Movement / Remote Services ────────────────────────────
    "T1021":     [   # Remote Services baseline
        ("NIS-2",     "Art-21(2)(j)",  "Secure remote access"),
        ("ISO-27001", "A.8.21",        "Security of network services"),
        ("BSI",       "OPS.1.2.5.A8",  "Sichere Fernzugriffe"),
    ],
    "T1021.001": [   # Remote Desktop Protocol
        ("NIS-2",     "Art-21(2)(j)",  "RDP with MFA / NLA required"),
        ("ISO-27001", "A.8.21",        "Security of network services"),
        ("BSI",       "OPS.1.2.5.A8",  "RDP-Härtung (NLA, MFA)"),
    ],
    "T1021.006": [   # WinRM
        ("NIS-2",     "Art-21(2)(h)",  "Encrypted management channels"),
        ("ISO-27001", "A.8.24",        "Use of cryptography"),
        ("BSI",       "SYS.1.2.3.A8",  "WinRM nur über HTTPS"),
    ],

    # ───── Command & Control / Exfil ─────────────────────────────────────
    "T1071.004": [   # DNS C2 / DNS tunneling
        ("NIS-2",     "Art-21(2)(g)",  "Network security monitoring"),
        ("ISO-27001", "A.8.16",        "Monitoring activities"),
        ("BSI",       "DER.2.1.A7",    "DNS-Tunneling-Erkennung"),
    ],

    # ───── Brute Force / Spraying  ───────────────────────────────────────
    "T1110.001": [   # Password Guessing
        ("NIS-2",     "Art-21(2)(i)",  "Authentication strength"),
        ("ISO-27001", "A.8.5",         "Secure authentication"),
        ("BSI",       "ORP.4.A22",     "Schutz vor Brute-Force-Angriffen"),
    ],
}


def map_technique(technique_id: str) -> list[dict[str, str]]:
    """Liefert die Compliance-Controls für eine MITRE-Technique-ID.
    Fällt auf die Parent-Technique zurück (z.B. T1558.004 → T1558).

    Returns Liste von Dicts: {framework, control_id, control_name}.
    Leer wenn keine Mapping bekannt."""
    out = list(COMPLIANCE_MAPPING.get(technique_id, []))
    # Sub-Technique → Parent-Fallback (zusätzlich, nicht statt)
    if "." in technique_id:
        parent = technique_id.split(".", 1)[0]
        for entry in COMPLIANCE_MAPPING.get(parent, []):
            if entry not in out:
                out.append(entry)
    return [{"framework": f, "control_id": c, "control_name": n}
            for (f, c, n) in out]


def framework_coverage(techniques: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Aggregiert über alle getesteten Techniques: pro Framework eine Liste
    von controls_tested (mind. ein Test) + controls_detected (mind. ein
    detected=true Run im Auswertungs-Fenster).

    `techniques` Format wie aus _collect_mitre_coverage:
       {"technique_id", "run_count", "detection_count", "scenarios": [...]}
    """
    by_fw: dict[str, dict[str, dict]] = {}
    for t in techniques:
        tid = t.get("technique_id")
        if not tid:
            continue
        run_count = int(t.get("run_count") or 0)
        det_count = int(t.get("detection_count") or 0)
        for c in map_technique(tid):
            fw = c["framework"]
            ctrl_id = c["control_id"]
            slot = by_fw.setdefault(fw, {})
            agg  = slot.setdefault(ctrl_id, {
                "control_id":     ctrl_id,
                "control_name":   c["control_name"],
                "technique_ids":  [],
                "run_count":      0,
                "detection_count": 0,
            })
            if tid not in agg["technique_ids"]:
                agg["technique_ids"].append(tid)
            agg["run_count"]       += run_count
            agg["detection_count"] += det_count

    # Pretty-Print: pro Framework Liste der Controls sortiert
    out: dict[str, dict[str, Any]] = {}
    for fw, controls in by_fw.items():
        ctrl_list = sorted(controls.values(), key=lambda c: c["control_id"])
        out[fw] = {
            "controls_tested":   len(ctrl_list),
            "controls_detected": sum(1 for c in ctrl_list if c["detection_count"] > 0),
            "controls":          ctrl_list,
        }
    return out
