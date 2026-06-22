"""
Loader für den Host-Rollen-Katalog.

Die Rollen-Definitionen liegen als YAML im Repo unter
`signature-engine/rules/host-roles/*.yml` (Schema eingefroren in
docs/contracts/host-roles.md) und werden im api-Container als Read-only-Mount
zur Verfügung gestellt. Pfad via env `ROLE_CATALOG_DIR`; der Default deckt sich
mit dem `SIG_BUILTIN_DIR`-Default aus sig_rules.py.

Für die API brauchen wir nur die für die GUI relevanten Felder
(`id`, `label`, `category`) — die Match-Logik (`match`, `mac_oui`, …) wertet
allein der host-role-detector aus.

Der Loader ist bewusst robust: fehlendes Verzeichnis, kaputtes YAML oder
einzelne defekte Einträge führen nie zu einem 500er, sondern werden geloggt
und übersprungen (leere Liste im schlimmsten Fall).
"""
from __future__ import annotations

import logging
import os
from pathlib import Path

import yaml

log = logging.getLogger(__name__)

# Default deckt sich mit SIG_BUILTIN_DIR (sig_rules.py) — im Container liegt
# das Repo unter /opt/ids, der Katalog also unter rules/host-roles.
CATALOG_DIR = Path(
    os.getenv("ROLE_CATALOG_DIR", "/opt/ids/signature-engine/rules/host-roles")
)


def load_catalog() -> list[dict]:
    """Liest alle Katalog-YAMLs und liefert die GUI-Felder pro Rolle.

    Rückgabe: Liste von ``{"id", "label", "category"}``. Bei fehlendem
    Verzeichnis oder reinen Lesefehlern: ``[]``.
    """
    if not CATALOG_DIR.is_dir():
        log.warning("Rollen-Katalog-Verzeichnis nicht gefunden: %s", CATALOG_DIR)
        return []

    out: list[dict] = []
    seen: set[str] = set()
    for path in sorted(CATALOG_DIR.glob("*.yml")):
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            log.warning("Katalog-Datei %s nicht lesbar: %s", path.name, exc)
            continue

        # Pro Datei kann eine Liste von Rollen oder eine einzelne Rolle stehen.
        entries = raw if isinstance(raw, list) else [raw]
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            role_id = entry.get("id")
            if not role_id or role_id in seen:
                # Ohne id ist die Rolle nicht referenzierbar; Duplikate
                # (z.B. id in zwei Dateien) nur einmal aufnehmen.
                continue
            seen.add(role_id)
            out.append({
                "id":       role_id,
                "label":    entry.get("label") or role_id,
                "category": entry.get("category"),
            })

    return out
