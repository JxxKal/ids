"""Fail-closed RPC-Allowlist (protocol.md §2.3).

Jede eingehende `rpc` wird gegen eine feste Liste aus (Methode, Pfad-Regex)
geprüft. **Was nicht drinsteht, wird abgelehnt** — es gibt keinen
Wildcard-Zweig, keinen "wenn Methode GET ist, dann eh"-Shortcut und keine
Konfigurationsvariable, die die Liste erweitern könnte.

Zweite Verteidigungslinie ist das Service-JWT mit `role=viewer`
(api_client.py): selbst wenn hier ein Regex zu weit wäre, sind alle
admin-gegateten Router serverseitig unerreichbar.

Triage (PATCH/DELETE feedback) hängt an APP_CONNECT_ALLOW_TRIAGE und ist
per Default AUS. Der Zustand wird im `hello`-Frame über `read_only` und
`capabilities` gemeldet — die App fragt nicht "darf ich?", sie liest die
Capability.
"""
from __future__ import annotations

import logging
import re
from urllib.parse import parse_qsl

log = logging.getLogger(__name__)

_UUID = r"[0-9a-fA-F-]{36}"

# protocol.md §2.3 READ — 1:1 übernommen.
READ_RULES: tuple[tuple[str, str], ...] = (
    ("GET", r"^/api/alerts$"),
    ("GET", rf"^/api/alerts/{_UUID}$"),
    ("GET", rf"^/api/alerts/{_UUID}/pcap$"),
    ("GET", r"^/api/stats/threat-level$"),
    ("GET", r"^/api/hosts$"),
    ("GET", r"^/api/hosts/[^/]+$"),
    ("GET", r"^/api/hosts/[^/]+/connections$"),
    ("GET", r"^/api/hosts/unknown$"),
    ("GET", r"^/api/networks$"),
    ("GET", r"^/api/flows$"),
    ("GET", r"^/api/flows/graph$"),
    ("GET", r"^/api/ml/status$"),
    ("GET", r"^/api/system/stats$"),
    ("GET", r"^/api/system/version$"),
    ("GET", r"^/api/system/feature-flags$"),
    ("GET", r"^/api/auth/me$"),
)

# protocol.md §2.3 TRIAGE — nur aktiv bei APP_CONNECT_ALLOW_TRIAGE=true.
TRIAGE_RULES: tuple[tuple[str, str], ...] = (
    ("PATCH", rf"^/api/alerts/{_UUID}/feedback$"),
    ("DELETE", rf"^/api/alerts/{_UUID}/feedback$"),
)

# Capabilities, die die App aus dem hello-Frame liest (protocol.md §8).
BASE_CAPABILITIES: tuple[str, ...] = ("pcap", "flows", "ml")

# Pfade, die streamen dürfen (protocol.md §2.5). Alles andere geht durch
# den normalen rpc_result-Pfad mit 4-MiB-Deckel.
_STREAM_RULE = re.compile(rf"^/api/alerts/{_UUID}/pcap$")

# Zeichen, die in einem Pfad nichts verloren haben. Ein Pfad mit Steuer-
# zeichen oder Whitespace ist entweder ein Bug oder ein Request-Smuggling-
# Versuch — in beiden Fällen: raus.
_FORBIDDEN = re.compile(r"[\x00-\x20\x7f\\]")


class RejectedPath(Exception):
    """Pfad nicht in der Allowlist bzw. syntaktisch unzulässig."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def normalize(path: str) -> tuple[str, dict[str, str]]:
    """Trennt einen evtl. angehängten Query-String ab und validiert die
    Pfad-Syntax. Liefert (pfad_ohne_query, extra_query_params).

    Der Proxy schickt `query` laut §2.1 separat; ein Pfad mit `?` ist
    trotzdem tolerierbar, solange die Allowlist-Prüfung auf dem
    abgetrennten Pfad-Teil passiert — genau das tun wir hier.
    """
    raw = path or ""
    if not raw.startswith("/"):
        raise RejectedPath("bad_path", "Pfad muss mit / beginnen")
    if _FORBIDDEN.search(raw):
        raise RejectedPath("bad_path", "Pfad enthält unzulässige Zeichen")
    # Fragment gibt es serverseitig nicht — wenn eins mitkommt, ist der
    # Request nicht das, was er vorgibt zu sein.
    if "#" in raw:
        raise RejectedPath("bad_path", "Pfad enthält Fragment")

    head, _, qs = raw.partition("?")
    lowered = head.lower()
    # Traversal in jeder Schreibweise, die die api unterschiedlich
    # normalisieren könnte.
    if ".." in head or "%2e%2e" in lowered or "%2f" in lowered:
        raise RejectedPath("bad_path", "Pfad enthält Traversal-Sequenz")

    extra = {k: v for k, v in parse_qsl(qs, keep_blank_values=True)} if qs else {}
    return head, extra


class Allowlist:
    """Kompilierte Allowlist. Eine Instanz pro Prozess, `allow_triage`
    kommt aus der env und ändert sich zur Laufzeit nicht."""

    def __init__(self, allow_triage: bool = False) -> None:
        self.allow_triage = bool(allow_triage)
        self._read = tuple((m, re.compile(p)) for m, p in READ_RULES)
        self._triage = tuple((m, re.compile(p)) for m, p in TRIAGE_RULES)

    # ── Introspektion fürs hello-Frame ───────────────────────────────────

    @property
    def read_only(self) -> bool:
        return not self.allow_triage

    def capabilities(self) -> list[str]:
        caps = list(BASE_CAPABILITIES)
        if self.allow_triage:
            caps.append("triage")
        return caps

    # ── Prüfung ──────────────────────────────────────────────────────────

    def is_allowed(self, method: str, path: str) -> bool:
        """Reine Prädikat-Form ohne Logging — für Tests und interne
        Vorprüfungen. `path` muss bereits query-frei sein."""
        m = (method or "").upper()
        for rule_method, rx in self._read:
            if m == rule_method and rx.match(path):
                return True
        if self.allow_triage:
            for rule_method, rx in self._triage:
                if m == rule_method and rx.match(path):
                    return True
        return False

    def check(self, method: str, path: str) -> tuple[str, dict[str, str]]:
        """Validiert + normalisiert. Wirft RejectedPath, wenn der Request
        nicht durchgelassen wird — jede Ablehnung wird MIT dem Pfad
        geloggt, damit ein Operator im Log sieht, was die App wollte.

        Liefert (normalisierter_pfad, extra_query_aus_dem_pfad).
        """
        m = (method or "").upper()
        try:
            clean, extra = normalize(path)
        except RejectedPath as exc:
            log.warning(
                "RPC abgelehnt (%s): method=%s path=%r — %s",
                exc.reason, m, path, exc.detail,
            )
            raise

        if not self.is_allowed(m, clean):
            # Diagnose-Hilfe: Triage ist der häufigste "warum geht das
            # nicht"-Fall, deshalb explizit unterscheiden.
            if not self.allow_triage and any(
                m == rm and rx.match(clean) for rm, rx in self._triage
            ):
                detail = "Triage deaktiviert (APP_CONNECT_ALLOW_TRIAGE=false)"
                reason = "read_only"
            else:
                detail = "kein Allowlist-Eintrag"
                reason = "not_allowed"
            log.warning("RPC abgelehnt (%s): method=%s path=%r — %s",
                        reason, m, clean, detail)
            raise RejectedPath(reason, detail)

        return clean, extra

    @staticmethod
    def is_streamable(path: str) -> bool:
        """§2.5 — nur der PCAP-Pfad darf den rpc_chunk-Kanal benutzen."""
        return bool(_STREAM_RULE.match(path))
