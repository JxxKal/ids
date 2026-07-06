import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    postgres_dsn:        str
    catalog_dir:         str
    # Cadence + Beobachtungsfenster.
    detect_interval_s:   float
    detect_window_days:  int
    # Match-/Confidence-Schwellen.
    min_confidence:      float
    # OUI-Bonus auf die confidence, wenn ein mac_oui-Präfix der Rolle die
    # Mode-MAC des Hosts trifft. Bewusst klein — die Port-Profile sind das
    # Hauptsignal, OUI nur Verstärker (eine geklonte MAC soll keine Rolle
    # allein tragen).
    oui_confidence_bonus: float
    # Schwellwert für "long_lived": ein Host gilt als langlebiger Responder,
    # wenn der älteste servierte Flow >= long_lived_min_days zurückreicht.
    long_lived_min_days: float
    # Aging: auto-Rollen eines Hosts, der seit >= role_stale_days nicht mehr als
    # Responder auftaucht (dekommissioniert / IP neu vergeben), werden entfernt.
    # manual-Locks + Suppress bleiben. 0 = Aging deaktiviert.
    role_stale_days:     float

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            postgres_dsn=os.environ.get(
                "POSTGRES_DSN",
                "postgresql://ids:ids-change-me@timescaledb:5432/ids",
            ),
            catalog_dir=os.environ.get("ROLE_CATALOG_DIR", "/host-roles"),
            detect_interval_s=float(os.environ.get("DETECT_INTERVAL_S", "1800")),
            detect_window_days=int(os.environ.get("DETECT_WINDOW_DAYS", "7")),
            min_confidence=float(os.environ.get("ROLE_MIN_CONFIDENCE", "0.6")),
            oui_confidence_bonus=float(os.environ.get("ROLE_OUI_BONUS", "0.05")),
            long_lived_min_days=float(os.environ.get("ROLE_LONG_LIVED_DAYS", "3")),
            role_stale_days=float(os.environ.get("ROLE_STALE_DAYS", "30")),
        )
