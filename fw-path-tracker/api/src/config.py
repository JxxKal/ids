"""Laufzeit-Konfiguration aus Environment-Variablen.

Nur Infrastruktur-Secrets leben in Env (JWT_SECRET, POSTGRES_PASSWORD) —
alles Fachliche (FMG-, iTop-, DNS-Zugänge) liegt in system_config (DB).
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


def _env(name: str, default: str | None = None) -> str:
    val = os.environ.get(name, default)
    if val is None:
        raise RuntimeError(f"Environment-Variable {name} ist nicht gesetzt.")
    return val


@dataclass
class Config:
    db_host: str = field(default_factory=lambda: os.environ.get("DB_HOST", "db"))
    db_port: int = field(default_factory=lambda: int(os.environ.get("DB_PORT", "5432")))
    db_name: str = field(default_factory=lambda: os.environ.get("DB_NAME", "fwtracker"))
    db_user: str = field(default_factory=lambda: os.environ.get("DB_USER", "fwtracker"))
    db_password: str = field(default_factory=lambda: _env("POSTGRES_PASSWORD"))
    secret_key: str = field(default_factory=lambda: _env("JWT_SECRET"))
    # Initial-Passwort für den beim ersten Start angelegten admin-User.
    admin_bootstrap_password: str = field(
        default_factory=lambda: os.environ.get("ADMIN_PASSWORD", "admin")
    )
    migrations_dir: str = field(
        default_factory=lambda: os.environ.get("MIGRATIONS_DIR", "/migrations")
    )
    # Record-Modus für den FixtureTransport (Lab-Mitschnitt für Tests/Demo).
    record_fixtures: bool = field(
        default_factory=lambda: os.environ.get("FMG_RECORD_FIXTURES", "") == "1"
    )
    fixture_dir: str = field(
        default_factory=lambda: os.environ.get("FMG_FIXTURE_DIR", "/fixtures")
    )

    @property
    def dsn(self) -> str:
        return (
            f"postgresql://{self.db_user}:{self.db_password}"
            f"@{self.db_host}:{self.db_port}/{self.db_name}"
        )
