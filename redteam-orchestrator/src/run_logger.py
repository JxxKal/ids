"""Schreibt Scenario-Run-Ergebnisse + Scenario-Registry in TimescaleDB.

Tabellen (Migration 021):
  - redteam_scenarios (Registry, eine Row pro Scenario-YAML)
  - redteam_results   (Hypertable, eine Row pro Run)

Warum getrennt von redteam_audit_log:
  audit_log = Roh-MCP-Trail (jeder Tool-Aufruf, allowed/rejected, freie JSONB).
  redteam_results = strukturierte Run-Daten für Aggregate (MITRE-Coverage,
                    Weekly-Report, TPR-Trends, Detection-Gap-Erkennung).

Beide werden parallel geschrieben — audit_log für Forensics, redteam_results
für Analyse. Fail-silent: Schreibfehler crashen NIE den eigentlichen Run.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

import yaml

from db import get_pool

log = logging.getLogger(__name__)


def _yaml_sha256(scenario: dict[str, Any]) -> str:
    """Stable Hash der YAML-Darstellung. sort_keys=False weil das auch
    der save_scenario-Pfad macht — sonst Drift bei jedem Re-Save."""
    text = yaml.safe_dump(scenario, sort_keys=False)
    return hashlib.sha256(text.encode()).hexdigest()


async def register_scenario(scenario: dict[str, Any]) -> None:
    """Upsert in redteam_scenarios. Aufruf nach save_scenario (KI via MCP)
    und nach seed_builtin_templates (Image-Startup).

    yaml_sha256 wird beim Drift-Vergleich genutzt (Migration-Doc): wenn der
    Hash sich ändert, wurde das Scenario re-curated."""
    pool = get_pool()
    if pool is None:
        return
    sid = scenario.get("id")
    if not sid:
        return

    yaml_text = yaml.safe_dump(scenario, sort_keys=False)
    sha = hashlib.sha256(yaml_text.encode()).hexdigest()
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO redteam_scenarios
                    (scenario_id, rule_id, yaml_source, yaml_sha256, description, enabled)
                VALUES ($1, $2, $3, $4, $5, true)
                ON CONFLICT (scenario_id) DO UPDATE SET
                    rule_id     = EXCLUDED.rule_id,
                    yaml_source = EXCLUDED.yaml_source,
                    yaml_sha256 = EXCLUDED.yaml_sha256,
                    description = EXCLUDED.description,
                    enabled     = true,
                    updated_at  = now()
                """,
                sid,
                scenario.get("expected_alert_rule_id") or scenario.get("rule_id"),
                yaml_text,
                sha,
                scenario.get("description") or "",
            )
    except Exception as exc:
        log.warning("register_scenario(%s) failed: %s", sid, exc)


async def mark_scenario_disabled(scenario_id: str) -> None:
    """Setzt enabled=false. Verwendet beim delete_scenario — Eintrag bleibt
    für Historie (run_count-Aggregation), wird aber nicht mehr als 'aktiv'
    gezählt im Coverage-Report."""
    pool = get_pool()
    if pool is None:
        return
    try:
        async with pool.acquire() as conn:
            await conn.execute(
                "UPDATE redteam_scenarios SET enabled=false, updated_at=now() "
                "WHERE scenario_id=$1",
                scenario_id,
            )
    except Exception as exc:
        log.warning("mark_scenario_disabled(%s) failed: %s", scenario_id, exc)


async def log_scenario_run(
    *,
    scenario_id:       str,
    target_ip:         str,
    exit_code:         int,
    duration_ms:       int | None,
    matched_count:     int,
    expected_rule_id:  str | None,
    matched_rule_ids:  list[str] | None = None,
    timed_out:         bool = False,
) -> None:
    """Schreibt eine Run-Row nach redteam_results. detected = matched_count>0
    UND expected_rule_id war gesetzt. Bei Scenarios ohne expected_rule_id
    bleibt detected=NULL (= unbewertet)."""
    pool = get_pool()
    if pool is None:
        return

    detected: bool | None = None
    if expected_rule_id:
        detected = matched_count > 0

    try:
        async with pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO redteam_results
                    (scenario_id, run_kind, target_ip, exit_code, timed_out,
                     duration_ms, matched_count, expected_rule_id, detected)
                VALUES ($1, 'scenario', $2::inet, $3, $4, $5, $6, $7, $8)
                """,
                scenario_id, target_ip, exit_code, timed_out, duration_ms,
                matched_count, expected_rule_id, detected,
            )
    except Exception as exc:
        log.warning("log_scenario_run(%s) failed: %s", scenario_id, exc)


async def log_tool_run(
    *,
    tool:             str,
    target_ip:        str,
    args:             list[str],
    exit_code:        int,
    duration_ms:      int | None,
    matched_count:    int,
    expected_rule_id: str | None,
    timed_out:        bool = False,
) -> None:
    """Wie log_scenario_run, aber run_kind='kali_tool' — z.B. für nmap-/
    hping3-Runs, die nicht aus einem YAML kommen aber trotzdem zu MITRE-
    Coverage gezählt werden sollten."""
    pool = get_pool()
    if pool is None:
        return
    detected: bool | None = None
    if expected_rule_id:
        detected = matched_count > 0
    try:
        async with pool.acquire() as conn:
            # DB-Pool hat einen jsonb-Codec aus db._init_conn — list/dict
            # wird automatisch zu jsonb encoded. Doppel-Encode via json.dumps
            # + ::jsonb-Cast wäre Müll (siehe Memory: asyncpg jsonb codec).
            await conn.execute(
                """
                INSERT INTO redteam_results
                    (scenario_id, run_kind, tool, target_ip, args, exit_code,
                     timed_out, duration_ms, matched_count, expected_rule_id, detected)
                VALUES ($1, 'kali_tool', $2, $3::inet, $4, $5, $6, $7, $8, $9, $10)
                """,
                f"_tool:{tool}", tool, target_ip, args, exit_code,
                timed_out, duration_ms, matched_count, expected_rule_id, detected,
            )
    except Exception as exc:
        log.warning("log_tool_run(%s) failed: %s", tool, exc)
