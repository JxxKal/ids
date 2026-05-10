"""api/src/routers/pattern_export.py — Lab-seitige Pattern-Bundle-Generierung.

Wird nur ge-mounted wenn `system_config['features'].pattern_export_enabled = true`.
Customer-Master ohne Lab-Profil hat den Endpoint physisch nicht — bei Default-
Config bleibt diese Datei import-able aber ungenutzt.

Endpoints:
  GET    /api/pattern/signing-keys      — Liste der Lab-Signing-Keys
  POST   /api/pattern/signing-keys      — Signing-Key registrieren (privkey-Pfad + Pubkey)
  DELETE /api/pattern/signing-keys/{id} — Key löschen
  POST   /api/pattern/export            — Bundle bauen + signieren + streamen
  GET    /api/pattern/exports           — Export-Audit-Log

Bundle-Format siehe docs/REDTEAM_v1.3.0.md §3.3.
"""
from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

import asyncpg
import yaml
from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from database import get_pool
from deps import require_admin

router = APIRouter(prefix="/api/pattern", tags=["pattern-export"])
log = logging.getLogger(__name__)

EXPORT_SCHEMA_VERSION = 1
LAB_ID = os.environ.get("CYJAN_LAB_ID", "").strip() or "cyjan-lab-unset"

# Lab-curated Recalibration-File. Lebt im signature-rules-Volume neben den
# Rules — Lab-Engineer pflegt es manuell nach Auswertung der Auto-RedTeam-Sweeps.
RECALIBRATION_FILE = Path("/sig-rules/_defaults_recalibration.yml")

CUSTOM_RULES_DIR   = Path("/sig-rules")
SURICATA_RULES_DIR = Path("/sig-rules/suricata")
SCENARIOS_DIR      = Path("/cyjan-scenarios")


# ─────────────────────────────────────────────────────────────────────────────
# Models
# ─────────────────────────────────────────────────────────────────────────────


BundleComponent = Literal[
    "rules.custom",
    "rules.suricata",
    "defaults.recalibration",
    "tests.regression",
    "evidence.mitre",
]


class SigningKey(BaseModel):
    id: str
    lab_id: str
    key_id: str
    pubkey_sha256: str
    enabled: bool
    description: str | None
    created_at: str


class SigningKeyCreate(BaseModel):
    lab_id: str = Field(min_length=1)
    key_id: str = Field(min_length=1)
    pubkey_pem: str = Field(min_length=20)
    privkey_path: str = Field(min_length=1)
    description: str | None = None


class ExportRequest(BaseModel):
    components: list[BundleComponent] = Field(min_length=1)
    sign_with_key_id: str | None = None
    description: str = ""
    lab_run_id: str | None = None


class ExportRecord(BaseModel):
    id: str
    bundle_sha256: str
    bundle_size: int
    lab_run_id: str
    components_exported: dict[str, Any]
    exported_at: str
    description: str | None


# ─────────────────────────────────────────────────────────────────────────────
# Signing-Keys CRUD
# ─────────────────────────────────────────────────────────────────────────────


@router.get("/signing-keys", dependencies=[Depends(require_admin)])
async def list_signing_keys(pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT id::text AS id, lab_id, key_id, pubkey_sha256, enabled, "
            "description, created_at::text AS created_at "
            "FROM pattern_signing_keys ORDER BY lab_id, key_id"
        )
    return {"keys": [SigningKey(**dict(r)).model_dump() for r in rows]}


@router.post("/signing-keys", dependencies=[Depends(require_admin)])
async def add_signing_key(
    body: SigningKeyCreate,
    pool: asyncpg.Pool = Depends(get_pool),
) -> SigningKey:
    pem = body.pubkey_pem.strip()
    if not pem.startswith("-----BEGIN"):
        raise HTTPException(400, "pubkey_pem muss PGP- oder PEM-Format haben")
    sha = hashlib.sha256(pem.encode()).hexdigest()

    # Sanity-Check: privkey_path muss existieren (file) oder hsm:// (URI)
    pk = body.privkey_path
    if not (pk.startswith("hsm://") or pk.startswith("cosign://") or Path(pk).is_file()):
        raise HTTPException(400, f"privkey_path '{pk}' nicht erreichbar")

    async with pool.acquire() as conn:
        try:
            row = await conn.fetchrow(
                """
                INSERT INTO pattern_signing_keys
                    (lab_id, key_id, pubkey_pem, pubkey_sha256, privkey_path, description)
                VALUES ($1, $2, $3, $4, $5, $6)
                RETURNING id::text AS id, lab_id, key_id, pubkey_sha256, enabled,
                          description, created_at::text AS created_at
                """,
                body.lab_id, body.key_id, pem, sha, body.privkey_path, body.description,
            )
        except asyncpg.UniqueViolationError as exc:
            raise HTTPException(409, f"Key bereits registriert: {exc}")
    return SigningKey(**dict(row))


@router.delete("/signing-keys/{key_id}", dependencies=[Depends(require_admin)])
async def delete_signing_key(key_id: str, pool: asyncpg.Pool = Depends(get_pool)) -> dict:
    async with pool.acquire() as conn:
        result = await conn.execute(
            "DELETE FROM pattern_signing_keys WHERE id = $1::uuid", key_id,
        )
    if result == "DELETE 0":
        raise HTTPException(404, "Signing-Key nicht gefunden")
    return {"deleted": True}


# ─────────────────────────────────────────────────────────────────────────────
# Bundle-Build + Signing
# ─────────────────────────────────────────────────────────────────────────────


@router.post("/export", dependencies=[Depends(require_admin)])
async def export_bundle(
    req: ExportRequest,
    pool: asyncpg.Pool = Depends(get_pool),
) -> StreamingResponse:
    """Baut das Bundle in-memory, optional signiert, gibt es als ZIP-Stream
    zurück. Audit-Eintrag wird nach successful build gespeichert."""

    lab_run_id = req.lab_run_id or f"lab-{datetime.now(timezone.utc):%Y-%m-%d-%H%M}"

    buf = io.BytesIO()
    component_manifest: dict[str, Any] = {}

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as zf:

        if "rules.custom" in req.components:
            files = await _collect_custom_rules(zf)
            if files:
                component_manifest["rules.custom"] = {"file_count": len(files), "files": files}

        if "rules.suricata" in req.components:
            files = await _collect_suricata_rules(zf)
            if files:
                component_manifest["rules.suricata"] = {"file_count": len(files), "files": files}

        if "defaults.recalibration" in req.components:
            recal = await _collect_recalibration()
            if recal:
                payload = yaml.safe_dump(recal, sort_keys=False)
                zf.writestr("defaults/parameter_recalibration.yml", payload)
                component_manifest["defaults.recalibration"] = {
                    "entry_count": len(recal.get("recalibrations", [])),
                    "sha256":      _sha256_str(payload),
                }

        if "tests.regression" in req.components:
            files = await _collect_regression_tests(zf)
            if files:
                component_manifest["tests.regression"] = {"file_count": len(files), "files": files}

        if "evidence.mitre" in req.components:
            mitre = await _collect_mitre_coverage(pool, lab_run_id)
            if mitre:
                payload = json.dumps(mitre, indent=2)
                zf.writestr("evidence/mitre-coverage-matrix.json", payload)
                component_manifest["evidence.mitre"] = {
                    "techniques_validated": len(mitre.get("techniques", [])),
                    "sha256":                _sha256_str(payload),
                }

        # ── manifest.json ──────────────────────────────────────────────
        manifest = {
            "schema_version":   EXPORT_SCHEMA_VERSION,
            "lab_id":           LAB_ID,
            "lab_run_id":       lab_run_id,
            "cyjan_version":    _read_cyjan_version(),
            "compatible_with":  f">={_cyjan_minor()},<{_cyjan_next_major()}",
            "exported_at":      datetime.now(timezone.utc).isoformat(),
            "description":      req.description,
            "components":       component_manifest,
            "summary": {
                "total_files": sum(
                    c.get("file_count", c.get("entry_count", 0))
                    for c in component_manifest.values()
                ),
            },
        }
        manifest_bytes = json.dumps(manifest, indent=2).encode()
        zf.writestr("manifest.json", manifest_bytes)

        # ── manifest.json.sig (optional) ───────────────────────────────
        sig_key_id_uuid = None
        if req.sign_with_key_id:
            sig_bytes, sig_key_id_uuid = await _sign_manifest(
                manifest_bytes, req.sign_with_key_id, pool,
            )
            zf.writestr("manifest.json.sig", sig_bytes)

        # ── README.md ──────────────────────────────────────────────────
        zf.writestr("README.md", _build_readme(manifest, signed=bool(sig_key_id_uuid)))

    raw = buf.getvalue()
    bundle_sha = hashlib.sha256(raw).hexdigest()

    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO pattern_export_log
                (bundle_sha256, bundle_size, lab_run_id, components_exported,
                 signed_with_key_id, description)
            VALUES ($1, $2, $3, $4::jsonb, $5, $6)
            """,
            bundle_sha, len(raw), lab_run_id,
            json.dumps(component_manifest),
            sig_key_id_uuid, req.description,
        )

    fname = f"cyjan-pattern-{LAB_ID}-{lab_run_id}.zip"
    return StreamingResponse(
        io.BytesIO(raw),
        media_type="application/zip",
        headers={
            "Content-Disposition": f'attachment; filename="{fname}"',
            "Content-Length":      str(len(raw)),
            "X-Bundle-SHA256":     bundle_sha,
            "X-Bundle-Schema-Ver": str(EXPORT_SCHEMA_VERSION),
        },
    )


@router.get("/exports", dependencies=[Depends(require_admin)])
async def list_exports(pool: asyncpg.Pool = Depends(get_pool), limit: int = 50) -> dict:
    limit = max(1, min(500, limit))
    async with pool.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT id::text AS id, bundle_sha256, bundle_size, lab_run_id,
                   components_exported, exported_at::text AS exported_at, description
            FROM pattern_export_log
            ORDER BY exported_at DESC
            LIMIT $1
            """,
            limit,
        )
    return {"exports": [dict(r) for r in rows]}


# ─────────────────────────────────────────────────────────────────────────────
# Collector-Funktionen
# ─────────────────────────────────────────────────────────────────────────────


async def _collect_custom_rules(zf: zipfile.ZipFile) -> list[dict]:
    if not CUSTOM_RULES_DIR.exists():
        return []
    out = []
    for f in sorted(CUSTOM_RULES_DIR.glob("*.yml")):
        # Skip Config-Files (nicht Rules)
        if f.name.startswith("_"):
            continue
        try:
            doc = yaml.safe_load(f.read_text())
        except yaml.YAMLError as exc:
            log.warning("skip unparseable %s: %s", f.name, exc)
            continue
        if not isinstance(doc, dict) or "id" not in doc:
            continue

        clean_yaml = yaml.safe_dump(doc, sort_keys=False)
        zf.writestr(f"rules/custom/{f.name}", clean_yaml)
        out.append({
            "name":    f.name,
            "rule_id": doc["id"],
            "sha256":  _sha256_str(clean_yaml),
        })
    return out


async def _collect_suricata_rules(zf: zipfile.ZipFile) -> list[dict]:
    if not SURICATA_RULES_DIR.exists():
        return []
    out = []
    for f in sorted(SURICATA_RULES_DIR.glob("*.rules")):
        content = f.read_bytes()
        zf.writestr(f"rules/suricata/{f.name}", content)
        out.append({"name": f.name, "sha256": hashlib.sha256(content).hexdigest()})
    return out


async def _collect_recalibration() -> dict | None:
    """Liest Lab-curated _defaults_recalibration.yml. Format:

        version: 1
        curator: jan@cyjan.io
        reviewed_at: 2026-04-29
        recalibrations:
          - rule_id: SCAN_001
            param: port_count
            new_default: 35
            old_default: 50
            reason: "Lab-Sweep optimum bei 35 (+12% TPR / -3% FPR), generisch"
            evidence:
              scenarios_validated: 18

    Wird vom Lab-Engineer manuell nach Review der Auto-RedTeam-Sweeps gepflegt
    — kein Auto-Derive aus rule_baselines (Lab-spezifisch wäre)."""
    if not RECALIBRATION_FILE.exists():
        return None
    try:
        doc = yaml.safe_load(RECALIBRATION_FILE.read_text())
    except yaml.YAMLError as exc:
        log.error("recalibration file unparseable: %s", exc)
        return None
    if not isinstance(doc, dict) or "recalibrations" not in doc:
        return None
    return doc


async def _collect_regression_tests(zf: zipfile.ZipFile) -> list[dict]:
    if not SCENARIOS_DIR.exists():
        return []
    out = []
    for f in sorted(SCENARIOS_DIR.rglob("*.yml")):
        if "imported" in f.parts:
            # Imported Scenarios nicht reexportieren — Echo-Loop-Schutz
            continue
        rel = f.relative_to(SCENARIOS_DIR)
        content = f.read_bytes()
        zf.writestr(f"tests/regression/{rel}", content)
        out.append({"path": str(rel), "sha256": hashlib.sha256(content).hexdigest()})
    return out


async def _collect_mitre_coverage(pool: asyncpg.Pool, lab_run_id: str) -> dict:
    """MITRE-Coverage aus redteam_results, aggregiert über letzte 30 Tage.
    Tags-Format aus scenario.yaml: 'T1234' oder 'T1234.001' für Sub-Techniques."""
    try:
        async with pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT
                    s.scenario_id,
                    s.rule_id           AS expected_rule_id,
                    s.yaml_source,
                    COUNT(r.*)          AS run_count,
                    SUM(CASE WHEN r.detected THEN 1 ELSE 0 END)::int AS detected_count
                FROM redteam_scenarios s
                LEFT JOIN redteam_results r
                  ON r.scenario_id = s.scenario_id
                  AND r.ts > now() - interval '30 days'
                GROUP BY s.scenario_id, s.rule_id, s.yaml_source
                ORDER BY s.scenario_id
                """
            )
    except asyncpg.UndefinedTableError:
        # redteam_scenarios noch nicht migriert — kommt bei Phase-1-only-Stand vor
        return {
            "schema_version": 1,
            "lab_run_id": lab_run_id,
            "evaluated_at": datetime.now(timezone.utc).isoformat(),
            "evaluation_window_days": 30,
            "techniques": [],
            "note": "redteam_scenarios-Tabelle leer oder nicht migriert",
        }

    techniques: dict[str, dict] = {}
    for row in rows:
        try:
            doc = yaml.safe_load(row["yaml_source"]) or {}
            tags = doc.get("tags") or []
        except Exception:
            tags = []
        mitre_tags = [
            t for t in tags
            if isinstance(t, str) and t.startswith("T")
            and t[1:].split(".")[0].isdigit()
        ]
        for tt in mitre_tags:
            tech = techniques.setdefault(tt, {
                "technique_id": tt, "scenarios": [],
                "detection_count": 0, "run_count": 0,
            })
            tech["scenarios"].append({
                "scenario_id":      row["scenario_id"],
                "expected_rule_id": row["expected_rule_id"],
                "run_count":        row["run_count"] or 0,
                "detected_count":   row["detected_count"] or 0,
                "tpr":              (row["detected_count"] / row["run_count"]) if row["run_count"] else 0,
            })
            tech["detection_count"] += row["detected_count"] or 0
            tech["run_count"]       += row["run_count"] or 0

    return {
        "schema_version": 1,
        "lab_run_id": lab_run_id,
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "evaluation_window_days": 30,
        "techniques": sorted(techniques.values(), key=lambda t: t["technique_id"]),
    }


# ─────────────────────────────────────────────────────────────────────────────
# Signing
# ─────────────────────────────────────────────────────────────────────────────


async def _sign_manifest(
    manifest_bytes: bytes,
    key_id: str,
    pool: asyncpg.Pool,
) -> tuple[bytes, str]:
    """Detached PGP-Signature über manifest.json. HSM/Cosign-Pfade als V2."""
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT id::text AS id, privkey_path, key_id, lab_id "
            "FROM pattern_signing_keys WHERE id = $1::uuid AND enabled = true",
            key_id,
        )
    if not row:
        raise HTTPException(404, "Signing-Key nicht gefunden oder deaktiviert")

    privkey_path = row["privkey_path"]

    if privkey_path.startswith("hsm://") or privkey_path.startswith("cosign://"):
        raise HTTPException(501, "HSM/Cosign-Signing ist V2-Backlog. PGP-Pfad nutzen.")

    try:
        import pgpy
    except ImportError:
        raise HTTPException(500, "pgpy nicht installiert")

    try:
        priv, _ = pgpy.PGPKey.from_file(privkey_path)
    except Exception as exc:
        raise HTTPException(500, f"Privkey {privkey_path} nicht ladbar: {exc}")

    if priv.is_protected:
        passphrase = os.environ.get("PATTERN_SIGNING_PASSPHRASE", "")
        if not passphrase:
            raise HTTPException(
                500,
                "Privkey ist passphrase-protected, aber PATTERN_SIGNING_PASSPHRASE nicht gesetzt",
            )
        with priv.unlock(passphrase):
            sig = priv.sign(manifest_bytes, detach=True)
    else:
        sig = priv.sign(manifest_bytes, detach=True)
    return str(sig).encode(), row["id"]


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────


def _read_cyjan_version() -> str:
    try:
        return Path("/opt/ids/VERSION").read_text().strip()
    except FileNotFoundError:
        return "unknown"


def _cyjan_minor() -> str:
    v = _read_cyjan_version().lstrip("v")
    parts = v.split(".")
    if len(parts) >= 2 and parts[0].isdigit() and parts[1].isdigit():
        major, minor = int(parts[0]), int(parts[1])
        return f"v{major}.{max(0, minor - 1)}.0"
    return "v0.0.0"


def _cyjan_next_major() -> str:
    v = _read_cyjan_version().lstrip("v")
    parts = v.split(".")
    if parts and parts[0].isdigit():
        return f"v{int(parts[0]) + 1}.0.0"
    return "v999.0.0"


def _sha256_str(s: str | bytes) -> str:
    if isinstance(s, str):
        s = s.encode()
    return hashlib.sha256(s).hexdigest()


def _build_readme(manifest: dict, signed: bool) -> str:
    lines = [
        f"# Cyjan Pattern Bundle",
        "",
        f"- **Lab-ID:** `{manifest['lab_id']}`",
        f"- **Lab-Run:** `{manifest['lab_run_id']}`",
        f"- **Erstellt:** {manifest['exported_at']}",
        f"- **Cyjan-Version:** {manifest['cyjan_version']}",
        f"- **Schema:** v{manifest['schema_version']}",
        f"- **Signiert:** {'ja' if signed else 'NEIN — Customer-Apply braucht force_unverified=true'}",
        "",
    ]
    if manifest.get("description"):
        lines += [f"## Beschreibung", "", manifest["description"], ""]
    lines += ["## Inhalt", ""]
    for cname, cdata in manifest.get("components", {}).items():
        lines.append(f"### `{cname}`")
        for k, v in cdata.items():
            if k == "files" and isinstance(v, list) and len(v) > 5:
                lines.append(f"- **{k}:** {len(v)} Einträge (siehe manifest.json)")
            elif k == "files":
                lines.append(f"- **{k}:**")
                for entry in v:
                    name = entry.get("name") or entry.get("path") or "?"
                    lines.append(f"  - `{name}`")
            else:
                lines.append(f"- **{k}:** {v}")
        lines.append("")
    lines += [
        "## Anwendung",
        "",
        "Customer-System: Settings → System → Pattern-Bundle einspielen.",
    ]
    if not signed:
        lines += [
            "",
            "**WARNUNG:** Bundle ist nicht signiert. Customer-Apply erfordert",
            "explizit `force_unverified=true`. Manuell verifizieren!",
        ]
    return "\n".join(lines)
