"""Offline-Update: ZIP-Upload → Extraktion → docker load → compose up.

Kernproblem: docker compose up -d läuft im ids-api-Container. Wenn Compose
ids-api rekonstruiert, killt es sich selbst.

Lösung: Nach docker load einen UNABHÄNGIGEN Einweg-Container starten, der
docker compose up -d ausführt. Dieser Container heißt NICHT ids-api und wird
daher NICHT gekillt, wenn Compose ids-api neustartet. Funktioniert auch wenn
das geladene Image alten Code enthält – der Runner-Container ist ein anderes
Objekt als der ids-api-Service-Container.
"""
from __future__ import annotations

import asyncio
import io
import os
import shlex
import shutil
import subprocess
import tempfile
import zipfile
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Body, Depends, File, Form, HTTPException, UploadFile

from deps import require_admin as _require_admin_late  # type: ignore[import-not-found]

router = APIRouter(prefix="/api/system", tags=["update"])

IDS_DIR       = Path("/opt/ids")
_PROTECT      = {".env", ".git"}
_IMAGE_FILES  = {"images.tar.zst", "images.tar.gz", "images.tar"}
_VERSION_FILE = IDS_DIR / "VERSION"


def _read_version() -> str:
    try:
        return _VERSION_FILE.read_text().strip()
    except OSError:
        return "unbekannt"


_state: dict[str, Any] = {
    "phase":       "idle",
    "log":         [],
    "progress":    0,
    "started_at":  None,
    "finished_at": None,
}


def _ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def _log(msg: str) -> None:
    _state["log"].append(f"[{_ts()}] {msg}")
    if len(_state["log"]) > 500:
        _state["log"] = _state["log"][-200:]


def _extract(zip_bytes: bytes, dest: Path) -> tuple[int, str | None]:
    with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
        tmp.write(zip_bytes)
        tmp_path = Path(tmp.name)
    images_entry: str | None = None
    dest_resolved = dest.resolve()
    try:
        with zipfile.ZipFile(tmp_path, "r") as zf:
            members = zf.namelist()
            if not members:
                raise ValueError("ZIP ist leer")
            prefix = members[0].split("/")[0] + "/"
            count = 0
            for member in members:
                rel = member.removeprefix(prefix)
                if not rel:
                    continue
                parts = rel.split("/")
                if parts[0] in _PROTECT:
                    continue
                if parts[-1] in _IMAGE_FILES:
                    images_entry = member
                    continue
                target = dest / rel
                # Zip-Slip-Schutz: ein Member wie '…/../../etc/cron.d/pwn' oder ein
                # absoluter Pfad ('/etc/...') würde sonst außerhalb von dest landen.
                # Der API-Container läuft als root mit gemountetem /opt/ids + docker.sock,
                # also wäre ein Write außerhalb ein Root-File-Write am Host → RCE.
                # resolve() normalisiert '..'; relative_to wirft bei Ausbruch.
                try:
                    target.resolve().relative_to(dest_resolved)
                except ValueError:
                    _log(f"Übersprungen (Pfad-Traversal-Versuch): {member}")
                    continue
                if member.endswith("/"):
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with zf.open(member) as src, open(target, "wb") as dst:
                        shutil.copyfileobj(src, dst)
                    count += 1
        return count, images_entry
    finally:
        tmp_path.unlink(missing_ok=True)


def _unpack_images_to_temp(zip_bytes: bytes, member: str) -> Path:
    if member.endswith(".zst"):
        suffix = ".tar.zst"
    elif member.endswith(".gz"):
        suffix = ".tar.gz"
    else:
        suffix = ".tar"
    tmp = Path(tempfile.mktemp(suffix=suffix))
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        with zf.open(member) as src, open(tmp, "wb") as dst:
            shutil.copyfileobj(src, dst)
    return tmp


async def _run_subprocess(
    cmd: list[str],
    on_line: Callable[[str], None] | None = None,
) -> None:
    proc = await asyncio.create_subprocess_exec(
        *cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
        cwd=str(IDS_DIR),
    )
    assert proc.stdout is not None
    async for raw in proc.stdout:
        line = raw.decode(errors="replace").rstrip()
        if line:
            _log(line)
            if on_line:
                on_line(line)
    rc = await proc.wait()
    if rc != 0:
        raise RuntimeError(f"'{' '.join(cmd[:3])} …' beendet mit Code {rc}")


def _profile_flags(profile: str) -> str:
    """'prod,snort' → '--profile prod --profile snort'.

    /etc/cyjan/profile ist kommasepariert; ein einzelnes
    `--profile prod,snort` würde Compose als EIN (nicht existentes) Profil
    lesen — Services unter dem snort-Profil blieben dann beim Update auf dem
    alten Container stehen. Profilnamen sind alphanumerisch (+Bindestrich),
    daher ist die String-Interpolation in die sh-c-Runner unkritisch.
    """
    parts = [p.strip() for p in profile.split(",") if p.strip()] or ["prod"]
    return " ".join(f"--profile {p}" for p in parts)


def _profile_args(profile: str) -> list[str]:
    """Wie _profile_flags, aber als argv-Liste für subprocess-Aufrufe."""
    parts = [p.strip() for p in profile.split(",") if p.strip()] or ["prod"]
    args: list[str] = []
    for p in parts:
        args += ["--profile", p]
    return args


def _spawn_compose_up_runner(ids_dir: Path, profile: str) -> None:
    """Startet docker compose up -d in einem UNABHÄNGIGEN Einweg-Container.

    Der Container wird via `docker run` gestartet und ist NICHT der
    ids-api-Service-Container. Wenn Compose den ids-api-Service neu startet,
    ist dieser Runner-Container davon unberührt und läuft bis zum Ende.

    Verwendet ids-api:latest als Basis-Image (hat docker-compose-plugin).
    sleep 5 gibt dem aktuellen API-Container Zeit, den "done"-Status zu schreiben
    bevor compose up startet.

    --force-recreate: Compose erkennt manchmal nicht, dass ein per `docker load`
    geladenes Image neue Layer hat (Image-Tag ist identisch, Image-Digest weicht
    aber ab). Ohne --force-recreate bleibt z.B. der frontend-Container am
    alten Image kleben — mit dem Effekt, dass neue UI-Sections nach einem
    Update unsichtbar bleiben. Nach dem Update wollen wir ohnehin alle
    Container in der neuen Version sehen, also forcieren wir das.

    Hinweis: --no-build wurde bewusst weggelassen, weil das Flag erst seit
    docker compose 2.21+ existiert und das Plugin im API-Image bei alten
    Update-Pfaden ggf. älter ist (Update-Runner nutzt sein eigenes Plugin,
    nicht das Host-Plugin). Compose `up -d` bauen nur Services für die
    `build:` deklariert ist UND deren Image fehlt — nach `docker load`
    sind alle nötigen Images da, das Risiko eines unbeabsichtigten Builds
    ist null.

    Logs landen in <ids_dir>/.update-runner.log (auf dem Host sichtbar, weil
    das ids-Verzeichnis ohnehin gebind-mountet ist), damit man bei Problemen
    nachvollziehen kann warum Compose ggf. abgebrochen ist.
    """
    compose_cmd = (
        f"docker compose --project-directory {ids_dir} {_profile_flags(profile)} "
        f"up -d --force-recreate"
    )
    log_path = str(ids_dir / ".update-runner.log")
    subprocess.Popen(
        [
            "docker", "run", "--rm", "--detach",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{ids_dir}:{ids_dir}",
            "-w", str(ids_dir),
            "-e", "COMPOSE_PROJECT_NAME=ids",
            "--name", "ids-update-runner",
            "ids-api:latest",
            "sh", "-c",
            f"sleep 5 && {compose_cmd} >{log_path} 2>&1",
        ],
        start_new_session=True,
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ},
    )


async def _run_update(zip_bytes: bytes, pull_images: bool) -> None:
    _state.update({
        "phase":       "extracting",
        "log":         [],
        "progress":    0,
        "started_at":  datetime.now(timezone.utc).isoformat(),
        "finished_at": None,
    })
    try:
        # ── 1. ZIP entpacken (0-10%) ──────────────────────────────────────────
        _log(f"Entpacke ZIP ({len(zip_bytes) // 1024} KB) nach {IDS_DIR} ...")
        count, images_entry = await asyncio.to_thread(_extract, zip_bytes, IDS_DIR)
        _log(f"{count} Dateien entpackt. .env und .git bleiben erhalten.")
        _state["progress"] = 10

        profile_file = Path("/etc/cyjan/profile")
        profile = profile_file.read_text().strip() if profile_file.exists() else "prod"
        _log(f"Compose-Profil: {profile}")

        base_args = [
            "docker", "compose",
            "--project-directory", str(IDS_DIR),
            *_profile_args(profile),
        ]

        if images_entry:
            # ── 2A. Vorgebaute Images laden (10-80%) ──────────────────────────
            _state["phase"] = "loading"
            img_name = images_entry.split("/")[-1]
            _log(f"Vorgebaute Images gefunden ({img_name}) – lade via docker load ...")
            _state["progress"] = 12

            tmp_img = await asyncio.to_thread(_unpack_images_to_temp, zip_bytes, images_entry)
            try:
                loaded = [0]
                def on_load_line(line: str) -> None:
                    if "Loaded image" in line:
                        loaded[0] += 1
                        _state["progress"] = min(78, 15 + loaded[0] * 6)

                # docker load akzeptiert tar und tar.gz direkt, .tar.zst aber
                # erst ab Engine 24+. Für Robustheit bei zstd entpacken wir
                # explizit per `zstd -dc` und pipen in `docker load -i -`.
                if str(tmp_img).endswith(".zst"):
                    cmd = ["sh", "-c",
                           f"zstd -dc {shlex.quote(str(tmp_img))} | docker load"]
                else:
                    cmd = ["docker", "load", "-i", str(tmp_img)]
                await _run_subprocess(cmd, on_load_line)
            finally:
                await asyncio.to_thread(tmp_img.unlink, True)

            _log("Images geladen.")
            _state["progress"] = 80

        else:
            # ── 2B. Aus Quellcode bauen (10-80%) ─────────────────────────────
            _state["phase"] = "building"
            build_cmd = base_args + ["build"]
            if pull_images:
                build_cmd.append("--pull")
                _log("Starte: docker compose build --pull ...")
            else:
                _log("ZIP enthält keine vorgebauten Images – baue aus Quellcode.")
                _log("HINWEIS: Erfordert Zugriff auf Docker Hub (python:3.12-slim, rust:1.85-slim …).")
                _log("         Für Offline-Betrieb bitte Release-ZIP von GitHub verwenden (enthält images.tar.gz).")
            _state["progress"] = 15
            network_error = [False]
            def _check_network(line: str) -> None:
                if "registry-1.docker.io" in line or "deadline exceeded" in line or "dial tcp" in line:
                    network_error[0] = True

            try:
                await _run_subprocess(build_cmd, _check_network)
            except RuntimeError as build_exc:
                if network_error[0]:
                    raise RuntimeError(
                        "Docker Hub nicht erreichbar – Build abgebrochen. "
                        "Bitte Release-ZIP von GitHub verwenden: das enthält images.tar.gz "
                        "und funktioniert ohne Internet-Zugang."
                    ) from build_exc
                raise
            _state["progress"] = 80

        # ── 3. Unabhängigen Runner-Container starten (80-100%) ────────────────
        _state["phase"]       = "restarting"
        _state["progress"]    = 85
        _log("Starte unabhängigen Update-Runner-Container ...")
        _log("Alle Services werden neu gestartet – API-Verbindung kurz unterbrochen (~20 Sek.).")

        # Status jetzt setzen BEVOR der Runner startet und uns killt
        _state["phase"]       = "done"
        _state["progress"]    = 100
        _state["finished_at"] = datetime.now(timezone.utc).isoformat()
        _log("Update abgeschlossen. Seite nach ~20 Sekunden neu laden.")

        _spawn_compose_up_runner(IDS_DIR, profile)
        return  # finally setzt finished_at nicht nochmal

    except Exception as exc:  # noqa: BLE001
        _state["phase"] = "error"
        _log(f"FEHLER: {exc}")
    finally:
        if not _state.get("finished_at"):
            _state["finished_at"] = datetime.now(timezone.utc).isoformat()


def _peek_zip_version(zip_bytes: bytes) -> str | None:
    """Liest VERSION aus dem ZIP ohne zu extrahieren. Gibt None zurück
    wenn das Bundle keinen lesbaren Marker hat (z.B. uralte Builds vor
    dem VERSION-File-Pinning) — in dem Fall lassen wir das Update zu."""
    try:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            members = zf.namelist()
            if not members:
                return None
            prefix = members[0].split("/")[0] + "/"
            candidate = f"{prefix}VERSION"
            if candidate in members:
                with zf.open(candidate) as fh:
                    return fh.read().decode("utf-8", errors="replace").strip() or None
    except Exception:
        pass
    return None


def _validate_bundle(zip_bytes: bytes) -> None:
    """Prüft die ZIP-Struktur, bevor das Update überhaupt scheduled wird.

    Häufiger User-Fehler: aus dem GitHub-Actions-„Artifacts"-Tab statt aus den
    Release-Assets heruntergeladen — das produziert einen Wrapper-ZIP mit
    den eigentlichen Update-ZIPs *innen drin* (verschachtelt). Der bisherige
    Code hat das nicht erkannt und ist still in den Build-aus-Quellcode-Pfad
    gerutscht.

    Erwartete Struktur:
      cyjan-ids-update-<tag>/
        images.tar.{zst,gz}    (oder images.tar)
        docker-compose.yml
        VERSION
        infra/...

    Bei Fehler → HTTPException(400) mit klarer User-Message.
    """
    try:
        zf = zipfile.ZipFile(io.BytesIO(zip_bytes))
    except zipfile.BadZipFile as exc:
        raise HTTPException(400, f"Datei ist kein gültiges ZIP: {exc}")
    members = zf.namelist()
    if not members:
        raise HTTPException(400, "ZIP ist leer")

    # Wrapped-ZIP-Detection: wenn der Top-Level Inhalt selbst eine .zip-Datei
    # ist, hat der User wahrscheinlich aus „GitHub Actions Artifacts" geladen
    # (das verpackt Release-Assets in einem zusätzlichen Wrapper).
    nested_zips = [m for m in members if m.endswith(".zip") and "/" not in m.rstrip("/")]
    if nested_zips:
        raise HTTPException(
            400,
            "Diese ZIP enthält weitere ZIP-Dateien — vermutlich wurde sie aus "
            "dem GitHub-Actions-Artifacts-Tab heruntergeladen. Bitte stattdessen "
            "den Release-Asset von github.com/JxxKal/ids/releases verwenden "
            f"(z.B. cyjan-ids-update-latest.zip). Gefunden: {', '.join(nested_zips[:3])}",
        )

    # Erwartete Top-Level-Marker prüfen.
    prefix = members[0].split("/")[0] + "/"
    has_compose = any(m == f"{prefix}docker-compose.yml" for m in members)
    has_bundle = any(
        m == f"{prefix}{img}" for m in members for img in _IMAGE_FILES
    )
    if not has_compose:
        raise HTTPException(
            400,
            "ZIP enthält keine docker-compose.yml auf Top-Level — kein gültiges "
            "Cyjan-Update-Bundle. Bitte das offizielle "
            "cyjan-ids-update-<tag>.zip aus den GitHub-Releases verwenden.",
        )
    if not has_bundle:
        raise HTTPException(
            400,
            "ZIP enthält kein Image-Bundle (images.tar.zst/.gz/.tar). Ohne "
            "vorgebaute Images würde der Update-Pfad in den Build-aus-Quellcode-"
            "Modus fallen, was auf Air-Gap-Hosts ohne Internet sicher fehlschlägt. "
            "Bitte das offizielle Release-ZIP verwenden.",
        )


def _parse_semver(s: str) -> tuple[int, int, int] | None:
    """v1.5.1 → (1, 5, 1). Alles was nicht passt → None.
    Ignoriert nachgehängte Suffixe wie '-iso', '-rc1' (alphabetischer
    Vergleich auf Suffix wäre fragil; wir vergleichen rein numerisch
    und behandeln gleich-numerische Tags als 'gleichwertig')."""
    s = s.strip().lstrip("vV")
    # Trim alles ab dem ersten Nicht-[0-9.]
    import re
    m = re.match(r"^(\d+)\.(\d+)\.(\d+)", s)
    if not m:
        return None
    return (int(m.group(1)), int(m.group(2)), int(m.group(3)))


@router.post("/update", summary="Offline-Update via ZIP")
async def start_update(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    pull_images: bool = Form(False),
    force: bool = Form(False),
    user: dict = Depends(_require_admin_late),
) -> dict:
    """Offline-Update via Update-ZIP. Validiert die VERSION im ZIP gegen
    die installierte Version — Downgrades + Same-Version-Re-Plays werden
    abgewiesen, es sei denn `force=true`. Damit verhindert wir Fälle wie
    'eine v1.4.0-ZIP auf eine v1.5.1-Maschine geladen → System sieht aus
    als wär es 1.5.1 (VERSION-File wurde überschrieben), aber die Docker-
    Images sind älter und Migrations bleiben aus'.
    """
    if _state["phase"] not in ("idle", "done", "error"):
        raise HTTPException(409, "Ein Update läuft bereits")
    if not (file.filename or "").endswith(".zip"):
        raise HTTPException(400, "Nur ZIP-Dateien erlaubt")
    zip_bytes = await file.read()

    # Vor allem anderen: Struktur prüfen. Wirft 400 mit spezifischer Message
    # wenn z.B. wrapped GitHub-Actions-Artifacts geladen wurden.
    _validate_bundle(zip_bytes)

    incoming = _peek_zip_version(zip_bytes)
    current = _read_version()
    if incoming and current and not force:
        in_sv = _parse_semver(incoming)
        cur_sv = _parse_semver(current)
        if in_sv and cur_sv:
            if in_sv < cur_sv:
                raise HTTPException(
                    400,
                    f"ZIP enthält {incoming}, installiert ist {current} — Downgrade abgelehnt. "
                    f"Mit force=true erzwingbar.",
                )
            if in_sv == cur_sv:
                raise HTTPException(
                    400,
                    f"ZIP-Version {incoming} entspricht der installierten — kein Update notwendig. "
                    f"Mit force=true erzwingbar.",
                )

    background_tasks.add_task(_run_update, zip_bytes, pull_images)
    return {
        "status":   "started",
        "incoming": incoming or "?",
        "current":  current,
    }


@router.get("/update/status", summary="Update-Status abfragen")
async def get_update_status() -> dict:
    return {**_state, "version": _read_version()}


@router.get("/version", summary="Installierte Version")
async def get_version() -> dict:
    return {"version": _read_version()}


def _spawn_compose_restart_runner(ids_dir: Path, profile: str) -> None:
    compose_cmd = (
        f"docker compose --project-directory {ids_dir} {_profile_flags(profile)} restart"
    )
    subprocess.Popen(
        [
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            "-v", f"{ids_dir}:{ids_dir}",
            "-w", str(ids_dir),
            "-e", "COMPOSE_PROJECT_NAME=ids",
            "--name", "ids-restart-runner",
            "ids-api:latest",
            "sh", "-c", f"sleep 3 && {compose_cmd}",
        ],
        start_new_session=True,
        close_fds=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env={**os.environ},
    )


@router.post("/restart", summary="Stack-Neustart")
async def restart_stack(
    user: dict = Depends(_require_admin_late),
) -> dict:
    if _state["phase"] not in ("idle", "done", "error"):
        raise HTTPException(409, "Ein Update läuft bereits – bitte warten.")
    profile_file = Path("/etc/cyjan/profile")
    profile = profile_file.read_text().strip() if profile_file.exists() else "prod"
    _spawn_compose_restart_runner(IDS_DIR, profile)
    return {"status": "started"}


@router.post("/reboot", summary="Host-Reboot (Hardware-Neustart)")
async def reboot_host(
    payload: dict = Body(default={}),
    user: dict = Depends(_require_admin_late),
) -> dict:
    """Echter Host-Reboot via privilegiertem One-Shot-Container.

    Re-Auth via Passwort, weil shutdown -r alle laufenden Container kappt
    (incl. der API selbst). Nach +1 min Delay, damit die HTTP-Response
    sauber zum Browser zurückkommt bevor das System runterfährt.

    Wird primär nach Settings-Migration angeboten — Stack-Restart allein
    reicht nicht, wenn z.B. die Netzwerk-Bind-Adresse via .env geändert
    wurde und der Kernel-Side-Bind erst beim Re-Bind passt.
    """
    from database import get_pool as _get_pool       # lazy, sonst Zirkel
    from bcrypt import checkpw

    password = (payload or {}).get("password") or ""
    if not password:
        raise HTTPException(400, "Passwort fehlt (Re-Auth-Pflicht)")

    # Re-Auth gegen die users-Tabelle. JWT-Payload trägt "username" separat
    # von "sub" (welches die user_id-UUID ist) — dafür gehen wir gegen
    # username, nicht sub.
    username = user.get("username") or user.get("sub")
    if not username:
        raise HTTPException(401, "Ungültiger Token")
    pool = _get_pool()
    async with pool.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT password_hash, role FROM users WHERE username = $1",
            username,
        )
    if not row or not row["password_hash"]:
        raise HTTPException(403, "Re-Auth fehlgeschlagen")
    if not checkpw(password.encode(), row["password_hash"].encode()):
        raise HTTPException(403, "Passwort falsch")
    if row["role"] != "admin":
        raise HTTPException(403, "Nur Admins dürfen rebooten")

    # Privileged Side-Container mit --pid=host startet shutdown -r +1.
    # nsenter ist im alpine-Image nicht drin, deshalb util-linux nachziehen.
    # +1 = 60 s Gnade — Frontend kann eine Countdown-UI rendern und der
    # User kann mit `shutdown -c` am Host noch abbrechen wenn nötig.
    subprocess.Popen(
        [
            "docker", "run", "--rm", "-d",
            "--privileged", "--pid=host",
            "--name", "ids-host-reboot",
            "busybox:stable",
            "sh", "-c",
            # nsenter wechselt in die PID-1-Mount/PID/UTS-Namespaces des Hosts
            # und ruft dort den shutdown-Binary auf.
            "nsenter -t 1 -m -u -i -p -- /sbin/shutdown -r +1 'Cyjan: Host-Migration-Reboot'",
        ],
        start_new_session=True, close_fds=True,
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        env={**os.environ},
    )
    return {"status": "rebooting", "delay_seconds": 60}
