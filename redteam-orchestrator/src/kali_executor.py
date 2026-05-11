"""Bridge zur kali-shell via `docker exec -i`.

Sicherheits-Eigenschaften:
- Ein asyncio.Lock pro Executor — der veth darf nur in EINEM Namespace
  gleichzeitig leben. Concurrent run-Aufrufe serialisieren.
- subprocess.create_subprocess_exec mit args-Liste — NIE shell=True und
  NIE f-string-Konstruktion mit user-controlled-Werten.
- detach_iface läuft im finally-Block — auch bei Exception/Timeout
  kommt der veth zurück in den Default-Namespace.
- Pre-validate target_ip gegen ALLOWED_SRC_CIDRS BEVOR die Sequence
  überhaupt startet — Defense in Depth ggü. kali_runner-Side-Check.
"""
from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
from typing import Any

from config import settings

log = logging.getLogger(__name__)

RUNNER_PATH = "/opt/cyjan/kali_runner.py"


class KaliExecutionError(Exception):
    pass


class KaliExecutor:
    def __init__(self) -> None:
        self._iface_lock = asyncio.Lock()
        # Pre-parsed CIDR-Liste für schnellen Containment-Check
        self._allowed_nets = [ipaddress.ip_network(c) for c in settings.allowed_src_cidrs]

    def _validate_target_local(self, target_ip: str) -> None:
        try:
            addr = ipaddress.ip_address(target_ip)
        except ValueError as exc:
            raise KaliExecutionError(f"invalid target_ip: {target_ip}") from exc
        if not any(addr in net for net in self._allowed_nets):
            raise KaliExecutionError(
                f"target_ip {target_ip} not in ALLOWED_SRC_CIDRS "
                f"({', '.join(settings.allowed_src_cidrs)})"
            )

    async def _exec(self, *args: str) -> tuple[int, str, str]:
        """Sicherer subprocess-Helper — IMMER list-form, kein shell."""
        proc = await asyncio.create_subprocess_exec(
            *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await proc.communicate()
        return proc.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")

    async def _get_container_pid(self) -> int:
        rc, out, err = await self._exec(
            "docker", "inspect", "-f", "{{.State.Pid}}", settings.kali_container,
        )
        if rc != 0:
            raise KaliExecutionError(f"docker inspect failed: {err.strip()}")
        try:
            return int(out.strip())
        except ValueError as exc:
            raise KaliExecutionError(f"unable to parse PID: {out!r}") from exc

    # Peer-Name muss <16 Zeichen sein (Linux IFNAMSIZ). cy-inj-peer = 11.
    _PEER_IFACE     = "cy-inj-peer"
    _HOST_IP_CIDR   = "192.0.2.254/24"
    _KALI_IP_CIDR   = "192.0.2.1/24"

    async def setup_veth_pair_once(self) -> None:
        """Idempotent: erstellt veth-Pair, konfiguriert Host-Peer, schiebt
        kali-Seite in den kali-Namespace. Wird beim orchestrator-Startup
        einmal aufgerufen — nicht pro Tool-Run.

        Vorteil: cy-inj-peer ist persistent am Host → Sniffer kann
        kontinuierlich dort capture'n. Tool-Runs sind no-op auf dem Pair,
        die kali-Seite bleibt im kali-namespace.

        Idempotenz:
        - Pair existiert schon → ip link add wirft "File exists", ok
        - Host-Peer-IP existiert schon → ip addr add wirft "exists", ok
        - kali-Seite ist schon im kali-namespace → ip link set netns wirft
          "Device not found" weil iface aus Host-Sicht weg ist, ok"""
        # 1. Pair anlegen (idempotent)
        rc, _, err = await self._exec(
            "ip", "link", "add", settings.test_iface,
            "type", "veth", "peer", "name", self._PEER_IFACE,
        )
        pair_existed = rc != 0 and "exists" in err.lower()
        if rc != 0 and not pair_existed:
            log.error("veth-Pair-Creation failed: %s", err.strip())
            return

        # 2. Host-Peer konfigurieren (idempotent)
        await self._exec("ip", "addr", "add", self._HOST_IP_CIDR, "dev", self._PEER_IFACE)
        await self._exec("ip", "link", "set", self._PEER_IFACE, "up")

        # 3. kali-Seite ins kali-namespace (idempotent: wenn schon dort, fail = ok)
        pid = await self._get_container_pid()
        rc, _, err = await self._exec(
            "ip", "link", "set", settings.test_iface, "netns", str(pid),
        )
        if rc != 0 and "does not exist" not in err.lower():
            log.warning("link set netns failed (vielleicht schon im kali-ns?): %s", err.strip())

        # 4. IP + up im kali-namespace (idempotent)
        await self._exec(
            "nsenter", "-t", str(pid), "-n",
            "ip", "addr", "add", self._KALI_IP_CIDR, "dev", settings.test_iface,
        )
        await self._exec(
            "nsenter", "-t", str(pid), "-n",
            "ip", "link", "set", settings.test_iface, "up",
        )
        log.info("Veth-Pair %s↔%s persistent (kali-pid=%d, %s ↔ %s)",
                 settings.test_iface, self._PEER_IFACE, pid,
                 self._KALI_IP_CIDR, self._HOST_IP_CIDR)

    async def _attach_iface_unlocked(self) -> None:
        """No-op — veth ist persistent über setup_veth_pair_once eingerichtet.
        Tool-Run verifiziert nur die Existenz, damit ein verlorenes Pair
        (z.B. kali-Container restart) gleich beim ersten Run erkannt wird."""
        # Sanity: kali-Seite muss im kali-namespace sein, IP gesetzt
        pid = await self._get_container_pid()
        rc, _, _ = await self._exec(
            "nsenter", "-t", str(pid), "-n",
            "ip", "link", "show", settings.test_iface,
        )
        if rc != 0:
            # Pair verloren — re-setup einmal versuchen
            log.warning("Veth nicht im kali-ns sichtbar — re-setup")
            await self.setup_veth_pair_once()

    async def _detach_iface_unlocked(self) -> None:
        """No-op bei persistentem Setup — veth bleibt bestehen zwischen Runs."""
        pass

    async def run_with_iface(
        self, tool: str, target_ip: str, args: list[str], timeout_sec: int = 30,
        *, attach_iface: bool = True,
    ) -> dict[str, Any]:
        """Atomar: pre-validate + attach → exec → detach.
        Detach läuft IMMER im finally — auch bei Exception."""
        self._validate_target_local(target_ip)

        # Wenn attach_iface=false (z.B. für ping zu localhost-Tests oder
        # Self-Tests ohne veth) → Lock nicht nehmen, direkter exec.
        if not attach_iface:
            return await self._run_inner(tool, target_ip, args, timeout_sec)

        async with self._iface_lock:
            await self._attach_iface_unlocked()
            try:
                return await self._run_inner(tool, target_ip, args, timeout_sec)
            finally:
                await self._detach_iface_unlocked()

    async def _run_inner(
        self, tool: str, target_ip: str, args: list[str], timeout_sec: int,
    ) -> dict[str, Any]:
        cmd_json = json.dumps({
            "tool": tool, "target_ip": target_ip,
            "args": args, "timeout_sec": timeout_sec,
        }).encode()
        outer_timeout = int(timeout_sec * 1.5) + 10

        proc = await asyncio.create_subprocess_exec(
            "docker", "exec", "-i", settings.kali_container,
            "python3", RUNNER_PATH,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=cmd_json), timeout=outer_timeout,
            )
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise KaliExecutionError(f"docker exec outer timeout ({outer_timeout}s)")

        if proc.returncode == 3:
            # Validation-Fehler im kali-shell-Runner
            try:
                err_obj = json.loads(stdout.decode())
                msg = err_obj.get("message", "(no message)")
            except json.JSONDecodeError:
                msg = stderr.decode()[:200]
            raise KaliExecutionError(f"kali-shell rejected: {msg}")

        if proc.returncode not in (0, 1):
            raise KaliExecutionError(
                f"kali-shell exited unexpectedly: rc={proc.returncode}, "
                f"stderr={stderr.decode()[:200]}"
            )

        return json.loads(stdout.decode())
