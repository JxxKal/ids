"""No-Write-Garantie: alles außer get/exec-Whitelist muss raisen —
bevor irgendein Transport angefasst wird."""
from __future__ import annotations

import pytest

from fmg.client import FmgClient, FmgWriteBlocked
from fmg.transport import FixtureTransport


class ExplodingTransport(FixtureTransport):
    """Raist bei jedem send() — beweist, dass der Guard vorher greift."""
    async def send(self, payload: dict) -> dict:
        raise AssertionError("Transport wurde trotz Write-Guard aufgerufen!")


@pytest.fixture
def client() -> FmgClient:
    return FmgClient(ExplodingTransport(), auth_mode="token")


@pytest.mark.parametrize("method", ["add", "set", "update", "delete", "move",
                                    "clone", "replace", "install"])
async def test_write_methods_blocked(client: FmgClient, method: str):
    with pytest.raises(FmgWriteBlocked):
        await client.rpc(method, "/pm/config/adom/root/obj/firewall/address",
                         {"name": "evil"})


@pytest.mark.parametrize("url", [
    "/securityconsole/install/package",
    "/dvmdb/adom/root/workspace/commit",
    "/sys/reboot",
    "/pm/config/adom/root/pkg/p/firewall/policy",
])
async def test_exec_foreign_urls_blocked(client: FmgClient, url: str):
    with pytest.raises(FmgWriteBlocked):
        await client.rpc("exec", url, {})


@pytest.mark.parametrize("action", ["post", "put", "delete", None, "exec"])
async def test_proxy_non_get_actions_blocked(client: FmgClient, action):
    data = {"action": action, "resource": "/api/v2/cmdb/firewall/policy",
            "target": ["adom/root/device/fgt1"]}
    with pytest.raises(FmgWriteBlocked):
        await client.rpc("exec", "/sys/proxy/json", data)


async def test_get_passes_guard(client: FmgClient):
    """get kommt durch den Guard (und scheitert erst an der fehlenden Fixture
    — hier am ExplodingTransport, was den Durchlass beweist)."""
    with pytest.raises(AssertionError):
        await client.rpc("get", "/dvmdb/adom")


async def test_proxy_get_passes_guard(client: FmgClient):
    data = {"action": "get", "resource": "/api/v2/monitor/router/lookup?vdom=root",
            "target": ["adom/root/device/fgt1"]}
    with pytest.raises(AssertionError):
        await client.rpc("exec", "/sys/proxy/json", data)
