"""F-046/F-106: a failed health probe must report the node as degraded,
including the central MAIN node (it used to be forced to "online")."""
import asyncio

from api import cdn


class _FailingClient:
    async def get(self, url):
        raise ConnectionError("down")


class _OkClient:
    class _R:
        status_code = 200

    async def get(self, url):
        return self._R()


def test_main_node_reports_degraded_when_probe_fails():
    r = asyncio.run(cdn._check_node("MAIN", cdn.REGIONS_META["MAIN"], _FailingClient()))
    assert r["online"] is False and r["status"] == "degraded"


def test_main_node_reports_healthy_when_probe_succeeds():
    r = asyncio.run(cdn._check_node("MAIN", cdn.REGIONS_META["MAIN"], _OkClient()))
    assert r["online"] is True and r["status"] == "healthy"


def test_public_snapshot_degrades_when_main_is_down():
    from services.public_status import build_public_snapshot
    down = asyncio.run(cdn._check_node("MAIN", cdn.REGIONS_META["MAIN"], _FailingClient()))
    snap = build_public_snapshot({"MAIN": down})
    assert snap["overall_status"] == "degraded"
