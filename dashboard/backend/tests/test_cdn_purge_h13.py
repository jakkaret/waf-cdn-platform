"""H13: the dead cdn/purge-api service stays gone. Purge itself now works
through the edges' rulesync (services/cdn_purge.py, tests/test_cdn_purge.py);
until 2026-10-26 the endpoint answered 501."""
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[3]


def test_purge_api_service_removed():
    assert not (REPO / "cdn" / "purge-api").exists()
    assert "purge-api" not in (REPO / "cdn" / "docker-compose-cdn.yml").read_text(encoding="utf-8")
