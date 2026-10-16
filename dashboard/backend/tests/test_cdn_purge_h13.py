"""H13: purge is honestly unavailable (501) until the edges have a purge
endpoint; the dead cdn/purge-api service is gone."""
import pathlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from api import auth as auth_module, cdn as cdn_module
from services.rate_limiter import limiter

REPO = pathlib.Path(__file__).resolve().parents[3]


@pytest.fixture()
def client() -> TestClient:
    a = FastAPI()
    a.state.limiter = limiter
    a.include_router(auth_module.router)
    a.include_router(cdn_module.router)
    return TestClient(a)


def test_purge_returns_501_for_admin(client, register_user):
    admin = register_user(email="purge-admin@example.com", username="purge_admin")
    client.cookies.clear()
    r = client.post("/api/cdn/purge", params={"url": "/x"},
                    headers={"Authorization": f"Bearer {admin['access_token']}"})
    assert r.status_code == 501
    assert "not available" in r.json()["detail"]


def test_purge_api_service_removed():
    assert not (REPO / "cdn" / "purge-api").exists()
    assert "purge-api" not in (REPO / "cdn" / "docker-compose-cdn.yml").read_text(encoding="utf-8")
