"""Phase 5: input the PostgreSQL columns would refuse is a 422, not a 500."""
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _client(app: FastAPI) -> TestClient:
    from api import ip_rules, rate_limits
    app.include_router(ip_rules.router)
    app.include_router(rate_limits.router)
    return TestClient(app)


def test_rate_rule_validation(app, register_user, auth_header):
    client = _client(app)
    h = auth_header(register_user(email="p5-admin@example.com", username="p5_admin")["access_token"])
    bad_action = client.post("/api/rate-limits/rules", headers=h, json={
        "name": "x", "path_pattern": "/x", "limit_count": 5, "window_seconds": 60, "action": "drop"})
    assert bad_action.status_code == 422
    assert client.put("/api/rate-limits/rules/rule_global_api", headers=h,
                      json={"limit_count": 0}).status_code == 422


def test_ip_rule_validation(app, register_user, auth_header):
    client = _client(app)
    h = auth_header(register_user(email="p5-admin2@example.com", username="p5_admin2")["access_token"])
    assert client.post("/api/ip-rules/", headers=h, json={"ip": "1.2.3.4", "rule_type": "maybe"}).status_code == 422
    assert client.post("/api/ip-rules/", headers=h, json={"ip": "1.2.3.4", "source": "who"}).status_code == 422
