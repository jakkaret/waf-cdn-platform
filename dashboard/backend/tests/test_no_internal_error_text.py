"""Re-audit 2026-10-17: a 500 never echoes internal exception text, even when
a route raises HTTPException(500, detail=str(e)) itself."""
from fastapi import HTTPException
from fastapi.testclient import TestClient


def test_http_500_detail_is_not_echoed():
    import main

    path = "/api/__test_internal_500"
    if not any(getattr(r, "path", None) == path for r in main.app.routes):
        async def _boom():
            raise HTTPException(status_code=500, detail="psycopg error at host db-internal:5432 table secret_x")
        main.app.add_api_route(path, _boom, methods=["GET"])
        # ahead of the SPA catch-all /{full_path:path}, which would answer 404
        main.app.router.routes.insert(0, main.app.router.routes.pop())

    r = TestClient(main.app).get(path)
    assert r.status_code == 500
    assert "secret_x" not in r.text and "db-internal" not in r.text
    assert r.json()["error"] == "Internal server error" and r.json()["ref"]


def test_deliberate_4xx_and_503_messages_kept():
    """Only 500s are rewritten; a 400/403/503 keeps its intended message."""
    import main
    for code, msg in ((400, "subject must be 1-200 characters"), (503, "ClickHouse unavailable")):
        path = f"/api/__test_keep_{code}"
        if not any(getattr(r, "path", None) == path for r in main.app.routes):
            async def _h(c=code, m=msg):
                raise HTTPException(status_code=c, detail=m)
            main.app.add_api_route(path, _h, methods=["GET"])
            main.app.router.routes.insert(0, main.app.router.routes.pop())
        r = TestClient(main.app).get(path)
        assert r.status_code == code and r.json()["detail"] == msg
