"""The BOLA guard was removed (it never sat in the request path and could not
verify a customer app's tokens). Its API must be gone, not left half-working."""
from fastapi.testclient import TestClient

import main


def test_bola_endpoints_are_gone():
    client = TestClient(main.app)
    paths = main.app.openapi()["paths"]
    assert not any("/bola" in p for p in paths)
    for method, path in (("GET", "/api/rules/bola/policies"), ("POST", "/api/rules/bola/inspect"),
                         ("PUT", "/api/rules/bola/policies/p1"), ("DELETE", "/api/rules/bola/policies/p1")):
        assert client.request(method, path).status_code in (404, 405), (method, path)


def test_bola_guard_module_is_gone():
    import importlib.util
    assert importlib.util.find_spec("services.bola_guard") is None
