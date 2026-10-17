"""Re-audit 2026-10-17: the tenant column of a ModSecurity row comes from the
Host header only; a visitor's X-Forwarded-Host cannot attribute it elsewhere."""
from services.log_forward import normalize_modsec


def _tx(headers):
    return {"transaction": {"client_ip": "203.0.113.9", "time_stamp": "Sat Oct 17 10:00:00 2026",
                            "request": {"method": "GET", "uri": "/x", "headers": headers},
                            "response": {"http_code": 403}, "messages": []}}


def test_host_header_wins():
    assert normalize_modsec(_tx({"Host": "mine.example", "X-Forwarded-Host": "victim.example"}))["host"] == "mine.example"


def test_x_forwarded_host_is_never_used():
    assert normalize_modsec(_tx({"X-Forwarded-Host": "victim.example"}))["host"] in (None, "", "-")
