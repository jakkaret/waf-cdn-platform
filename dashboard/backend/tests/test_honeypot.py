"""Honeypot behaviour capture (services/honeypot.py, api/honeypot.py,
migration 0023, 2026-10-28): what one visitor did inside a site's decoys,
grouped into sessions, alerted on, and shown to the site's team only."""
import asyncio
import datetime as dt
import os
import urllib.parse

import pytest

os.environ.setdefault("DECEPTION_INTERNAL_KEY", "test-deception-internal-key")

from api import deception as deception_api
from api import honeypot as honeypot_api
from db import pool
from services import daily_digest, deception_content, honeypot, tenant_service
from services.deception_service import DeceptionService

HOST = "shop.example.com"
KEY = os.environ["DECEPTION_INTERNAL_KEY"]
SCANNER_UA = "Mozilla/5.0 (compatible; Nuclei - Open-source project (github.com/projectdiscovery/nuclei))"


@pytest.fixture(autouse=True)
def _routers(client):
    client.app.include_router(deception_api.router)
    client.app.include_router(honeypot_api.router)


@pytest.fixture()
def team(client, register_user, auth_header):
    register_user(email="hp-support@example.com", username="hp_support")  # first account = operator
    owner = register_user(email="hp-owner@example.com", username="hp_owner")
    editor = register_user(email="hp-editor@example.com", username="hp_editor")
    viewer = register_user(email="hp-viewer@example.com", username="hp_viewer")
    stranger = register_user(email="hp-stranger@example.com", username="hp_stranger")
    h = {k: auth_header(u["access_token"]) for k, u in
         (("owner", owner), ("editor", editor), ("viewer", viewer), ("stranger", stranger))}
    oid = client.post("/api/origins", json={"label": "shop", "ip": "203.0.113.70", "port": 80}, headers=h["owner"]).json()["id"]
    for u, role in ((editor, "editor"), (viewer, "viewer")):
        pool.exec_("INSERT INTO origin_members (origin_id, user_id, role) VALUES (%s, %s, %s)", (oid, u["user"]["user_id"], role))
    tenant_service._TENANT_CACHE.clear()
    return oid, h


@pytest.fixture()
def store(monkeypatch, team):
    """An in-memory honeypot_events table, and HOST attributed to the team's site."""
    oid, _ = team
    rows = []
    monkeypatch.setattr(honeypot, "origin_for_host", lambda h: oid if deception_content.normalize_host(h) == HOST else "")
    monkeypatch.setattr(deception_api.deception_service, "log_honeypot_event", lambda e: rows.append(e))
    monkeypatch.setattr(honeypot, "fetch_events",
                        lambda origin_id, since, until=None, limit=20000: [r for r in rows if r["origin_id"] == origin_id])
    sent = []

    async def _notify(event):
        sent.append(event)
        return True
    monkeypatch.setattr(honeypot, "notify", _notify)
    return rows, sent


def _hit(client, uri, ip="198.51.100.20", ua=SCANNER_UA, method="GET", body=b"", content_type="", peer="10.88.0.2"):
    headers = {"X-Internal-Deception-Key": KEY, "X-Original-URI": uri, "X-Original-Method": method,
               "X-Real-IP": ip, "X-Original-Host": HOST, "User-Agent": ua, "X-Edge-Peer": peer}
    if content_type:
        headers["Content-Type"] = content_type
    r = client.post("/api/deception/respond", content=body, headers=headers)
    assert r.status_code == 200, r.text
    return r


# ---------------------------------------------------------------- pure logic

def test_actor_tool_and_stage():
    a = honeypot.actor_id(HOST, "198.51.100.1", "curl/8.0")
    assert a == honeypot.actor_id("SHOP.example.com.", "198.51.100.1", "curl/8.0") and len(a) == 16
    assert a != honeypot.actor_id(HOST, "198.51.100.2", "curl/8.0")
    assert a != honeypot.actor_id("other.example.com", "198.51.100.1", "curl/8.0")
    assert honeypot.tool_for("sqlmap/1.8#stable (https://sqlmap.org)") == "sqlmap"
    assert honeypot.tool_for(SCANNER_UA) == "Nuclei"
    assert honeypot.tool_for("Mozilla/5.0 (X11) Chrome/120.0 Safari/537.36", "/wp-json/wp/v2/users") == "WordPress scanner"
    assert honeypot.tool_for("") == "No User-Agent"
    assert honeypot.stage_for("admin_panel") == "recon"
    assert honeypot.stage_for("admin_panel", "POST") == "exploit"
    assert honeypot.stage_for("sensitive_file") == "loot"
    assert honeypot.stage_for("sql_injection") == "exploit"
    assert honeypot.stage_for("admin_panel", "POST", login=True) == "exploit"
    assert honeypot.stage_for("honeytoken") == "credential_use"
    assert honeypot.stage_for("admin_panel", "POST", upload=True) == "persistence"


def test_login_keeps_no_password():
    got = honeypot.extract_login("log=administrator&pwd=Secret%2B123&wp-submit=Log+In",
                                 "application/x-www-form-urlencoded")
    assert got["user_masked"] == "ad******" and got["pass_len"] == len("Secret+123")
    assert "Secret" not in repr(got) and not got["pass_common"]
    assert got["pass_hash"] == honeypot.extract_login("log=x&pwd=Secret%2B123")["pass_hash"]
    assert honeypot.extract_login('{"email":"bob@example.com","password":"admin"}', "application/json") == {
        "user_masked": "b***@example.com", "user_hash": got_hash("bob@example.com"),
        "pass_hash": honeypot._mac("password", "admin", 24), "pass_len": 5, "pass_common": True}
    assert honeypot.extract_login("q=search", "application/x-www-form-urlencoded") is None
    assert honeypot.extract_login("", "") is None


def got_hash(user):
    return honeypot._mac("user", user, 16)


def _multipart(name="shell.php", data=b"<?php system($_GET['c']); ?>"):
    boundary = "----hpBoundary7"
    body = (f"--{boundary}\r\nContent-Disposition: form-data; name=\"pluginzip\"; filename=\"{name}\"\r\n"
            f"Content-Type: application/x-php\r\n\r\n").encode() + data + f"\r\n--{boundary}--\r\n".encode()
    return body, f"multipart/form-data; boundary={boundary}"


def test_upload_metadata():
    import hashlib
    body, ct = _multipart()
    up = honeypot.extract_upload(body, ct)
    assert up == {"name": "shell.php", "size": 28, "type": "application/x-php",
                  "sha256": hashlib.sha256(b"<?php system($_GET['c']); ?>").hexdigest()}
    assert honeypot.extract_upload(body, "text/plain") is None
    assert honeypot.extract_upload(b"garbage", "multipart/form-data; boundary=x") is None


def test_plus_encoded_form_sqli_is_classified():
    svc = DeceptionService.__new__(DeceptionService)
    got = svc.classify_attack(uri="/login", body="user=admin'+OR+1%3D1--+&pass=x")
    assert got.template_id == "sql_injection"


def _ev(actor, ts, stage="recon", ip="198.51.100.1", **kw):
    e = {"actor_id": actor, "timestamp": float(ts), "stage": stage, "client_ip": ip, "tool": "curl",
         "category": "", "edge_node": "edge-th", "tokens_issued": [], "token_replayed": "",
         "login_pass_hash": "", "login_pass_common": 0, "upload_sha256": ""}
    e.update(kw)
    return e


def test_sessions_split_on_gap_and_link_replays():
    t0 = 1_800_000_000
    evs = [_ev("a", t0), _ev("a", t0 + 60, "loot", tokens_issued=["aws_secret"]),
           _ev("a", t0 + 130 + honeypot.SESSION_GAP_SECONDS + 1),
           _ev("b", t0 + 3600, "credential_use", ip="203.0.113.9", token_replayed="aws_secret"),
           _ev("a", t0 + 120, "exploit", login_pass_hash="h1", login_pass_common=1),
           _ev("a", t0 + 130, "exploit", login_pass_hash="h1")]
    sessions = honeypot.sessionize(evs)
    assert len(sessions) == 3
    first = next(s for s in sessions if s["first_seen"] == t0)
    assert first["events"] == 4 and first["max_stage"] == "exploit"
    assert first["stages"] == ["recon", "loot", "exploit"]
    assert first["login_attempts"] == 2 and first["distinct_passwords"] == 1 and first["common_passwords"] == 1
    replay = next(s for s in sessions if s["actor_id"] == "b")
    assert replay["linked_from"] == [first["id"]]
    summary = honeypot.summarize_window(sessions, 3, now=t0 + 7200)
    assert summary["sessions"] == 3 and summary["unique_ips"] == 2
    assert summary["reached"]["recon"] == 3 and summary["reached"]["credential_use"] == 1
    assert sum(d["sessions"] for d in summary["per_day"]) == 3


def test_event_row_attribution_and_body_sample(monkeypatch):
    monkeypatch.setattr(honeypot, "origin_for_host", lambda h: "o-1")
    e = honeypot.build_event(
        request_id="r1", host=HOST, client_ip="198.51.100.5, 10.0.0.1", user_agent="curl/8.0", method="POST",
        uri="/wp-login.php?redirect_to=x", referer="", content_type="application/x-www-form-urlencoded",
        body="log=admin&pwd=hunter2", raw_body=b"log=admin&pwd=hunter2", template_id="admin_panel",
        category="Admin Probe", rule_id="3100001", response_body="", delay_seconds=0, edge_peer="10.88.0.3")
    assert set(e) == set(honeypot.COLUMNS)
    assert (e["origin_id"], e["edge_node"], e["client_ip"]) == ("o-1", "edge-asia", "198.51.100.5")
    assert e["stage"] == "exploit" and e["login_user"] == "ad***" and e["login_pass_len"] == 7
    assert "hunter2" not in e["body_sample"]
    assert honeypot.edge_for_peer("") == "unknown" and honeypot.edge_for_peer("203.0.113.1") == "main"


# ---------------------------------------------------------------- the whole story through the API

def test_an_attackers_session_reads_back_as_a_timeline(client, team, store):
    oid, h = team
    rows, sent = store
    site = deception_content.site_for(HOST)

    _hit(client, "/wp-admin/")
    loot = _hit(client, "/.env")
    assert site.tokens["db_password"] in loot.text
    _hit(client, "/wp-login.php", method="POST", body=b"log=admin&pwd=admin",
         content_type="application/x-www-form-urlencoded")
    body, ct = _multipart()
    _hit(client, "/wp-admin/update.php?action=upload-plugin", method="POST", body=body, content_type=ct)
    # The leaked password comes back from somewhere else.
    _hit(client, "/admin/login?pass=" + urllib.parse.quote(site.tokens["db_password"]), ip="203.0.113.99",
         ua="python-requests/2.31", peer="10.88.0.3")

    assert len(rows) == 5 and all(r["origin_id"] == oid for r in rows)
    assert [r["stage"] for r in rows] == ["recon", "loot", "exploit", "persistence", "credential_use"]
    assert rows[0]["edge_node"] == "edge-th" and rows[-1]["edge_node"] == "edge-asia"
    assert "db_password" in rows[1]["tokens_issued"]
    assert rows[-1]["token_replayed"] == "db_password"
    assert all("admin&pwd=admin" not in r["body_sample"] for r in rows)
    assert {e["stage"] for e in sent} == {"recon", "loot", "exploit", "persistence", "credential_use"}

    listed = client.get(f"/api/origins/{oid}/honeypot/sessions", headers=h["owner"]).json()
    assert listed["total"] == 2
    attacker = next(s for s in listed["sessions"] if s["tool"] == "Nuclei")
    replay = next(s for s in listed["sessions"] if s["tool"] == "python-requests")
    assert attacker["max_stage"] == "persistence" and attacker["uploads"][0]["name"] == "shell.php"
    assert replay["linked_from"] == [attacker["id"]] and replay["tokens_replayed"] == ["db_password"]
    assert "_events" not in attacker

    detail = client.get(f"/api/origins/{oid}/honeypot/sessions/{attacker['id']}", headers=h["editor"]).json()["session"]
    steps = detail["timeline"]
    assert [s["attack_id"] for s in steps] == ["T1595", "T1552", "T1190", "T1505.003"]
    assert steps[2]["login"] == {"user": "ad***", "password_length": 5, "common_password": True}
    assert steps[3]["upload"]["name"] == "shell.php"
    assert "login_pass_hash" not in steps[2]

    summary = client.get(f"/api/origins/{oid}/honeypot/summary?days=7", headers=h["owner"]).json()
    assert summary["sessions"] == 2 and summary["reached"]["persistence"] == 1

    story_in = honeypot_api.story_input(next(s for s in honeypot.sessionize(rows) if s["id"] == attacker["id"]))
    text = repr(story_in)
    assert "198.51.100.20" not in text and "pwd" not in text and story_in["mitre"]["persistence"] == "T1505.003"


def test_only_the_sites_owner_and_editors_see_it(client, team, store):
    oid, h = team
    _hit(client, "/.env")
    sid = client.get(f"/api/origins/{oid}/honeypot/sessions", headers=h["owner"]).json()["sessions"][0]["id"]
    for who in ("viewer", "stranger"):
        assert client.get(f"/api/origins/{oid}/honeypot/sessions", headers=h[who]).status_code in (403, 404)
        assert client.get(f"/api/origins/{oid}/honeypot/sessions/{sid}", headers=h[who]).status_code in (403, 404)
        assert client.post(f"/api/origins/{oid}/honeypot/sessions/{sid}/block", json={}, headers=h[who]).status_code in (403, 404)
    assert client.get(f"/api/origins/{oid}/honeypot/sessions/nope-1", headers=h["owner"]).status_code == 404


def test_block_every_ip_in_a_session(client, team, store, monkeypatch):
    oid, h = team
    rows, _ = store
    _hit(client, "/.env", ip="198.51.100.31")
    # Same actor id from a second address is a different actor; join them by hand.
    _hit(client, "/.git/config", ip="198.51.100.32")
    rows[1]["actor_id"] = rows[0]["actor_id"]
    sid = client.get(f"/api/origins/{oid}/honeypot/sessions", headers=h["owner"]).json()["sessions"][0]["id"]
    r = client.post(f"/api/origins/{oid}/honeypot/sessions/{sid}/block", json={"hours": 24}, headers=h["editor"])
    assert r.status_code == 200, r.text
    assert sorted(r.json()["added"]) == ["198.51.100.31", "198.51.100.32"]
    again = client.post(f"/api/origins/{oid}/honeypot/sessions/{sid}/block", json={"hours": 24}, headers=h["owner"]).json()
    assert again["added"] == [] and len(again["skipped"]) == 2
    listed = {x["ip"] for x in client.get(f"/api/origins/{oid}/ip-rules", headers=h["owner"]).json()["rules"]}
    assert {"198.51.100.31", "198.51.100.32"} <= listed
    audit = pool.q("SELECT summary FROM audit_logs WHERE scope_id = %s AND action = 'site_ip_rule.add'", (oid,))
    assert len(audit) == 2 and all("honeypot" in a["summary"] for a in audit)


# ---------------------------------------------------------------- alerts and digest

def test_alert_is_sent_once_per_actor_stage_and_hour(team, monkeypatch):
    oid, _ = team
    from services import notification_prefs, site_alerts
    from services import telegram_listener as tl
    messages = []

    async def _send(chats, text, buttons=None):
        messages.append((chats, text, buttons))
        return len(chats)
    monkeypatch.setattr(tl, "send_telegram", _send)
    monkeypatch.setattr(tl, "recipients_for", lambda origin_id, origin: [{"telegram_chat_id": "42"}])
    monkeypatch.setattr(notification_prefs, "filter_users", lambda users, origin, kind: users)
    monkeypatch.setattr(site_alerts, "_base_url", lambda: "https://waf.example")
    event = {"origin_id": oid, "actor_id": "a1", "stage": "credential_use", "host": HOST,
             "token_replayed": "db_password", "client_ip": "203.0.113.99", "tool": "curl",
             "method": "GET", "path": "/admin/<script>"}
    assert asyncio.run(honeypot.notify(event)) is True
    assert asyncio.run(honeypot.notify(event)) is False
    assert asyncio.run(honeypot.notify({**event, "stage": "recon"})) is False
    assert len(messages) == 1
    chats, text, buttons = messages[0]
    assert chats == ["42"] and "honeytoken" in text and "&lt;script&gt;" in text
    assert buttons == [("ดู Honeypot", f"https://waf.example/origins/{oid}?tab=honeypot")]


def test_digest_line_counts_sessions_and_depth():
    base = {"blocked": 0, "prev_blocked": 0, "ips": 0, "types": [], "incidents": 0, "outages": 0}
    assert "Honeypot" not in daily_digest.format_digest("shop", dt.date(2026, 10, 27), base)
    text = daily_digest.format_digest("shop", dt.date(2026, 10, 27), {
        **base, "honeypot": {"sessions": 3, "ips": 2, "loot": 2, "exploit": 1, "credential_use": 0, "persistence": 0}})
    assert "🍯 Honeypot 3 session จาก 2 IP (ได้ข้อมูลลับปลอม 2 · พยายามเจาะ 1)" in text


# ---------------------------------------------------------------- decoy probe

def test_probe_skips_tunnels_and_unsafe_targets(monkeypatch):
    assert honeypot_api.probe_decoy({"id": "x", "connection_mode": "agent", "is_tunnel": True}, "wp-login")["reason"] == "tunnel"
    assert honeypot_api.probe_decoy({"id": "x", "connection_mode": "direct", "ip": "127.0.0.1"}, "wp-login")["reason"] == "not_public"
    assert honeypot_api.probe_decoy({"id": "x", "connection_mode": "direct", "ip": "app.example.com"}, "wp-login")["reason"] == "hostname"


def test_probe_tells_a_real_page_from_a_catch_all(monkeypatch):
    from services import nginx_site_service
    monkeypatch.setattr(nginx_site_service, "direct_upstream_allowed", lambda ip: True)
    monkeypatch.setattr(honeypot_api, "_probe_host", lambda oid: HOST)
    seen = []

    def fake(answers):
        def _fetch(client, url, host, sni):
            seen.append((url, host))
            return answers["decoy"] if url.endswith("/wp-login.php") else answers["random"]
        return _fetch
    origin = {"id": "x", "connection_mode": "direct", "ip": "203.0.113.70", "port": 80, "origin_scheme": "http"}
    monkeypatch.setattr(honeypot_api, "_fetch", fake({"decoy": 200, "random": 404}))
    assert honeypot_api.probe_decoy(origin, "wp-login")["serves_path"] is True
    assert seen[0] == ("http://203.0.113.70:80/wp-login.php", HOST)
    monkeypatch.setattr(honeypot_api, "_fetch", fake({"decoy": 200, "random": 200}))  # SPA answers everything
    assert honeypot_api.probe_decoy(origin, "wp-login")["serves_path"] is False
    monkeypatch.setattr(honeypot_api, "_fetch", fake({"decoy": 404, "random": 404}))
    assert honeypot_api.probe_decoy(origin, "wp-login")["serves_path"] is False
    monkeypatch.setattr(honeypot_api, "_fetch", fake({"decoy": None, "random": None}))
    assert honeypot_api.probe_decoy(origin, "wp-login")["reason"] == "unreachable"


def test_incident_report_counts_the_windows_honeypot_sessions(monkeypatch):
    from api.ai_summary import build_incident_timeline
    t0 = dt.datetime(2026, 10, 27, 3, 0, tzinfo=dt.timezone.utc).timestamp()
    asked = {}

    def _fetch(origin_id, since, until=None, limit=20000):
        asked.update(origin=origin_id, since=since, until=until)
        return [_ev("a", t0), _ev("a", t0 + 60, "loot"), _ev("b", t0 + 120, "persistence", ip="198.51.100.9")]
    monkeypatch.setattr(honeypot, "fetch_events", _fetch)
    oid = "11111111-1111-1111-1111-111111111111"
    timeline = build_incident_timeline({"id": oid, "ip": "203.0.113.9"},
                                       dt.datetime(2026, 10, 27, 2, 0), dt.datetime(2026, 10, 27, 5, 0))
    assert timeline["stats"]["honeypot"] == {"sessions": 2, "ips": 2, "loot": 2, "exploit": 1,
                                             "credential_use": 1, "persistence": 1}
    assert asked == {"origin": oid, "since": dt.datetime(2026, 10, 27, 2, 0), "until": dt.datetime(2026, 10, 27, 5, 0)}
