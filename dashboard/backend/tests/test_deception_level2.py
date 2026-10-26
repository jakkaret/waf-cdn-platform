"""Deception layer level 2: per-site fake data, file targets, emulated MySQL
(error / UNION / boolean / time), command output, SSRF metadata, escaped XSS,
admin panels, and honeytokens that come back as a ModSecurity rule."""

import base64
import json
import os
import re

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

os.environ.setdefault("DECEPTION_INTERNAL_KEY", "test-deception-internal-key")

import api.deception as deception_api  # noqa: E402
from services import deception_content as dc  # noqa: E402
from services.deception_service import DeceptionService  # noqa: E402

HOST_A = "shop.example.com"
HOST_B = "blog.example.org"


@pytest.fixture()
def svc():
    return DeceptionService()


def gen(svc, uri, host=HOST_A, **kw):
    return svc.generate_response(uri=uri, host=host, **kw)


# ----------------------------------------------------------- per-site profile


def test_same_site_same_data_other_site_other_data(svc):
    a1 = gen(svc, "/download?file=../../etc/passwd").body
    a2 = gen(svc, "/download?file=../../etc/passwd").body
    b = gen(svc, "/download?file=../../etc/passwd", host=HOST_B).body
    assert a1 == a2
    assert a1 != b
    assert dc.site_for(HOST_A).tokens != dc.site_for(HOST_B).tokens


def test_host_spellings_share_one_profile():
    assert dc.site_for("Shop.Example.com.:443") is dc.site_for(HOST_A)


def test_profile_depends_on_the_key(monkeypatch):
    before = dc.site_for(HOST_A).tokens["db_password"]
    monkeypatch.setenv("DECEPTION_INTERNAL_KEY", "another-key")
    assert dc.site_for(HOST_A).tokens["db_password"] != before


def test_no_dummy_tells_anywhere(svc):
    for uri in ("/.env", "/backup.sql", "/items?id=1' OR 1=1-- -", "/download?file=../../etc/shadow"):
        assert "dummy" not in gen(svc, uri).body.lower()


# --------------------------------------------------------------- file targets


@pytest.mark.parametrize("uri,check", [
    ("/download?file=../../etc/shadow", lambda b: b.startswith("root:$6$")),
    ("/download?file=../../etc/hosts", lambda b: b.startswith("127.0.0.1\tlocalhost")),
    ("/download?file=../../../proc/self/environ", lambda b: "\x00DB_PASSWORD=" in b),
    ("/.env", lambda b: "DB_PASSWORD=" in b and "AWS_SECRET_ACCESS_KEY=" in b),
    ("/.git/HEAD", lambda b: b == "ref: refs/heads/main\n"),
    ("/.git/config", lambda b: '[remote "origin"]' in b),
    ("/.aws/credentials", lambda b: b.startswith("[default]\naws_access_key_id = AKIA")),
    ("/wp-config.php.bak", lambda b: "define( 'DB_PASSWORD'" in b),
    ("/.ssh/id_rsa", lambda b: b.startswith("-----BEGIN OPENSSH PRIVATE KEY-----")),
])
def test_file_targets(svc, uri, check):
    r = gen(svc, uri)
    assert r.template_id in ("path_traversal", "sensitive_file")
    assert check(r.body), r.body[:120]


def test_secrets_in_files_are_this_sites_honeytokens(svc):
    t = dc.site_for(HOST_A).tokens
    env = gen(svc, "/.env").body
    for kind in ("db_password", "aws_access_key_id", "aws_secret_access_key", "api_key", "app_key"):
        assert t[kind] in env


def test_executed_php_prints_nothing(svc):
    r = gen(svc, "/wp-config.php")
    assert r.template_id == "sensitive_file"
    assert r.body == ""


def test_backup_is_a_sql_dump_download(svc):
    r = gen(svc, "/backup-db")
    site = dc.site_for(HOST_A)
    assert r.template_id == "sensitive_file"
    assert r.body.startswith("-- MySQL dump")
    assert f"Database: {site.db_name}" in r.body
    assert r.headers["Content-Disposition"].startswith('attachment; filename="')
    assert "no-store" in r.headers["Cache-Control"]


def test_php_filter_returns_base64_source(svc):
    r = gen(svc, "/index.php?page=php://filter/convert.base64-encode/resource=config.php")
    assert base64.b64decode(r.body).startswith(b"<?php")


# ---------------------------------------------------------------- emulated SQL


def sql(svc, payload, **kw):
    r = gen(svc, "/api/items?id=" + payload, **kw)
    assert r.template_id == "sql_injection"
    return r, json.loads(r.body)


def test_unbalanced_quote_is_a_mysql_syntax_error(svc):
    _, data = sql(svc, "1'")
    assert data["status"] == "error"
    assert "You have an error in your SQL syntax" in data["error"]


def test_order_by_finds_the_column_count(svc):
    n = dc.site_for(HOST_A).ncols
    assert sql(svc, f"1' ORDER BY {n}-- -")[1]["status"] == "success"
    _, data = sql(svc, f"1' ORDER BY {n + 1}-- -")
    assert f"Unknown column '{n + 1}' in 'order clause'" in data["error"]


def test_union_reflects_literals_and_functions(svc):
    site = dc.site_for(HOST_A)
    items = ["0x716b7a6a71", "database()", "version()"] + ["NULL"] * (site.ncols - 3)
    _, data = sql(svc, "-1' UNION ALL SELECT " + ",".join(items) + "-- -")
    last = data["data"][-1]
    cols = site.columns
    assert last[cols[0]] == "qkzjq"
    assert last[cols[1]] == site.db_name
    assert last[cols[2]] == site.mysql_version


def test_union_concat_marker(svc):
    site = dc.site_for(HOST_A)
    items = ["CONCAT(0x7171,database(),0x7171)"] + ["NULL"] * (site.ncols - 1)
    _, data = sql(svc, "1' UNION ALL SELECT " + ",".join(items) + "-- -")
    assert data["data"][-1][site.columns[0]] == f"qq{site.db_name}qq"


def test_boolean_true_and_false_probes_differ(svc):
    _, true = sql(svc, "1' AND 4821=4821-- -")
    _, false = sql(svc, "1' AND 4821=4822-- -")
    assert true["count"] > 0
    assert false["count"] == 0


@pytest.mark.parametrize("payload,delay", [
    ("1' AND SLEEP(5)-- -", 5.0),
    ("1' AND (SELECT 1 FROM (SELECT(SLEEP(3)))a)-- -", 3.0),
    ("1'; WAITFOR DELAY '0:0:4'-- -", 4.0),
    ("1' AND pg_sleep(2)-- -", 2.0),
    ("1' AND SLEEP(600)-- -", dc.MAX_DELAY_SECONDS),
    ("1' AND 1=2 AND SLEEP(5)-- -", 0.0),
    ("1' AND 1=1-- -", 0.0),
])
def test_time_based_delay(svc, payload, delay):
    r, _ = sql(svc, payload)
    assert r.delay_seconds == delay


def test_html_clients_get_an_html_table(svc):
    r = gen(svc, "/products?id=1' OR 1=1-- -", headers={"Accept": "text/html,application/xhtml+xml"})
    assert r.content_type.startswith("text/html")
    assert "<table>" in r.body


def test_schema_enumeration_lists_tables(svc):
    site = dc.site_for(HOST_A)
    items = ["table_name"] + ["NULL"] * (site.ncols - 1)
    _, data = sql(svc, "1' UNION SELECT " + ",".join(items) + " FROM information_schema.tables-- -")
    assert "users" in [row[site.columns[1]] for row in data["data"]]


# --------------------------------------------------------- command injection


@pytest.mark.parametrize("payload,expected", [
    (";id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)"),
    ("|whoami", "www-data"),
    ("$(pwd)", "/var/www/html"),
])
def test_command_output(svc, payload, expected):
    r = gen(svc, "/ping?host=127.0.0.1" + payload)
    assert r.template_id == "command_injection"
    assert expected in json.loads(r.body)["output"]


def test_command_cat_reads_the_fake_file(svc):
    r = gen(svc, "/ping?host=x;cat%20/etc/passwd", headers={"Accept": "text/html"})
    assert "root:x:0:0:root" in r.body


def test_echo_reflects_only_safe_characters(svc):
    r = gen(svc, "/ping?host=x;echo%20<img/src=x>", headers={"Accept": "text/html"})
    assert "<img" not in r.body


# ---------------------------------------------------------------------- SSRF


def test_ssrf_metadata_hands_out_honeytoken_credentials(svc):
    site = dc.site_for(HOST_A)
    base = "/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    role = gen(svc, base).body
    assert role == f"{site.slug}-ec2-role"
    creds = json.loads(gen(svc, base + role).body)
    assert creds["AccessKeyId"] == site.tokens["aws_session_key_id"]
    assert creds["SecretAccessKey"] == site.tokens["aws_secret_access_key"]


def test_ssrf_to_other_internal_host_gets_default_page(svc):
    r = gen(svc, "/fetch?url=http://127.0.0.1:8080/admin")
    assert r.template_id == "ssrf"
    assert "Welcome to nginx!" in r.body


# ----------------------------------------------------------------------- XSS


def test_xss_payload_is_reflected_escaped(svc):
    r = gen(svc, "/search?q=<script>alert(document.domain)</script>")
    assert r.template_id == "xss"
    assert "<script>alert" not in r.body
    assert "&lt;script&gt;alert" in r.body


# --------------------------------------------------------------- admin panels


def test_admin_get_shows_login_post_lets_anyone_in(svc):
    form = gen(svc, "/wp-login.php")
    assert form.template_id == "admin_panel"
    assert 'name="pwd"' in form.body
    dash = gen(svc, "/wp-login.php", method="POST", body="log=admin&pwd=hunter2")
    assert "Dashboard" in dash.body
    assert "Set-Cookie" not in dash.headers


# ---------------------------------------------------------------- honeytokens


def test_replayed_honeytoken_is_recognised(svc):
    pw = dc.site_for(HOST_A).tokens["admin_password"]
    r = gen(svc, "/wp-login.php", method="POST", body=f"log=admin&pwd={pw}")
    assert r.template_id == "honeytoken"
    assert r.category == "Honeytoken Replay"


def test_honeytoken_in_authorization_header(svc):
    key = dc.site_for(HOST_A).tokens["api_key"]
    r = gen(svc, "/api/orders", headers={"Authorization": f"Bearer {key}"})
    assert r.template_id == "honeytoken"


def test_other_sites_token_is_not_this_sites_replay(svc):
    pw = dc.site_for(HOST_B).tokens["admin_password"]
    assert gen(svc, "/login", method="POST", body=f"password={pw}").template_id != "honeytoken"


def test_honeytoken_rule_lists_every_token_safely():
    rule = dc.honeytoken_rule([HOST_A, HOST_B, "bad host!"])
    tokens = re.search(r'"@pm ([^"]+)"', rule).group(1).split()
    expected = set(dc.honeytoken_values(dc.site_for(HOST_A))) | set(dc.honeytoken_values(dc.site_for(HOST_B)))
    assert set(tokens) == expected
    assert all(re.fullmatch(r"[A-Za-z0-9]+", t) and len(t) >= 11 for t in tokens)
    assert f"id:{dc.HONEYTOKEN_RULE_ID}," in rule
    assert "status:418" in rule and "tag:'action:deceive'" in rule


def test_honeytoken_rule_without_hosts_has_no_rule():
    assert "SecRule" not in dc.honeytoken_rule([])


# ------------------------------------------------------------------- endpoint


@pytest.fixture()
def client():
    app = FastAPI()
    app.include_router(deception_api.router)
    return TestClient(app)


def _headers(uri, host=HOST_A):
    return {
        deception_api.INTERNAL_DECEPTION_HEADER: os.environ["DECEPTION_INTERNAL_KEY"],
        "X-Original-URI": uri,
        "X-Original-Host": host,
        "X-Request-ID": "req-l2",
    }


def test_endpoint_uses_the_original_host(client):
    resp = client.get("/api/deception/respond", headers=_headers("/.env"))
    assert dc.site_for(HOST_A).tokens["db_password"] in resp.text


def test_endpoint_holds_time_based_answers(client, monkeypatch):
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(deception_api.asyncio, "sleep", fake_sleep)
    resp = client.get("/api/deception/respond", headers=_headers("/api/items?id=1' AND SLEEP(4)-- -"))
    assert resp.status_code == 200
    assert slept == [4.0]


def test_endpoint_does_not_hold_when_slots_are_full(client, monkeypatch):
    slept = []

    async def fake_sleep(seconds):
        slept.append(seconds)

    monkeypatch.setattr(deception_api.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(deception_api._delay_slots, "locked", lambda: True)
    client.get("/api/deception/respond", headers=_headers("/api/items?id=1' AND SLEEP(4)-- -"))
    assert slept == []


@pytest.mark.parametrize("body", ["log=admin&pwd=hunter2", "a=1&id=5&ls=2", "q=shoes&w=10"])
def test_query_parameters_named_like_commands_are_not_injection(svc, body):
    assert svc.classify_attack(uri="/form", body=body).template_id != "command_injection"
