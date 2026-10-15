"""F-019: the internal ML relay is gated by a secret from ML_RELAY_SECRET.

The header value used to be the constant "nginx-shadow-v1" in the public
repo, and every request behind Caddy/nginx comes from 172.16.0.0/12, so the
gate let internet callers in. Now: no secret configured = relay closed, and
the old public value never passes.
"""
from types import SimpleNamespace

import pytest

from api import ml

SECRET = "a" * 64
INTERNAL_IP = "172.18.0.1"


def _request(header=None, host=INTERNAL_IP):
    headers = {} if header is None else {ml.INTERNAL_RELAY_HEADER: header}
    return SimpleNamespace(headers=headers, client=SimpleNamespace(host=host))


@pytest.fixture
def secret(monkeypatch):
    monkeypatch.setattr(ml, "INTERNAL_RELAY_SECRET", SECRET)


def test_correct_secret_from_docker_network_passes(secret):
    assert ml._is_internal_relay_request(_request(SECRET)) is True


def test_old_public_value_is_rejected(secret):
    assert ml._is_internal_relay_request(_request("nginx-shadow-v1")) is False


def test_missing_or_wrong_header_is_rejected(secret):
    assert ml._is_internal_relay_request(_request()) is False
    assert ml._is_internal_relay_request(_request(SECRET[:-1])) is False


def test_outside_docker_network_is_rejected(secret):
    assert ml._is_internal_relay_request(_request(SECRET, host="203.0.113.5")) is False


@pytest.mark.parametrize("header", [None, "", "nginx-shadow-v1"])
def test_unset_secret_closes_the_relay(monkeypatch, header):
    monkeypatch.setattr(ml, "INTERNAL_RELAY_SECRET", "")
    assert ml._is_internal_relay_request(_request(header)) is False


def test_no_relay_value_left_in_source():
    from pathlib import Path

    src = Path(ml.__file__).read_text()
    assert "nginx-shadow-v1" not in src
