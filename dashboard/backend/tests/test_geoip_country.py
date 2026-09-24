"""
Scenario: the country recorded for a request is the client's, not a guess.

access_logs.country used to be a fabricated value: ingestion defaulted it to
"TH", and the CDN path took it from the *edge node's* region rather than from
the client. 100% of ~111k rows said TH, so the dashboard's Geographic
Distribution panel could only ever show one country. The country is now
resolved from the client IP against a local .mmdb database
(services/geoip.py). These tests pin the properties that matter:

* it comes from the client IP, whatever edge the request landed on;
* an address that has no country (private, malformed, unknown) yields "",
  never a made-up value -- analytics already leaves '' out of the breakdown;
* a missing or broken database degrades to "" and never raises, because log
  ingestion must not fail on a lookup.

A real .mmdb is not shipped in the repo (it is a monthly-refreshed download),
so the reader is faked at the boundary; the module's own logic -- address
validation, private-range skipping, record parsing, failure handling -- is
what runs.
"""
import pytest

import services.geoip as geoip


class _FakeReader:
    def __init__(self, table):
        self.table = table
        self.lookups = []

    def get(self, ip):
        self.lookups.append(ip)
        return self.table.get(ip)


@pytest.fixture()
def reader(monkeypatch):
    fake = _FakeReader(
        {
            # Real public addresses on purpose: the RFC 5737 documentation
            # ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) are not
            # "global", so geoip.country_code() rightly returns before any
            # lookup and a test using them would pass for the wrong reason.
            "8.8.8.8": {"country": {"iso_code": "US"}},
            "1.1.1.1": {"country": {"iso_code": "th"}},  # lowercase in the file
            "9.9.9.9": {"continent": {"code": "AS"}},  # no country (anonymous/satellite)
            "4.4.4.4": {"country": {"iso_code": "TOOLONG"}},
        }
    )
    geoip.reset_for_tests()
    monkeypatch.setattr(geoip, "_get_reader", lambda: fake)
    return fake


def test_public_ip_resolves_to_its_own_country(reader):
    assert geoip.country_code("8.8.8.8") == "US"


def test_code_is_normalised_to_uppercase(reader):
    assert geoip.country_code("1.1.1.1") == "TH"


def test_record_without_a_country_is_blank_not_guessed(reader):
    assert geoip.country_code("9.9.9.9") == ""


def test_malformed_code_is_rejected(reader):
    assert geoip.country_code("4.4.4.4") == ""


@pytest.mark.parametrize(
    "ip",
    ["10.0.0.5", "172.18.0.2", "192.168.1.10", "127.0.0.1", "169.254.1.1", "::1", "fd00::1"],
)
def test_private_and_local_addresses_have_no_country_and_are_not_looked_up(reader, ip):
    # docker-internal hops and edge-to-Main traffic land here; they must not
    # be attributed to any country, and must not cost a database read.
    assert geoip.country_code(ip) == ""
    assert reader.lookups == []


@pytest.mark.parametrize("bad", [None, "", "   ", "not-an-ip", "999.1.1.1", "8.8.8"])
def test_garbage_input_is_blank_and_never_raises(reader, bad):
    assert geoip.country_code(bad) == ""


def test_unknown_public_ip_is_blank(reader):
    assert geoip.country_code("5.5.5.5") == ""


def test_missing_database_degrades_to_blank(monkeypatch, tmp_path):
    geoip.reset_for_tests()
    monkeypatch.setenv("GEOIP_DB_PATH", str(tmp_path / "does-not-exist.mmdb"))
    assert geoip.country_code("8.8.8.8") == ""
    # ...and repeated calls do not retry the failing open every time.
    assert geoip.country_code("8.8.4.4") == ""


def test_reader_that_raises_on_lookup_degrades_to_blank(monkeypatch):
    class _Boom:
        def get(self, ip):
            raise RuntimeError("corrupt database")

    geoip.reset_for_tests()
    monkeypatch.setattr(geoip, "_get_reader", lambda: _Boom())
    assert geoip.country_code("8.8.8.8") == ""


# --- flag ------------------------------------------------------------------


def test_flag_emoji_for_a_real_code():
    assert geoip.flag_emoji("TH") == "\U0001F1F9\U0001F1ED"
    assert geoip.flag_emoji("us") == "\U0001F1FA\U0001F1F8"


@pytest.mark.parametrize("bad", ["", None, "T", "THA", "1A"])
def test_flag_emoji_falls_back_to_globe(bad):
    assert geoip.flag_emoji(bad) == "\U0001F310"


# --- the write paths --------------------------------------------------------


def test_clickhouse_row_uses_the_client_ip_not_a_default(reader):
    from services.clickhouse_service import ClickHouseService

    svc = ClickHouseService.__new__(ClickHouseService)  # no live connection needed
    row = svc._build_access_log_row(
        {"ip": "8.8.8.8", "url": "/", "status": 200, "edge_node": "edge-th"}
    )
    country = row[svc.ACCESS_LOG_COLUMNS.index("country")]
    assert country == "US", "must follow the client, not the edge node it arrived through"


def test_clickhouse_row_for_private_client_is_blank_not_TH(reader):
    from services.clickhouse_service import ClickHouseService

    svc = ClickHouseService.__new__(ClickHouseService)
    row = svc._build_access_log_row({"ip": "172.18.0.6", "url": "/", "status": 403, "edge_node": "edge-th"})
    assert row[svc.ACCESS_LOG_COLUMNS.index("country")] == ""


def test_cdn_normalizer_no_longer_derives_country_from_the_edge_region(reader):
    from services.cdn_log_forward import normalize_cdn_access

    from_us = normalize_cdn_access({"remote_addr": "8.8.8.8", "status": "200"}, "th")
    from_th = normalize_cdn_access({"remote_addr": "1.1.1.1", "status": "200"}, "th")
    # Same edge region, different clients -> different countries. Under the
    # old code both were "TH".
    assert from_us["country"] == "US"
    assert from_th["country"] == "TH"
    assert from_us["edge_node"] == from_th["edge_node"] == "edge-th"


def test_documentation_ranges_are_not_treated_as_lookups(reader):
    # Regression guard for the fixture mistake above: an RFC 5737 address is
    # not global, so it must return blank without touching the database.
    assert geoip.country_code("203.0.113.5") == ""
    assert reader.lookups == []
