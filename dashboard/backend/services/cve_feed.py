"""CVE Auto-Patch (2026-09-22): poll NVD for recently-modified CVEs and
match them against origins' self-declared tech_stack_tags. No real
fingerprinting -- that's explicitly out of scope (unreliable at this
project's scale); tags are admin-set free text.

Two halves, deliberately separate (same split that worked for
build_incident_timeline in api/ai_summary.py):
  - fetch_recent_cves(): the one network call, isolated so it can fail
    (timeout, 403, malformed response) without ever raising into the
    caller -- an empty list is the worst case, never a 500.
  - match_cves_to_origins(): pure, no network, no Gemini -- this is the
    actual feature and where every test in test_cve_auto_patch.py lives.

Built directly against a real NVD API 2.0 response (fetched live
2026-09-22: cpeMatch criteria strings, affected[].affectedData[], English
descriptions, cvssMetricV31/V30/V2 in that preference order) -- not a
remembered schema.
"""
import asyncio
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD's own documented max window for an incremental (lastModStartDate/
# lastModEndDate) query.
NVD_MAX_WINDOW_DAYS = 120
# Unauthenticated NVD limit is ~5 requests per rolling 30s, so searches are
# spaced out and capped: 5 terms * 6.5s keeps one scan under ~35s.
NVD_REQUEST_GAP_SECONDS = 6.5
NVD_MAX_SEARCH_TERMS = 5
DEFAULT_WINDOW_DAYS = 14
# Per-keyword cache: the origin page reads matches on every open, and NVD's
# data for a 14-day window barely moves within hours.
KEYWORD_CACHE_TTL_SECONDS = 6 * 3600
_keyword_cache: Dict[Tuple[str, int], Tuple[float, List[Dict[str, Any]]]] = {}
_nvd_lock = asyncio.Lock()


def _extract_cve_keywords(cve: Dict[str, Any]) -> Set[str]:
    """Vendor/product keywords from BOTH shapes seen in a real live
    response: configurations[].nodes[].cpeMatch[].criteria (a
    "cpe:2.3:<part>:<vendor>:<product>:..." string) and the newer
    affected[].affectedData[].vendor/product fields. A CVE with neither
    populated yields no keywords and therefore matches nothing -- fail
    closed, never guess from the free-text description alone."""
    keywords: Set[str] = set()

    for config in cve.get("configurations", []) or []:
        for node in config.get("nodes", []) or []:
            for cpe_match in node.get("cpeMatch", []) or []:
                criteria = cpe_match.get("criteria", "")
                parts = criteria.split(":")
                # cpe:2.3:<part>:<vendor>:<product>:...
                if len(parts) > 4 and parts[0] == "cpe":
                    vendor, product = parts[3], parts[4]
                    if vendor and vendor != "*":
                        keywords.add(vendor.lower())
                    if product and product != "*":
                        keywords.add(product.lower())

    for affected in cve.get("affected", []) or []:
        for affected_data in affected.get("affectedData", []) or []:
            vendor = str(affected_data.get("vendor", "")).strip().lower()
            product = str(affected_data.get("product", "")).strip().lower()
            if vendor and vendor != "n/a":
                keywords.add(vendor)
            if product and product != "n/a":
                keywords.add(product)

    return keywords


def _english_description(cve: Dict[str, Any]) -> str:
    for d in cve.get("descriptions", []) or []:
        if d.get("lang") == "en":
            return d.get("value", "")
    return ""


def _severity_and_score(cve: Dict[str, Any]) -> Tuple[str, Optional[float]]:
    """Prefers the newest CVSS version present, same preference order NVD
    itself displays (v3.1 > v3.0 > v2)."""
    metrics = cve.get("metrics", {}) or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if entries:
            data = entries[0].get("cvssData", {}) or {}
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity") or "UNKNOWN"
            return severity, data.get("baseScore")
    return "UNKNOWN", None


def match_cves_to_origins(
    vulnerabilities: List[Dict[str, Any]],
    origins: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Pure, no network, no Gemini. Matches each CVE's vendor/product
    keywords against each origin's tech_stack_tags -- case-insensitive
    substring match in either direction, so a tag "nginx" matches keyword
    "nginx" and a tag "php 8.1" still matches keyword "php". One match per
    (cve, origin) pair even if several tags would match."""
    matches: List[Dict[str, Any]] = []

    for vuln in vulnerabilities:
        cve = vuln.get("cve", {}) or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue

        keywords = _extract_cve_keywords(cve)
        if not keywords:
            continue

        severity, score = _severity_and_score(cve)
        description = _english_description(cve)

        for origin in origins:
            tags = origin.get("tech_stack_tags") or []
            for tag in tags:
                tag_clean = str(tag).strip().lower()
                if not tag_clean:
                    continue
                if any(tag_clean in kw or kw in tag_clean for kw in keywords):
                    matches.append({
                        "cve_id": cve_id,
                        "origin_id": origin.get("id"),
                        "origin_label": origin.get("label", ""),
                        "matched_tag": tag,
                        "severity": severity,
                        "cvss_score": score,
                        "description": description[:500],
                        "published": cve.get("published"),
                        "last_modified": cve.get("lastModified"),
                    })
                    break  # next origin -- one match per (cve, origin) is enough

    return matches


def select_search_terms(origins: List[Dict[str, Any]]) -> Tuple[List[str], List[str]]:
    """The NVD keyword to search for each distinct tech_stack_tag, as
    (searched, skipped). Only the tag's first word is used ("php 8.1" ->
    "php"): keywordSearch ANDs every word against the CVE description, and a
    version like "8.1" rarely appears there. match_cves_to_origins() still
    does the precise tag-vs-CPE comparison afterwards. Terms beyond
    NVD_MAX_SEARCH_TERMS are returned in `skipped` so the caller can say so
    instead of silently ignoring them."""
    terms: List[str] = []
    for origin in origins:
        for tag in origin.get("tech_stack_tags") or []:
            words = str(tag).strip().lower().split()
            if words and words[0] not in terms:
                terms.append(words[0])
    return terms[:NVD_MAX_SEARCH_TERMS], terms[NVD_MAX_SEARCH_TERMS:]


async def fetch_recent_cves(keywords: List[str], days: int = DEFAULT_WINDOW_DAYS) -> List[Dict[str, Any]]:
    """One NVD request per keyword (keywordSearch + lastMod window), results
    de-duplicated by CVE id. A single unfiltered request returned only the
    first 200 of thousands of recently-modified CVEs, so most real products
    never appeared. Results are cached per (keyword, window) for
    KEYWORD_CACHE_TTL_SECONDS, and requests are serialised under one lock so
    concurrent page loads cannot exceed NVD's rate limit. Any failure
    (timeout, non-200, malformed JSON) skips that keyword and is not cached --
    callers must never 500 because an external API had a bad moment."""
    window_days = min(max(days, 1), NVD_MAX_WINDOW_DAYS)
    found: Dict[str, Dict[str, Any]] = {}
    async with _nvd_lock:
        fetched_any = False
        async with httpx.AsyncClient(timeout=20.0) as client:
            for keyword in keywords:
                cached = _keyword_cache.get((keyword, window_days))
                if cached and time.monotonic() - cached[0] < KEYWORD_CACHE_TTL_SECONDS:
                    vulns = cached[1]
                else:
                    if fetched_any:
                        await asyncio.sleep(NVD_REQUEST_GAP_SECONDS)
                    fetched_any = True
                    vulns = await _fetch_keyword(client, keyword, window_days)
                    if vulns is None:
                        continue
                    _keyword_cache[(keyword, window_days)] = (time.monotonic(), vulns)
                for vuln in vulns:
                    cve_id = (vuln.get("cve") or {}).get("id")
                    if cve_id:
                        found.setdefault(cve_id, vuln)
    return list(found.values())


async def _fetch_keyword(client: httpx.AsyncClient, keyword: str, window_days: int) -> Optional[List[Dict[str, Any]]]:
    """One NVD request; None on any failure. lastModStartDate/lastModEndDate
    is mandatory for an incremental query."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=window_days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
        "keywordSearch": keyword,
    }
    try:
        res = await client.get(NVD_BASE_URL, params=params, headers={"User-Agent": "waf-project-cve-auto-patch/1.0"})
        if res.status_code != 200:
            logger.warning(f"NVD API returned {res.status_code} for keyword {keyword!r}")
            return None
        data = res.json()
    except Exception as e:
        logger.error(f"Failed to fetch CVE feed from NVD for {keyword!r}: {e}")
        return None
    vulns = data.get("vulnerabilities", []) or []
    if data.get("totalResults", len(vulns)) > len(vulns):
        logger.warning(f"NVD keyword {keyword!r}: {data['totalResults']} results, only first {len(vulns)} read")
    return vulns
