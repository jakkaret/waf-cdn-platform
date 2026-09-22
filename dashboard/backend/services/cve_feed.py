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
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

logger = logging.getLogger(__name__)

NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# NVD's own documented max window for an incremental (lastModStartDate/
# lastModEndDate) query.
NVD_MAX_WINDOW_DAYS = 120


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


async def fetch_recent_cves(days: int = 7) -> List[Dict[str, Any]]:
    """One request, never a loop over pages -- NVD's unauthenticated rate
    limit is roughly 5 requests per 30s, and a scan is meant to run at
    most a few times a day. lastModStartDate/lastModEndDate is mandatory
    for an incremental query. Any failure (timeout, non-200, malformed
    JSON) returns an empty list rather than raising -- the caller (the
    /cve-scan endpoint) must never 500 because an external API had a bad
    moment."""
    window_days = min(max(days, 1), NVD_MAX_WINDOW_DAYS)
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=window_days)
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "lastModEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
        "resultsPerPage": 200,
    }
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            res = await client.get(
                NVD_BASE_URL, params=params,
                headers={"User-Agent": "waf-project-cve-auto-patch/1.0"},
            )
            if res.status_code != 200:
                logger.warning(f"NVD API returned {res.status_code}")
                return []
            data = res.json()
            return data.get("vulnerabilities", []) or []
    except Exception as e:
        logger.error(f"Failed to fetch CVE feed from NVD: {e}")
        return []
