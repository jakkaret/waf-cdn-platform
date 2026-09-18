#!/usr/bin/env python3
"""Dependency vulnerability scanner for the WAF backend -- REPORT ONLY.

On every run it asks OSV.dev (the live open-source vulnerability database) about
the exact versions of the Python packages installed in this venv, so newly
published advisories are picked up automatically as they land. It also records
the running nginx / ModSecurity / CRS versions for manual review.

It NEVER changes a package, a rule, or any configuration. Acting on a finding is
a human decision -- the project rule is that security controls are not modified
automatically (same reason ML auto-block is off). Output: a timestamped JSON +
text report, and a one-line summary on stdout (which the systemd timer captures
into the journal).

Usage: python3 vuln_scan.py [--quiet]
Exit code: 0 always (a scanner that failed the job it is scheduled for should
not spam failure mail on a transient network blip); findings are in the report.
"""
import json, os, subprocess, sys, urllib.request, urllib.error
from datetime import datetime, timezone

OSV_BATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/"
REPORT_DIR = "/root/waf_project/reports/vuln-scan"
QUIET = "--quiet" in sys.argv


def installed_packages():
    out = subprocess.check_output([sys.executable, "-m", "pip", "list", "--format=json"])
    return json.loads(out)


def query_osv_batch(pkgs):
    queries = [{"package": {"name": p["name"], "ecosystem": "PyPI"},
                "version": p["version"]} for p in pkgs]
    req = urllib.request.Request(
        OSV_BATCH, data=json.dumps({"queries": queries}).encode(),
        headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=45) as r:
        return json.loads(r.read()).get("results", [])


def vuln_detail(vuln_id):
    try:
        with urllib.request.urlopen(OSV_VULN + vuln_id, timeout=20) as r:
            d = json.loads(r.read())
        sev = ""
        for s in d.get("severity", []):
            sev = s.get("score", "") or sev
        fixed = []
        for aff in d.get("affected", []):
            for rng in aff.get("ranges", []):
                for ev in rng.get("events", []):
                    if ev.get("fixed"):
                        fixed.append(ev["fixed"])
        return {"id": vuln_id, "summary": (d.get("summary") or "")[:160],
                "severity": sev, "fixed": sorted(set(fixed))[:3],
                "aliases": d.get("aliases", [])[:4]}
    except Exception as e:
        return {"id": vuln_id, "summary": f"(detail fetch failed: {e})",
                "severity": "", "fixed": [], "aliases": []}


def infra_versions():
    info = {}
    try:
        info["nginx_modsec"] = subprocess.check_output(
            ["docker", "exec", "waf-nginx", "sh", "-c",
             "nginx -v 2>&1; grep -rhoE 'OWASP_CRS/[0-9.]+' /etc/nginx /etc/modsecurity 2>/dev/null | head -1"],
            stderr=subprocess.STDOUT, timeout=15).decode().strip()
    except Exception as e:
        info["nginx_modsec"] = f"(unavailable: {e})"
    return info


def main():
    os.makedirs(REPORT_DIR, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    pkgs = installed_packages()

    try:
        results = query_osv_batch(pkgs)
    except Exception as e:
        print(f"[vuln-scan] OSV query failed (network?): {e}")
        return 0

    findings = []
    for pkg, res in zip(pkgs, results):
        for v in (res or {}).get("vulns", []) or []:
            findings.append((pkg["name"], pkg["version"], v["id"]))

    detailed = []
    seen = {}
    for name, ver, vid in findings:
        if vid not in seen:
            seen[vid] = vuln_detail(vid)
        d = dict(seen[vid]); d["package"] = name; d["installed"] = ver
        detailed.append(d)

    report = {
        "scanned_at": ts,
        "packages_scanned": len(pkgs),
        "vulnerable_packages": len({d["package"] for d in detailed}),
        "total_findings": len(detailed),
        "infra_versions": infra_versions(),
        "findings": detailed,
    }
    json_path = os.path.join(REPORT_DIR, f"vuln-scan-{ts}.json")
    with open(json_path, "w") as f:
        json.dump(report, f, indent=2)

    # keep only the newest 30 reports
    files = sorted(f for f in os.listdir(REPORT_DIR) if f.startswith("vuln-scan-"))
    for old in files[:-30]:
        try: os.remove(os.path.join(REPORT_DIR, old))
        except OSError: pass

    summary = (f"[vuln-scan {ts}] {len(pkgs)} packages, "
               f"{report['vulnerable_packages']} vulnerable, "
               f"{report['total_findings']} advisories -> {json_path}")
    print(summary)
    if not QUIET and detailed:
        for d in sorted(detailed, key=lambda x: x["package"]):
            fixed = f" fixed in {', '.join(d['fixed'])}" if d["fixed"] else " no fix listed"
            print(f"  - {d['package']}=={d['installed']}: {d['id']} "
                  f"({d['severity'] or 'severity n/a'}){fixed}")
            if d["summary"]:
                print(f"      {d['summary']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
