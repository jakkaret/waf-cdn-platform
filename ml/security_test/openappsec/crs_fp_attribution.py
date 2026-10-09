#!/usr/bin/env python3
"""Which CRS rules block the gen half's legitimate traffic, and on which variables?

Input for CRS tuning that stays leakage-free: exclusions are chosen from the gen half
(ml/security_test/openappsec/split.py) and measured on the eval half only.

The base CRS image runs with its full rule set in blocking mode (PL1, inbound 5, outbound 4, as
run_benchmark.sh), its JSON audit log written to a file. The gen half's legitimate requests are
replayed with X-Bench-Rid (backtest_rules.py replay), then for every blocked request:
  - the rules that scored it (blocking-evaluation and correlation rules left out)
  - for each rule, the variables it matched (e.g. ARGS:q, REQUEST_COOKIES:_ga)
A request "is blocked only because of" a set of rules when the other rules alone stay below the
inbound threshold.

Output (<out>/): crs_fp_attribution.json and a printed table. Local Docker only; nothing else is contacted.

    .venv/bin/python ml/security_test/openappsec/crs_fp_attribution.py --rules 932270,942550
"""

import argparse
import asyncio
import json
import os
import re
import sys
import tempfile
import time
from collections import Counter, defaultdict

import httpx

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, REPO)

from ml.security_test.openappsec.backtest_rules import (  # noqa: E402
    MODSEC, NET, RID_HEADER, STUB, gen_legit_requests, replay, sh, stop_modsec, wait_ready,
)

AUDIT = "/var/log/bt/audit.log"
# rules that only add up or report the score, not detections
NON_DETECTION = re.compile(r"^(949|959|980)\d{3}$")
SEVERITY_POINTS = {"CRITICAL": 5, "ERROR": 4, "WARNING": 3, "NOTICE": 2}
VARIABLE = re.compile(r"against variable `([^']+)'")


def start_crs(image, audit_dir, port, tuning=None):
    stop_modsec()
    sh("docker", "network", "create", NET)
    sh("docker", "run", "-d", "--name", STUB, "--network", NET, "traefik/whoami")
    mount = ["-v", f"{tuning}:/opt/owasp-crs/rules/RESPONSE-999-EXCLUSION-RULES-AFTER-CRS.conf:ro"] if tuning else []
    sh("docker", "run", "-d", "--name", MODSEC, "--network", NET, "-p", f"127.0.0.1:{port}:8080",
       "-e", f"BACKEND=http://{STUB}:80", "-e", "BLOCKING_PARANOIA=1", "-e", "PARANOIA=1",
       "-e", "ANOMALY_INBOUND=5", "-e", "ANOMALY_OUTBOUND=4",
       "-e", "MODSEC_AUDIT_LOG_PARTS=ABHZ", "-e", "MODSEC_AUDIT_ENGINE=RelevantOnly", "-e", f"MODSEC_AUDIT_LOG={AUDIT}",
       "-v", f"{audit_dir}:/var/log/bt", *mount, image)


def parse_audit(path):
    """rid -> {"status": int, "rules": {rule id: (points, [variables])}}; and unparseable line count."""
    out, bad = {}, 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            if not line.strip():
                continue
            try:
                tx = json.loads(line)["transaction"]
            except (ValueError, KeyError):
                bad += 1
                continue
            headers = {k.lower(): v for k, v in tx.get("request", {}).get("headers", {}).items()}
            rid = headers.get(RID_HEADER.lower())
            if rid is None:
                continue
            rules = {}
            for m in tx.get("messages", []):
                d = m.get("details", {})
                rule = str(d.get("ruleId", ""))
                if not rule or NON_DETECTION.match(rule):
                    continue
                points = SEVERITY_POINTS.get(str(d.get("severity", "")).upper(), 0)
                if str(d.get("severity", "")).isdigit():  # numeric severity: 2 critical, 3 error, 4 warning, 5 notice
                    points = {2: 5, 3: 4, 4: 3, 5: 2}.get(int(d["severity"]), 0)
                var = VARIABLE.search(d.get("match", "") or "")
                p, vs = rules.get(rule, (points, []))
                if var:
                    vs.append(var.group(1))
                rules[rule] = (max(p, points), vs)
            out[rid] = {"status": tx.get("response", {}).get("http_code"), "rules": rules}
    return out, bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--requests-db", default=os.path.expanduser("~/waf-bench/results/offline/requests.duckdb"))
    ap.add_argument("--out", default=os.path.expanduser("~/waf-bench/results/crs_tuning"))
    ap.add_argument("--image", default=os.environ.get("BASE_CRS_IMAGE", "owasp/modsecurity-crs:4.25.1-nginx-202609301109-lts"))
    ap.add_argument("--rules", default="932270,942550", help="rules to break down by variable")
    ap.add_argument("--tuning", help="exclusions file loaded after CRS (to check a tuning on the gen half)")
    ap.add_argument("--port", type=int, default=18082)
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--threshold", type=int, default=5)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    focus = args.rules.split(",")

    rows = gen_legit_requests(args.requests_db)
    with tempfile.TemporaryDirectory(prefix="crs-fp-") as tmp:
        os.chmod(tmp, 0o777)
        try:
            start_crs(args.image, tmp, args.port, args.tuning)
            wait_ready(f"http://127.0.0.1:{args.port}")
            t0 = time.time()
            statuses = asyncio.run(replay(f"http://127.0.0.1:{args.port}", rows, args.concurrency))
            time.sleep(2)
            tx, bad = parse_audit(os.path.join(tmp, "audit.log"))
        finally:
            stop_modsec()
    if bad:
        raise RuntimeError(f"{bad} audit log lines could not be parsed")

    sent = sum(1 for s in statuses.values() if isinstance(s, int))
    blocked = [rid for rid, s in statuses.items() if s == 403]
    per_rule, only_focus, focus_vars = Counter(), 0, defaultdict(Counter)
    missing = 0
    for rid in blocked:
        t = tx.get(str(rid))
        if not t:
            missing += 1
            continue
        rules = t["rules"]
        per_rule.update(rules.keys())
        rest = sum(p for r, (p, _) in rules.items() if r not in focus)
        if rest < args.threshold and any(r in focus for r in rules):
            only_focus += 1
        for r in focus:
            if r in rules:
                for v in set(rules[r][1]):
                    focus_vars[r][re.sub(r":.*", ":*", v) if ":" in v else v] += 1
                    focus_vars[r + " (exact)"][v] += 1
    report = {
        "image": args.image, "tuning": args.tuning, "gen_legit_sent": sent, "blocked_403": len(blocked),
        "fpr": len(blocked) / sent if sent else None, "blocked_without_audit_entry": missing,
        "blocked_only_because_of_focus_rules": only_focus,
        "share_of_fp_removed_by_dropping_focus_rules": only_focus / len(blocked) if blocked else None,
        "top_rules_in_blocked": per_rule.most_common(25),
        "focus_rule_variables": {r: c.most_common(25) for r, c in focus_vars.items()},
        "replay_seconds": round(time.time() - t0),
        "non_200": {str(k): v for k, v in Counter(s for s in statuses.values() if s != 200).items()},
    }
    name = "crs_fp_attribution" + ("_tuned" if args.tuning else "") + ".json"
    with open(os.path.join(args.out, name), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    print(f"gen-half legitimate sent {sent:,}, blocked {len(blocked):,} (FPR {report['fpr']:.2%}), no audit entry {missing}")
    print(f"blocked only because of {focus}: {only_focus:,} ({report['share_of_fp_removed_by_dropping_focus_rules']:.1%} of FP)")
    print("top rules among blocked:", report["top_rules_in_blocked"][:12])
    for r in focus:
        print(f"{r} variables:", focus_vars[r].most_common(10))
    print(f"[✔] {os.path.join(args.out, name)}")


if __name__ == "__main__":
    main()
