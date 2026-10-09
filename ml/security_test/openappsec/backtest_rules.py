#!/usr/bin/env python3
"""Backtest proposed rules on the gen half's legitimate traffic with a real ModSecurity, and approve the clean ones.

Part 2.3 of the rule-proposal plan: the "-backtest" approval policy. It stands in for an admin who
looks at "this rule would have blocked N normal requests" before approving, with a rule fixed in
advance: approve only rules that match no legitimate request of the gen half.

How (all on local Docker, nothing else is contacted):
  1. A ModSecurity container from the base CRS image loads ONLY the proposed rules (the CRS rule
     directory is replaced), in log-only mode (deny -> pass,auditlog), so every rule that matches
     a request is recorded, not just the first, and CRS warnings do not bury them.
  2. The gen half's legitimate requests are replayed to it with an X-Bench-Rid header.
  3. The JSON audit log (a file on a mounted dir; `docker logs` splits lines over 16 KB) maps
     X-Bench-Rid -> rule ids that matched. Any entry that cannot be parsed stops the run.
A canary rule must show up in the audit log, or the run stops: an empty audit log would approve
every rule.

Output (<rules-dir>/):
  <generator>-backtest.conf   approved rules, deny mode (what the "-backtest" systems load)
  <generator>-backtest.json   per rule: legitimate requests matched in the gen half, approved or not

    .venv/bin/python ml/security_test/openappsec/backtest_rules.py --rules-dir ~/waf-bench/results/rules/url
"""

import argparse
import asyncio
import json
import os
import re
import subprocess
import sys
import tempfile
import time

import duckdb
import httpx

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, REPO)

from ml.security_test.openappsec.split import GEN, half_of  # noqa: E402

CANARY_ID = 1999999
CANARY_RULE = (f'SecRule ARGS:bt_canary "@streq on" "id:{CANARY_ID},phase:2,pass,log,auditlog,'
               f"msg:'backtest canary'\"")
RID_HEADER = "X-Bench-Rid"
DROP_HEADERS = {"host", "content-length", "connection", "transfer-encoding"}
NET, STUB, MODSEC = "bt-net", "bt-stub", "bt-modsec"


def log_only(rule_text):
    """deny -> pass with an audit entry; the HTTP status action is dropped with its line continuation."""
    text = re.sub(r"status:\d+,(\\\n\s*)?", "", rule_text)
    text = re.sub(r"\bdeny,", "pass,auditlog,", text)
    if "deny" in text or "pass,auditlog," not in text:
        raise ValueError(f"cannot turn this rule into log-only mode:\n{rule_text}")
    return text


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


AUDIT_IN_CONTAINER = "/var/log/bt/audit.log"


def start_modsec(image, rules_dir, audit_dir, port):
    """The audit log goes to a file on a mounted dir, not stdout: `docker logs` splits lines over
    16 KB, and the JSON entry of a request with long headers or many matching rules was lost that way."""
    stop_modsec()
    sh("docker", "network", "create", NET)
    sh("docker", "run", "-d", "--name", STUB, "--network", NET, "traefik/whoami")
    sh("docker", "run", "-d", "--name", MODSEC, "--network", NET, "-p", f"127.0.0.1:{port}:8080",
       "-e", f"BACKEND=http://{STUB}:80", "-e", "MODSEC_AUDIT_LOG_PARTS=ABHZ", "-e", "MODSEC_AUDIT_ENGINE=RelevantOnly",
       "-e", f"MODSEC_AUDIT_LOG={AUDIT_IN_CONTAINER}",
       "-v", f"{rules_dir}:/opt/owasp-crs/rules", "-v", f"{audit_dir}:/var/log/bt", image)


def stop_modsec():
    sh("docker", "rm", "-f", MODSEC, STUB, check=False)
    sh("docker", "network", "rm", NET, check=False)


def wait_ready(base, seconds=900):  # thousands of RF-rules regexes take minutes to compile
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if httpx.get(base + "/", timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(2)
    logs = sh("docker", "logs", "--tail", "40", MODSEC, check=False)
    raise RuntimeError(f"ModSecurity container not ready:\n{logs.stdout}\n{logs.stderr}")


def gen_legit_requests(requests_db, limit=None):
    con = duckdb.connect(requests_db, read_only=True)
    # wire_url: the URL as the tool sends it (requests' requoting), what the WAFs saw
    rows = con.execute('''SELECT rid, "TestName", coalesce(method, 'GET'), wire_url, coalesce(data, ''),
                                 coalesce(headers, '{}')
                          FROM requests WHERE "DataSetType" = 'Legitimate' ORDER BY rid''').fetchall()
    con.close()
    rows = [r for r in rows if half_of("Legitimate", r[1], r[3], "") == GEN]  # legitimate: by site only
    return rows[:limit] if limit else rows


REPLAY_HOST = b"bench-waf:8080"  # the tool reaches each WAF by container name: a numeric Host trips CRS 920350


async def replay(base, rows, concurrency):
    sem = asyncio.Semaphore(concurrency)
    statuses = {}

    async def one(client, rid, method, url, body, headers_json):
        try:
            raw = {k: v for k, v in json.loads(headers_json).items() if k.lower() not in DROP_HEADERS}
            # as http.client (under the tool's requests) does: latin-1, and a value it cannot encode
            # means the tool never sent the request (status 0), so it is not replayed either
            headers = {k: str(v).encode("latin-1") for k, v in raw.items()}
        except UnicodeEncodeError:
            statuses[rid] = "unsendable_header"
            return
        except ValueError:
            headers = {}
        headers[RID_HEADER] = str(rid).encode()
        headers["Host"] = REPLAY_HOST
        async with sem:
            try:
                r = await client.request(method, base + url, headers=headers,
                                         content=body.encode("utf-8", "surrogatepass") if body else None)
                statuses[rid] = r.status_code
            except Exception as exc:  # one bad request must not end the replay
                statuses[rid] = type(exc).__name__

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    async with httpx.AsyncClient(timeout=30, limits=limits) as client:
        tasks = [one(client, rid, m, u, b, h) for rid, _, m, u, b, h in rows]
        for n in range(0, len(tasks), 5000):
            await asyncio.gather(*tasks[n:n + 5000])
            print(f"  replayed {min(n + 5000, len(tasks)):,}/{len(tasks):,}", flush=True)
    return statuses


def audit_hits(audit_path):
    """(X-Bench-Rid -> rule ids that matched, unparseable lines) from the JSON audit log file.

    Every unparseable line is counted: a lost entry would make its rules look clean and get them approved.
    """
    hits, bad = {}, 0
    if not os.path.exists(audit_path):
        return hits, bad
    with open(audit_path, encoding="utf-8", errors="replace") as f:
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
            ids = {int(m["details"]["ruleId"]) for m in tx.get("messages", []) if m.get("details", {}).get("ruleId")}
            if rid is None and ids:
                bad += 1  # a matched request we cannot attribute
            elif ids:
                hits.setdefault(rid, set()).update(ids)
    return hits, bad


def backtest(generator, rules_dir, rows, image, port, concurrency):
    with open(os.path.join(rules_dir, f"{generator}.json"), encoding="utf-8") as f:
        rules = json.load(f)
    print(f"[*] {generator}: {len(rules)} proposed rules, replaying {len(rows):,} gen-half legitimate requests")
    with tempfile.TemporaryDirectory(prefix=f"bt-{generator}-") as tmp:
        rules_dir_c, audit_dir = os.path.join(tmp, "rules"), os.path.join(tmp, "audit")
        os.makedirs(rules_dir_c)
        os.makedirs(audit_dir)
        conf = "\n\n".join([CANARY_RULE] + [log_only(r["rule"]) for r in rules]) + "\n"
        with open(os.path.join(rules_dir_c, "REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf"), "w", encoding="utf-8") as f:
            f.write(conf)
        os.chmod(tmp, 0o755)
        os.chmod(rules_dir_c, 0o755)
        os.chmod(audit_dir, 0o777)  # written by the container's nginx user
        audit_path = os.path.join(audit_dir, "audit.log")
        base = f"http://127.0.0.1:{port}"
        try:
            start_modsec(image, rules_dir_c, audit_dir, port)
            wait_ready(base)
            httpx.get(base + "/?bt_canary=on", headers={RID_HEADER: "canary"}, timeout=5)
            time.sleep(1)
            if CANARY_ID not in audit_hits(audit_path)[0].get("canary", set()):
                raise RuntimeError("canary rule missing from the audit log: rules not loaded or audit log not readable")
            t0 = time.time()
            statuses = asyncio.run(replay(base, rows, concurrency))
            time.sleep(2)
            hits, bad = audit_hits(audit_path)
        finally:
            stop_modsec()
    if bad:
        raise RuntimeError(f"{bad} audit log entries could not be parsed or attributed: refusing to approve rules on a partial log")
    hits.pop("canary", None)

    per_rule = {r["id"]: set() for r in rules}
    for rid, ids in hits.items():
        for i in ids & per_rule.keys():
            per_rule[i].add(int(rid))
    errors = {s: sum(1 for v in statuses.values() if v == s) for s in set(statuses.values()) if s != 200}
    report = {"generator": generator, "image": image, "legitimate_replayed": len(rows), "replay_seconds": round(time.time() - t0),
              "non_200_responses": {str(k): v for k, v in errors.items()},
              "rules": [{"id": r["id"], "key": r["key"], "legitimate_hits": len(per_rule[r["id"]]),
                         "approved": not per_rule[r["id"]],
                         "example_rids": sorted(per_rule[r["id"]])[:5]} for r in rules]}
    approved = [r for r, rep in zip(rules, report["rules"]) if rep["approved"]]
    report["approved"], report["rejected"] = len(approved), len(rules) - len(approved)
    with open(os.path.join(rules_dir, f"{generator}-backtest.conf"), "w", encoding="utf-8") as f:
        f.write(f"# {generator}: rules with no match on the gen half's legitimate traffic (deny mode). backtest_rules.py\n\n")
        f.write("\n\n".join(r["rule"] for r in approved) + "\n")
    with open(os.path.join(rules_dir, f"{generator}-backtest.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1)
    print(f"[✔] {generator}: approved {len(approved)} / rejected {len(rules) - len(approved)}; non-200 responses {errors}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--requests-db", default=os.path.expanduser("~/waf-bench/results/offline/requests.duckdb"))
    ap.add_argument("--rules-dir", default=os.path.expanduser("~/waf-bench/results/rules/url"))
    ap.add_argument("--generators", default="rf-rules,gen3-rules")
    ap.add_argument("--image", default=os.environ.get("BASE_CRS_IMAGE", "owasp/modsecurity-crs:4.25.1-nginx-202609301109-lts"),
                    help="ModSecurity image of the base CRS system (its CRS rules are not loaded here)")
    ap.add_argument("--port", type=int, default=18081, help="published on 127.0.0.1 only")
    ap.add_argument("--concurrency", type=int, default=16)
    ap.add_argument("--limit", type=int, help="replay only the first N requests (smoke test; never for results)")
    args = ap.parse_args()

    rows = gen_legit_requests(args.requests_db, args.limit)
    for generator in args.generators.split(","):
        backtest(generator, args.rules_dir, rows, args.image, args.port, args.concurrency)


if __name__ == "__main__":
    main()
