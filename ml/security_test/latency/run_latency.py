#!/usr/bin/env python3
"""Does putting the ML on the WAF server slow requests down? Measured on local Docker, never on the VPS.

Part 3 of the rule-proposal plan. The WAF stack (CRS, ML containers) is pinned to 2 CPUs and 3.7 GB,
the main server's size (paper table 1); the load generator runs on other cores. Only containers on
a private Docker network are contacted; the CRS port is published on 127.0.0.1 only.

Scenarios:
  inline (ML decides on the request path, like "<BASE>+Gen3@card")
    crs           CRS -> stub origin                         (baseline)
    crs+gen3      CRS -> Gen3 harness, 1 uvicorn worker      (the harness as the benchmark ran it)
    crs+gen3x2    CRS -> Gen3 harness, 2 uvicorn workers
  async (production today: ML reads the access log after the response, ml/async_log_analyzer.py)
    crs+rf-async    CRS -> stub, plus ml_api + analyzer on the same 2 CPUs, RF /predict
    crs+gen3-async  same, analyzer calling /predict-gen3
    The load generator writes one access-log line per request it sends (the nginx json_combined
    `request` field), so the analyzer sees the traffic as it would on the server.

Per scenario and concurrency: requests/s, latency p50/p95/p99 (ms), errors; for async also how many
log lines the analyzer scored per second and the backlog left when the load stopped.

    .venv/bin/python ml/security_test/latency/run_latency.py [--seconds 20] [--concurrency 1,8,32]
"""

import argparse
import asyncio
import json
import os
import random
import shutil
import statistics
import subprocess
import sys
import tempfile
import time

import httpx

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
NET, PORT = "lat-net", 18090
WAF_CPUS, WAF_MEM, LOAD_CPUS = "0,1", "3700m", "4-11"
HARNESS_IMG = "waf-gen3-harness:local"
MODEL = "ml/models/gen3/gen3_f_noopenappsec.onnx"


def sh(*cmd, check=True):
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def cleanup():
    ids = sh("docker", "ps", "-aq", "--filter", "name=^lat-", check=False).stdout.split()
    if ids:
        sh("docker", "rm", "-f", *ids, check=False)
    sh("docker", "network", "rm", NET, check=False)


def run(name, image, *args, env=None, cmd=(), publish=None, volumes=()):
    c = ["docker", "run", "-d", "--name", name, "--network", NET, "--cpuset-cpus", WAF_CPUS, "--memory", WAF_MEM]
    for k, v in (env or {}).items():
        c += ["-e", f"{k}={v}"]
    for v in volumes:
        c += ["-v", v]
    if publish:
        c += ["-p", f"127.0.0.1:{publish}:8080"]
    sh(*c, *args, image, *cmd)


def harness(name, workers):
    run(name, HARNESS_IMG, volumes=[f"{REPO}:/app:ro"],
        env={"WAF_GEN3_ONNX_PATH": f"/app/{MODEL}", "WAF_TEST_LOG": "/tmp/decisions.jsonl"},
        cmd=["uvicorn", "ml.security_test.waf_test_harness:app", "--host", "0.0.0.0", "--port", "8088",
             "--no-access-log", "--workers", str(workers)])


def crs(image, backend):
    run("lat-crs", image, publish=PORT,
        env={"BACKEND": backend, "PARANOIA": "1", "BLOCKING_PARANOIA": "1", "ANOMALY_INBOUND": "5", "ANOMALY_OUTBOUND": "4"})


def wait_ok(url, seconds=300):
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            if httpx.get(url, timeout=2).status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1)
    raise RuntimeError(f"not ready: {url}")


def make_requests(n=400, seed=7):
    """Benign mix: short GETs with a query, and 1 KB form POSTs (no attack, so every request reaches the origin)."""
    rng = random.Random(seed)
    words = "customer requested delivery before noon please call on arrival".split()
    out = []
    for i in range(n):
        if i % 4 == 0:
            body = "&".join(f"f{j}={'+'.join(rng.sample(words, 5))}" for j in range(25))[:1000]
            out.append(("POST", f"/checkout/step{rng.randint(1, 3)}", body))
        else:
            out.append(("GET", f"/shop/item/{rng.randint(1, 99999)}?ref=home&page={rng.randint(1, 20)}&sort=price", ""))
    return out


async def load(base, reqs, concurrency, seconds, access_log=None):
    lat, errors, stop = [], {}, time.time() + seconds
    log = open(access_log, "a", encoding="utf-8", buffering=1) if access_log else None
    headers = {"Content-Type": "application/x-www-form-urlencoded", "User-Agent": "latency-test"}

    async def worker(client, k):
        i = k
        while time.time() < stop:
            m, u, b = reqs[i % len(reqs)]
            i += concurrency
            t = time.perf_counter()
            try:
                r = await client.request(m, base + u, content=b or None, headers=headers)
                ok = r.status_code == 200
                key = None if ok else r.status_code
            except httpx.HTTPError as exc:
                ok, key = False, type(exc).__name__
            if ok:
                lat.append((time.perf_counter() - t) * 1000)
            else:
                errors[str(key)] = errors.get(str(key), 0) + 1
            if log:
                log.write(json.dumps({"request": f"{m} {u} HTTP/1.1", "remote_addr": "10.0.0.1", "status": "200"}) + "\n")

    t0 = time.time()
    async with httpx.AsyncClient(timeout=5, limits=httpx.Limits(max_connections=concurrency)) as client:
        await asyncio.gather(*(worker(client, k) for k in range(concurrency)))
    elapsed = time.time() - t0
    if log:
        log.close()
    q = statistics.quantiles(lat, n=100) if len(lat) > 1 else [float("nan")] * 99
    return {"concurrency": concurrency, "requests": len(lat), "rps": round(len(lat) / elapsed, 1),
            "p50_ms": round(q[49], 2), "p95_ms": round(q[94], 2), "p99_ms": round(q[98], 2), "errors": errors}


def analyzer_lines():
    out = sh("docker", "logs", "lat-analyzer", check=False).stdout
    return sum(1 for line in out.splitlines() if "PASS]" in line or "DETECTED]" in line)


def scenario_inline(name, image, args):
    cleanup()
    sh("docker", "network", "create", NET)
    run("lat-stub", "traefik/whoami")
    if name == "crs":
        crs(image, "http://lat-stub:80")
    else:
        harness("lat-ml", 2 if name.endswith("x2") else 1)
        crs(image, "http://lat-ml:8088")
    wait_ok(f"http://127.0.0.1:{PORT}/")
    reqs = make_requests()
    asyncio.run(load(f"http://127.0.0.1:{PORT}", reqs, 4, 3))  # warm-up
    return [asyncio.run(load(f"http://127.0.0.1:{PORT}", reqs, c, args.seconds)) for c in args.concurrency]


def scenario_async(name, image, args):
    cleanup()
    sh("docker", "network", "create", NET)
    logs = tempfile.mkdtemp(prefix="lat-logs-")
    os.makedirs(os.path.join(logs, "nginx"))
    os.chmod(logs, 0o777)
    access_log = os.path.join(logs, "nginx", "access.json")
    open(access_log, "w").close()
    os.chmod(access_log, 0o666)
    try:
        run("lat-stub", "traefik/whoami")
        crs(image, "http://lat-stub:80")
        run("lat-mlapi", HARNESS_IMG, volumes=[f"{REPO}:/app:ro"], env={"WAF_GEN3_ONNX_PATH": f"/app/{MODEL}"},
            cmd=["uvicorn", "ml.ml_api:app", "--host", "0.0.0.0", "--port", "5000", "--no-access-log"])
        path = "/predict-gen3" if "gen3" in name else "/predict"
        run("lat-analyzer", HARNESS_IMG, volumes=[f"{REPO}:/app:ro", f"{logs}:/app/logs"],
            env={"ML_API_URL": "http://lat-mlapi:5000", "ML_PREDICT_URL": f"http://lat-mlapi:5000{path}"},
            cmd=["python", "ml/async_log_analyzer.py"])
        wait_ok(f"http://127.0.0.1:{PORT}/")
        for _ in range(120):  # ml_api loads its models before it answers
            if sh("docker", "exec", "lat-mlapi", "python", "-c",
                  "import urllib.request;urllib.request.urlopen('http://127.0.0.1:5000/health')", check=False).returncode == 0:
                break
            time.sleep(1)
        time.sleep(3)  # analyzer seeks to the end of the log at start
        reqs = make_requests()
        results = []
        for c in args.concurrency:
            before = analyzer_lines()
            r = asyncio.run(load(f"http://127.0.0.1:{PORT}", reqs, c, args.seconds, access_log))
            during = analyzer_lines() - before
            sent = r["requests"] + sum(r["errors"].values())
            time.sleep(10)
            after10 = analyzer_lines() - before
            r["analyzer"] = {"log_lines": sent, "scored_during_load": during,
                             "scored_per_s": round(during / args.seconds, 1),
                             "backlog_at_end": sent - during, "backlog_10s_later": sent - after10}
            results.append(r)
            # drain before the next level so backlogs do not add up
            for _ in range(600):
                if analyzer_lines() - before >= sent:
                    break
                time.sleep(1)
        return results
    finally:
        shutil.rmtree(logs, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--image", default=os.environ.get("BASE_CRS_IMAGE", "owasp/modsecurity-crs:4.25.1-nginx-202609301109-lts"))
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--concurrency", default="1,8,32")
    ap.add_argument("--scenarios", default="crs,crs+gen3,crs+gen3x2,crs+rf-async,crs+gen3-async")
    ap.add_argument("--out", default=os.path.expanduser("~/waf-bench/results/latency.json"))
    args = ap.parse_args()
    args.concurrency = [int(c) for c in args.concurrency.split(",")]
    if sh("docker", "image", "inspect", HARNESS_IMG, check=False).returncode != 0:
        sh("docker", "build", "-q", "-t", HARNESS_IMG, "-f", f"{REPO}/ml/security_test/openappsec/Dockerfile.harness", REPO)
    os.sched_setaffinity(0, {int(c) for c in range(int(LOAD_CPUS.split("-")[0]), int(LOAD_CPUS.split("-")[1]) + 1)})

    report = {"waf_cpus": WAF_CPUS, "waf_memory": WAF_MEM, "image": args.image, "seconds": args.seconds, "scenarios": {}}
    try:
        for name in args.scenarios.split(","):
            print(f"== {name}", flush=True)
            fn = scenario_async if name.endswith("-async") else scenario_inline
            report["scenarios"][name] = fn(name, args.image, args)
            for r in report["scenarios"][name]:
                print("  ", json.dumps(r), flush=True)
    finally:
        cleanup()
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"[✔] {args.out}")


if __name__ == "__main__":
    sys.exit(main())
