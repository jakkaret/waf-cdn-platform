"""On-demand TLS ask endpoint test (SYSTEM-OPERATIONAL-REQUIREMENTS 8, 15).

Caddy calls this for every TLS SNI it sees, so it is reachable by anyone who can
open a TLS connection to the edge. It must answer correctly, cheaply, and it must
not become database load under a flood of invented hostnames.
"""
import json, sys, time, urllib.error, urllib.request

BASE = "http://127.0.0.1:8000/api/domains/check-ssl-allowed"
results = []


def ask(domain):
    try:
        with urllib.request.urlopen(f"{BASE}?domain={urllib.request.quote(domain)}", timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def check(name, got, want):
    ok = got in want
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name:52s} got={got} want={want}")


check("a registered, verified domain is allowed", ask("juice.waf-it-kku.online"), {200})
check("an unregistered subdomain is refused", ask("nope-12345.waf-it-kku.online"), {400})
check("an unrelated domain is refused", ask("example.com"), {400})
check("an empty domain is refused", ask(""), {400})
check("a malformed hostname is refused", ask("not a hostname"), {400})
check("an over-long hostname is refused", ask("a" * 300 + ".com"), {400})
check("a single label is refused", ask("localhost"), {400})

N = 300
start = time.perf_counter()
for i in range(N):
    ask(f"flood{i}.pochtabank.sbermegamarket.waf-it-kku.online")
elapsed = time.perf_counter() - start
per_request_ms = elapsed / N * 1000
print(f"\n{N} invented hostnames in {elapsed:.2f}s -- {per_request_ms:.1f} ms each")
# Answering from the in-memory snapshot is sub-millisecond of real work; the
# ceiling here is generous so the test measures "no per-request database call"
# rather than machine speed.
check("a flood of invented hostnames stays cheap", per_request_ms < 25, {True})

print(f"\nRESULT: {sum(results)}/{len(results)} passed")
sys.exit(0 if all(results) else 1)
