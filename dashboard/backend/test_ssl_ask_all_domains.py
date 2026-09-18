"""Every DNS-verified domain must still be allowed by the ask endpoint.

The endpoint now rejects hostnames that fail _HOSTNAME_RE before looking them up.
That regex was written for the domain-creation form; it now decides whether Caddy
may hold a certificate for a live host, so any verified domain it rejects would
lose its certificate at the next renewal -- silently, days later.
"""
import sys, urllib.error, urllib.request
sys.path.insert(0, "/root/waf_project/dashboard/backend")
from services.dynamodb_service import DynamoDBService

BASE = "http://127.0.0.1:8000/api/domains/check-ssl-allowed"
rows = DynamoDBService().domains_table.scan().get("Items", [])
failures = 0

for r in sorted(rows, key=lambda x: str(x.get("domain_name"))):
    name = str(r.get("domain_name", "")).strip()
    verified = bool(r.get("dns_verified", False))
    try:
        with urllib.request.urlopen(f"{BASE}?domain={urllib.request.quote(name)}", timeout=15) as resp:
            code = resp.status
    except urllib.error.HTTPError as e:
        code = e.code
    want = 200 if verified else 400
    ok = code == want
    failures += 0 if ok else 1
    print(f"[{'PASS' if ok else 'FAIL'}] {name:34s} verified={str(verified):5s} -> {code} (want {want})")

print("\nFAILURES:", failures)
sys.exit(1 if failures else 0)
