#!/usr/bin/env python3
"""Recompute access_logs.country from client_ip for rows already stored.

Every row written before services/geoip.py existed carries a fabricated
country ("TH" -- a default, or the edge node's region), so the country
breakdown was one bar. This replaces those values with the real lookup.

Groups the distinct IPs by resolved country and issues ONE mutation per
country (a few dozen at most) instead of one per IP: ClickHouse mutations
rewrite data parts, so the count matters far more than the row count.
Unresolvable and private addresses become '' (unknown), which analytics
already leaves out of the breakdown.

Dry-run by default:
    python scripts/backfill_country.py            # report only
    python scripts/backfill_country.py --apply    # run the mutations
"""
import argparse
import sys
import time
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from services import geoip  # noqa: E402
from services.clickhouse_service import ClickHouseService  # noqa: E402


def _sql_list(ips):
    # client_ip values come out of our own table, but they were originally
    # attacker-controlled request data, so escape rather than trust them.
    return ", ".join("'" + str(ip).replace("\\", "\\\\").replace("'", "\\'") + "'" for ip in ips)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args()

    ch = ClickHouseService()
    if not ch.connected:
        print("ERROR: ClickHouse not reachable")
        return 1

    rows = ch.client.query("SELECT client_ip, country, count() FROM access_logs GROUP BY client_ip, country").result_rows
    by_country = defaultdict(list)  # resolved code -> [ip, ...] whose stored value differs
    rows_by_country = defaultdict(int)
    already_ok = 0
    for ip, stored, n in rows:
        resolved = geoip.country_code(ip)
        if resolved == stored:
            already_ok += n
            continue
        by_country[resolved].append(ip)
        rows_by_country[resolved] += n

    total_change = sum(rows_by_country.values())
    print(f"distinct (ip, country) groups: {len(rows)}; rows already correct: {already_ok}; rows to change: {total_change}")
    for code in sorted(rows_by_country, key=lambda c: -rows_by_country[c]):
        print(f"  {code or '(unknown)':10s} {rows_by_country[code]:8d} rows  {len(by_country[code]):5d} IPs")

    if not args.apply:
        print("\ndry run -- nothing changed. re-run with --apply")
        return 0
    if not by_country:
        print("nothing to do")
        return 0

    for code, ips in by_country.items():
        # Chunk the IN list so no single statement gets unreasonably large.
        for start in range(0, len(ips), 500):
            chunk = ips[start:start + 500]
            ch.client.command(
                f"ALTER TABLE access_logs UPDATE country = '{code}' WHERE client_ip IN ({_sql_list(chunk)})"
            )

    # Mutations are asynchronous; wait so the caller knows when it is finished.
    for _ in range(120):
        pending = ch.client.query(
            "SELECT count() FROM system.mutations WHERE table = 'access_logs' AND NOT is_done"
        ).result_rows[0][0]
        if pending == 0:
            break
        time.sleep(2)
    else:
        print("WARNING: mutations still running after 4 minutes; they will finish in the background")
        return 0

    top = ch.client.query(
        "SELECT if(country = '', '(unknown)', country), count() c FROM access_logs GROUP BY country ORDER BY c DESC LIMIT 8"
    ).result_rows
    print("\nafter backfill:")
    for code, n in top:
        print(f"  {code:10s} {n}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
