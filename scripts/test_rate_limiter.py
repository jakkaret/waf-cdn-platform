import time
import httpx
from collections import Counter

TARGET_URL = "https://t-dpr6uk2y.tunnel.originweb.site/login"
TOTAL_REQUESTS = 100
WINDOW_SECONDS = 60


def main():
    print("=" * 60)
    print("🚀 RATE LIMIT TEST")
    print(f"   Target : GET {TARGET_URL}")
    print(f"   Load   : {TOTAL_REQUESTS} requests over {WINDOW_SECONDS}s")
    print("=" * 60)

    # Pace evenly: 100 req / 60s = 1 req every 0.6s
    interval = WINDOW_SECONDS / TOTAL_REQUESTS

    client = httpx.Client(timeout=10.0, follow_redirects=False)
    statuses = Counter()
    start = time.monotonic()

    for i in range(1, TOTAL_REQUESTS + 1):
        send_at = start + (i - 1) * interval
        sleep_for = send_at - time.monotonic()
        if sleep_for > 0:
            time.sleep(sleep_for)

        try:
            r = client.get(TARGET_URL)
            statuses[r.status_code] += 1
            retry_after = r.headers.get("retry-after", "")
            extra = f"  Retry-After={retry_after}" if retry_after else ""
            print(f"Request #{i:3d}: Status {r.status_code}{extra}")
        except Exception as e:
            statuses["error"] += 1
            print(f"Request #{i:3d}: ❌ {e}")

    elapsed = time.monotonic() - start
    client.close()

    print("\n" + "=" * 60)
    print(f"Done in {elapsed:.1f}s")
    for code, count in sorted(statuses.items(), key=lambda x: str(x[0])):
        print(f"  {code}: {count}")
    print(f"  Blocked (429): {statuses.get(429, 0)}")
    print("=" * 60)


if __name__ == "__main__":
    main()
