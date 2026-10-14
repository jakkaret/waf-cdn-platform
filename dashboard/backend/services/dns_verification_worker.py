import asyncio
import time
from services.dynamodb_service import DynamoDBService
from services.dns_service import verify_domain_dns

SCAN_INTERVAL_SECONDS = 60
# A pending domain is re-checked after 1, 2, 4, ... minutes, capped here, so a
# domain whose owner never sets DNS stops costing three lookups a minute
# forever. The progress endpoint and the Verify button still check at once.
MAX_BACKOFF_SECONDS = 30 * 60

_next_check: dict = {}
_failures: dict = {}
_reported_invalid: set = set()


def _scan_unverified(db) -> list:
    return db.list_domains(dns_verified=False)


def _valid_hostname(name: str) -> bool:
    """The hostname shape api/domains.py enforces on create. Rows written
    before that check (e.g. "waf_project_web.com") can never verify; the
    worker used to retry them every minute and log each failure twice."""
    from api.domains import _validate_hostname
    try:
        _validate_hostname(name)
        return True
    except ValueError:
        return False


def backoff_seconds(failures: int) -> int:
    return min(SCAN_INTERVAL_SECONDS * (2 ** max(failures - 1, 0)), MAX_BACKOFF_SECONDS)


async def check_pending_domains(db, now: float | None = None) -> list:
    """One pass over unverified domains. Returns the names verified in it.
    DynamoDB and DNS calls are blocking, so they run in worker threads: on the
    event loop they stalled every API request for as long as a lookup took."""
    now = time.monotonic() if now is None else now
    verified = []
    for domain in await asyncio.to_thread(_scan_unverified, db):
        domain_id = domain.get("id")
        domain_name = str(domain.get("domain_name") or "").strip().lower()
        token = domain.get("verification_token")
        if not domain_id:
            continue
        if not _valid_hostname(domain_name):
            if domain_id not in _reported_invalid:
                _reported_invalid.add(domain_id)
                print(f"[DNS Worker] Skipping invalid domain name {domain_name!r} (ID: {domain_id})")
            continue
        if _next_check.get(domain_id, 0) > now:
            continue

        if await asyncio.to_thread(verify_domain_dns, domain_name, token):
            print(f"[DNS Worker] ✅ Domain {domain_name} successfully verified!")
            from api.domains import _mark_verified
            await asyncio.to_thread(_mark_verified, domain_id)
            _failures.pop(domain_id, None)
            _next_check.pop(domain_id, None)
            verified.append(domain_name)
            try:
                from api.domains import after_domain_verified
                await after_domain_verified(domain.get("origin_id"), domain_name)
            except Exception as exc:
                print(f"[DNS Worker] post-verify steps for {domain_name} failed: {exc}")
        else:
            _failures[domain_id] = _failures.get(domain_id, 0) + 1
            _next_check[domain_id] = now + backoff_seconds(_failures[domain_id])
    return verified


async def dns_verification_worker():
    print("=" * 50)
    print("🚀 Starting DNS Verification Worker...")
    print("=" * 50)

    db = DynamoDBService()

    while True:
        try:
            await check_pending_domains(db)
        except Exception as e:
            print(f"[DNS Worker] Error in check loop: {e}")

        # Wait before the next scan. Each tick is a full DynamoDB table scan, so
        # keep this well above the DNS-propagation timescale to bound AWS cost.
        await asyncio.sleep(SCAN_INTERVAL_SECONDS)

if __name__ == "__main__":
    # If run directly, run the worker loop
    import dotenv
    dotenv.load_dotenv()
    try:
        asyncio.run(dns_verification_worker())
    except KeyboardInterrupt:
        print("DNS Worker stopped.")
