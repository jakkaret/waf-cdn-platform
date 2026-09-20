"""Self-service onboarding wizard support (overnight session, 2026-09-22).

The wizard on the frontend just walks the user through calling the
existing origins/domains/tunnels endpoints in sequence -- this router adds
exactly one new thing: a resumability check, so refreshing mid-wizard or
coming back later lands on the right step instead of always restarting at
step 1. No new DB tables, no new writes -- pure read-composition over data
those existing endpoints already produce.
"""
from fastapi import APIRouter, Depends
from services.rbac import get_current_user
import services.origin_service as origin_service

router = APIRouter(prefix="/api/onboarding", tags=["Onboarding"])


def compute_onboarding_status(origins: list, domain_items: list) -> dict:
    origin_count = len(origins)
    has_origin = origin_count > 0

    domain_configured = False
    domain_verified = False
    for o in origins:
        oid = o.get("id") or o.get("origin_id")
        if o.get("tunnel_domains"):
            # A tunnel_domains entry only exists once a real agent has
            # actually connected and claimed it -- that's already stronger
            # evidence of a live setup than a domains_table row alone.
            domain_configured = True
            domain_verified = True
        for d in domain_items:
            if d.get("origin_id") == oid:
                domain_configured = True
                if d.get("dns_verified"):
                    domain_verified = True

    if not has_origin:
        next_step = "create_origin"
    elif not domain_configured:
        next_step = "add_domain"
    elif not domain_verified:
        next_step = "verify_domain"
    else:
        next_step = "done"

    return {
        "has_origin": has_origin,
        "origin_count": origin_count,
        "domain_configured": domain_configured,
        "domain_verified": domain_verified,
        "next_step": next_step,
        "onboarding_complete": next_step == "done",
    }


@router.get("/status")
async def get_onboarding_status(current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("user_id")
    user_role = current_user.get("role", "user")

    await origin_service.auto_sync_tunnel_origins(user_id, user_role)
    origins = origin_service.get_origins_visible_to_user(user_id)

    from services.dynamodb_service import DynamoDBService
    db = DynamoDBService()
    domain_items = db.domains_table.scan().get("Items", [])

    return compute_onboarding_status(origins, domain_items)
