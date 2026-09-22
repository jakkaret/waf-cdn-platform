from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta, timezone
import uuid
from services.gemini_service import gemini_service
from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService, invalidate_alerts_cache
from services.rbac import get_current_user, verify_origin_ownership
from services.tenant_service import get_user_origins_and_domains, build_tenant_origin_filter, build_domain_pattern_sql
from services import audit_log
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["AI Threat Intelligence"])

ch = ClickHouseService()
db = DynamoDBService()

class SummarizeRangeRequest(BaseModel):
    query: Optional[str] = None  # e.g. "สรุป 3 วันล่าสุด", "เมื่อวานถึงตอนนี้"
    start_time: Optional[str] = None
    end_time: Optional[str] = None

# Accepted inbound time formats. Anything else is rejected before it can reach
# the query layer.
_TIME_FORMATS = ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d")

def _parse_time_bound(value: Any, field: str) -> datetime:
    """Turn a caller-supplied time bound into a real datetime.

    Both bounds reach this endpoint from untrusted sources: directly from the
    request body, and indirectly from whatever Gemini returns for a natural
    language range. Parsing them here means only a genuine datetime ever gets
    as far as the ClickHouse queries below, which are parameterised as well.
    """
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value.strip():
        raise HTTPException(status_code=422, detail=f"{field} must be a datetime string")
    text = value.strip()
    for fmt in _TIME_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    raise HTTPException(
        status_code=422,
        detail=f"{field} must match one of {', '.join(_TIME_FORMATS)}",
    )

@router.post("/summarize-range")
async def summarize_threat_range(
    req: SummarizeRangeRequest,
    current_user: dict = Depends(get_current_user)
):
    """
    Summarize WAF attacks for a given time range or natural language text query.
    """
    try:
        # 1. Resolve time range
        if req.query and req.query.strip():
            parsed_time = await gemini_service.parse_natural_time_range(req.query.strip())
            start_dt = _parse_time_bound(parsed_time.get("start_time"), "start_time")
            end_dt = _parse_time_bound(parsed_time.get("end_time"), "end_time")
            time_desc = parsed_time.get("description", req.query)
        elif req.start_time and req.end_time:
            start_dt = _parse_time_bound(req.start_time, "start_time")
            end_dt = _parse_time_bound(req.end_time, "end_time")
            time_desc = f"{req.start_time} ถึง {req.end_time}"
        else:
            now = datetime.now()
            start_dt = now - timedelta(days=1)
            end_dt = now
            time_desc = "24 ชั่วโมงล่าสุด"

        if start_dt > end_dt:
            raise HTTPException(status_code=422, detail="start_time must not be after end_time")

        # Kept for the prompt and the response payload; the queries below bind
        # the datetime objects rather than these strings.
        start_time = start_dt.strftime("%Y-%m-%d %H:%M:%S")
        end_time = end_dt.strftime("%Y-%m-%d %H:%M:%S")
        time_params = {"start": start_dt, "end": end_dt}

        # 1b. Tenant scope -- 2026-09-20 fix: every query below used to have
        # no tenant filter at all (only a time range), so this endpoint (fed
        # to Gemini as "สถิติเหตุการณ์จากระบบ" -- this account's own system
        # events) actually summarized every tenant's traffic. Scoped the same
        # way GET /api/analytics/summary and POST /api/copilot/chat now are.
        user_id = current_user.get("user_id")
        is_admin = current_user.get("role") == "admin"
        _origin_ids, _active_origins, user_domains = get_user_origins_and_domains(user_id)
        has_scope = is_admin or bool(user_domains)

        if not has_scope:
            return {
                "success": True,
                "time_range": {"start": start_time, "end": end_time, "description": time_desc},
                "stats": {
                    "total_requests": 0, "blocked_attacks": 0,
                    "top_attack_types": [], "top_attacker_ips": [], "top_targeted_urls": [],
                },
                "ai_executive_summary": (
                    "ℹ️ บัญชีนี้ยังไม่มี Origin Server ผูกไว้ จึงยังไม่มีข้อมูลทราฟฟิกให้สรุป "
                    "กรุณาเพิ่ม Origin Server ในหน้า Origin Servers เพื่อเริ่มมอนิเตอร์"
                ),
            }

        # 2. Query stats from ClickHouse
        stats = {
            "total_requests": 0,
            "blocked_attacks": 0,
            "top_attack_types": [],
            "top_attacker_ips": [],
            "top_targeted_urls": []
        }

        if ch.connected and ch.client:
            try:
                origin_clause = build_tenant_origin_filter("ALL", user_domains, is_admin)
                scope_sql = f"AND {origin_clause}" if origin_clause else ""

                # Total & Blocked
                count_query = f"""
                    SELECT
                        count() AS total,
                        countIf(alert = 1 OR status_code IN (403, 429)) AS blocked
                    FROM access_logs
                    WHERE timestamp >= {{start:DateTime}} AND timestamp <= {{end:DateTime}} {scope_sql}
                """
                count_res = ch.client.query(count_query, parameters=time_params)
                if count_res.result_rows:
                    stats["total_requests"] = int(count_res.result_rows[0][0])
                    stats["blocked_attacks"] = int(count_res.result_rows[0][1])

                # Top attack types
                type_query = f"""
                    SELECT attack_type, count() AS cnt
                    FROM access_logs
                    WHERE timestamp >= {{start:DateTime}} AND timestamp <= {{end:DateTime}} AND attack_type != '' {scope_sql}
                    GROUP BY attack_type ORDER BY cnt DESC LIMIT 5
                """
                type_res = ch.client.query(type_query, parameters=time_params)
                stats["top_attack_types"] = [{"type": row[0], "count": int(row[1])} for row in type_res.result_rows]

                # Top attacker IPs
                ip_query = f"""
                    SELECT client_ip, country, count() AS cnt
                    FROM access_logs
                    WHERE timestamp >= {{start:DateTime}} AND timestamp <= {{end:DateTime}} AND (alert = 1 OR status_code IN (403, 429)) {scope_sql}
                    GROUP BY client_ip, country ORDER BY cnt DESC LIMIT 5
                """
                ip_res = ch.client.query(ip_query, parameters=time_params)
                stats["top_attacker_ips"] = [{"ip": row[0], "country": row[1], "count": int(row[2])} for row in ip_res.result_rows]

                # Top targeted URLs
                url_query = f"""
                    SELECT url, count() AS cnt
                    FROM access_logs
                    WHERE timestamp >= {{start:DateTime}} AND timestamp <= {{end:DateTime}} AND (alert = 1 OR status_code IN (403, 429)) {scope_sql}
                    GROUP BY url ORDER BY cnt DESC LIMIT 5
                """
                url_res = ch.client.query(url_query, parameters=time_params)
                stats["top_targeted_urls"] = [{"url": row[0], "count": int(row[1])} for row in url_res.result_rows]

            except Exception as db_err:
                logger.warning(f"Error querying ClickHouse stats: {db_err}")

        # 3. Generate AI Executive Summary
        ai_analysis = await gemini_service.generate_range_summary(time_desc, stats)

        return {
            "success": True,
            "time_range": {
                "start": start_time,
                "end": end_time,
                "description": time_desc
            },
            "stats": stats,
            "ai_executive_summary": ai_analysis
        }

    except HTTPException:
        # Validation failures carry their own status and a safe message; the
        # broad handler below would otherwise turn a 422 into a 500.
        raise
    except Exception as e:
        logger.error(f"Error in summarize_threat_range: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Failed to summarize the requested range")


def _alert_belongs_to_tenant(alert: Dict[str, Any], domain_keywords: List[str]) -> bool:
    """Real cross-tenant leak fixed 2026-09-22: waf_alerts' user_id has
    always been a hardcoded "default-user" placeholder (confirmed in
    services/telegram_listener.py, the real writer), never a usable owner
    -- filtering on it would hide every alert from every user, not scope
    them correctly. The real signal is the alert's captured domain (Host
    header, stored as "domain" as of this fix) matched against the
    tenant's registered domains/IPs, same substring-both-directions match
    already used for CVE matching (services/cve_feed.py) and ClickHouse
    scoping (tenant_service.build_domain_pattern_sql). An alert with no
    domain captured (rows written before this fix) matches nothing --
    fail closed, never open, matching build_tenant_origin_filter's own
    convention elsewhere in this file."""
    alert_domain = str(alert.get("domain", "")).strip().lower()
    alert_ip = str(alert.get("ip", "")).strip().lower()
    if not alert_domain and not alert_ip:
        return False
    for kw in domain_keywords:
        kw = str(kw).strip().lower()
        if not kw:
            continue
        if alert_domain and (kw in alert_domain or alert_domain in kw):
            return True
        if alert_ip and kw == alert_ip:
            return True
    return False


def _visible_alerts_for_user(current_user: dict, max_items: int = 2000) -> List[Dict[str, Any]]:
    """Admin sees every alert (same "is_admin -> no filter" branch
    summarize_range already uses); everyone else sees only alerts matching
    their own registered origins' domains/IPs."""
    items = db.get_all_alerts(max_items=max_items)
    if current_user.get("role") == "admin":
        return items
    _origin_ids, _active_origins, user_domains = get_user_origins_and_domains(current_user.get("user_id"))
    if not user_domains:
        return []
    return [a for a in items if _alert_belongs_to_tenant(a, user_domains)]


@router.get("/notifications/feed")
async def get_notification_feed(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """
    Get persistent notification feed with AI explanations for Dashboard
    Notification Center. Tenant-scoped (see _visible_alerts_for_user) --
    real bug fixed 2026-09-22: this used to return every alert in the
    system to every logged-in user, confirmed live with a brand-new
    account seeing the full production alert backlog.
    """
    try:
        if limit > 100:
            limit = 100
        items = _visible_alerts_for_user(current_user)
        sliced = items[:limit]
        return {
            "success": True,
            "count": len(sliced),
            "unread_count": sum(1 for x in items if not x.get("read", False)),
            "notifications": sliced
        }
    except Exception as e:
        logger.error(f"Error fetching notifications: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/notifications/mark-read")
async def mark_notifications_read(
    alert_id: Optional[str] = Body(None, embed=True),
    current_user: dict = Depends(get_current_user)
):
    """
    Mark one alert read (alert_id given), or ALL alerts read when alert_id
    is omitted -- this is exactly what the dashboard's "Mark all read"
    button sends (NotificationCenter.tsx's handleMarkAllRead calls
    markRead(undefined)).

    Real bug #1 fixed 2026-09-22: this previously only had the single-
    alert_id branch, so "mark all" (alert_id=None) silently updated nothing
    in DynamoDB while still returning {"success": True} -- every
    notification stayed unread after clicking it. Also invalidates the
    alerts in-memory cache (5s TTL, services/dynamodb_service.py) after
    writing: update_item() bypasses save_alert()'s own cache write, so
    without this a feed fetch made within that window could still show the
    pre-update unread count even for the single-alert path.

    Real bug #2 fixed 2026-09-22, deeper: waf_alerts' real key schema is
    COMPOSITE (HASH=user_id, RANGE=alert_id -- confirmed live via
    describe_table), not a plain alert_id key. Key={"alert_id": alert_id}
    (the ORIGINAL code, before bug #1's fix was even written) has never
    matched that schema and raised ValidationException: "The provided key
    element does not match the schema" on every single call -- caught by
    the blanket except below and turned into a 500, so *every* "mark as
    read" click, not just "mark all", has always failed in production.
    Fixed by looking the alert(s) up first (get_all_alerts(), already
    cached) to get each one's real user_id, then updating with the full
    composite key.

    Real bug #3 fixed 2026-09-22, the most serious: neither branch was
    tenant-scoped. A non-admin user could mark (and, via "mark all", DID
    mark -- confirmed run live against this project's own production data
    tonight) every other tenant's alerts as read, or guess/enumerate an
    alert_id belonging to someone else and mark it individually. Both
    branches now start from _visible_alerts_for_user(current_user) instead
    of the raw unscoped get_all_alerts(), the same scoping the feed uses.
    """
    try:
        visible_alerts = _visible_alerts_for_user(current_user)

        if alert_id:
            targets = [a for a in visible_alerts if a.get("alert_id") == alert_id]
            for a in targets:
                if not a.get("user_id") or not a.get("alert_id"):
                    continue
                db.alerts_table.update_item(
                    Key={"user_id": a["user_id"], "alert_id": a["alert_id"]},
                    UpdateExpression="SET #r = :val",
                    ExpressionAttributeNames={"#r": "read"},
                    ExpressionAttributeValues={":val": True}
                )
        else:
            # "Mark all" can touch thousands of real rows (confirmed live:
            # this project's own backlog was 1000+) -- one UpdateItem call
            # per row is too slow for a single HTTP request (confirmed
            # live: the request ran past 120s and had to be backgrounded).
            # batch_writer() batches up to 25 items per real
            # BatchWriteItem call instead. It only supports put/delete,
            # not update, so each target's FULL item (already in hand from
            # get_all_alerts()) is rewritten with read=True rather than
            # patched in place.
            targets = [a for a in visible_alerts if not a.get("read", False)]
            with db.alerts_table.batch_writer() as batch:
                for a in targets:
                    if not a.get("user_id") or not a.get("alert_id"):
                        continue
                    updated_item = dict(a)
                    updated_item["read"] = True
                    batch.put_item(Item=updated_item)
        invalidate_alerts_cache()
        return {"success": True, "message": "Marked as read"}
    except Exception as e:
        logger.error(f"Error marking read: {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ─── AI Incident Postmortem (2026-09-22) ───────────────────────────────────
# Owner-only (verify_origin_ownership), deliberately: a postmortem merges
# origin-scoped audit events with *global* ones (settings.update,
# rule.approve/reject), and those carry raw details like paranoia_level or
# threshold values that an editor/viewer of one origin has no business
# seeing about the whole system. See services/audit_log.py's scope_id
# convention -- "global" is system-wide, not this-origin-only.

def _build_origin_scope_sql(origin: Dict[str, Any]) -> str:
    """Fail-closed ClickHouse WHERE fragment restricted to this one origin's
    own domains + IP -- same assembly as tenant_service's
    get_user_origins_and_domains, scoped to a single origin instead of
    every origin a user can see."""
    origin_id = str(origin.get("id") or "")
    keywords = set()
    try:
        # origin_id-index query, not a full-table scan: same reasoning as
        # tenant_service.get_user_origins_and_domains -- an unpaginated
        # scan() silently stops at DynamoDB's 1MB cap, which here would
        # drop domains out of this origin's own scope filter.
        for d in db.get_domains_by_origin_ids([origin_id]):
            if d.get("domain_name"):
                keywords.add(str(d["domain_name"]).strip().lower())
    except Exception:
        pass
    ip_val = str(origin.get("ip", "")).strip().lower()
    if ip_val:
        keywords.add(ip_val)
    label_val = str(origin.get("label", "")).strip().lower()
    if "(" in label_val and ")" in label_val:
        try:
            extracted = label_val.split("(")[1].split(")")[0].strip()
            if "." in extracted:
                keywords.add(extracted)
        except Exception:
            pass
    clauses = [build_domain_pattern_sql(k) for k in keywords]
    clauses = [c for c in clauses if c]
    return f"({' OR '.join(clauses)})" if clauses else "1=0"


def build_incident_timeline(origin: Dict[str, Any], start_dt: datetime, end_dt: datetime) -> Dict[str, Any]:
    """Pure assembly, no Gemini call: real traffic/alert stats for this one
    origin correlated against the real audit trail (both this origin's own
    events AND global system-settings/rule events) in the same window,
    merged into one chronological timeline. This correlation -- not the
    prompt -- is what makes a postmortem different from summarize-range."""
    origin_id = str(origin.get("id"))
    time_params = {"start": start_dt, "end": end_dt}
    stats: Dict[str, Any] = {"total_requests": 0, "total_alerts": 0, "top_attack_types": []}
    hourly_buckets: List[Dict[str, Any]] = []

    if ch.connected and ch.client:
        try:
            scope_sql = _build_origin_scope_sql(origin)

            count_query = f"""
                SELECT count() AS total, countIf(alert = 1 OR status_code IN (403, 429)) AS blocked
                FROM access_logs
                WHERE timestamp >= {{start:DateTime}} AND timestamp <= {{end:DateTime}} AND {scope_sql}
            """
            count_res = ch.client.query(count_query, parameters=time_params)
            if count_res.result_rows:
                stats["total_requests"] = int(count_res.result_rows[0][0])
                stats["total_alerts"] = int(count_res.result_rows[0][1])

            type_query = f"""
                SELECT attack_type, count() AS cnt
                FROM access_logs
                WHERE timestamp >= {{start:DateTime}} AND timestamp <= {{end:DateTime}} AND attack_type != '' AND {scope_sql}
                GROUP BY attack_type ORDER BY cnt DESC LIMIT 5
            """
            type_res = ch.client.query(type_query, parameters=time_params)
            stats["top_attack_types"] = [{"type": row[0], "count": int(row[1])} for row in type_res.result_rows]

            bucket_query = f"""
                SELECT toStartOfHour(timestamp) AS bucket, count() AS total,
                       countIf(alert = 1 OR status_code IN (403, 429)) AS alerts
                FROM access_logs
                WHERE timestamp >= {{start:DateTime}} AND timestamp <= {{end:DateTime}} AND {scope_sql}
                GROUP BY bucket ORDER BY bucket ASC
            """
            bucket_res = ch.client.query(bucket_query, parameters=time_params)
            hourly_buckets = [
                {
                    "hour": row[0].strftime("%Y-%m-%d %H:%M:%S") if hasattr(row[0], "strftime") else str(row[0]),
                    "requests": int(row[1]),
                    "alerts": int(row[2]),
                }
                for row in bucket_res.result_rows
            ]
        except Exception as e:
            logger.warning(f"Error querying ClickHouse for postmortem timeline: {e}")

    # Both scopes, merged chronologically -- see module-level note above for
    # why "global" must be included, not just this origin_id.
    start_utc = start_dt if start_dt.tzinfo else start_dt.replace(tzinfo=timezone.utc)
    end_utc = end_dt if end_dt.tzinfo else end_dt.replace(tzinfo=timezone.utc)
    origin_events = audit_log.get_audit_log(origin_id, start=start_utc, end=end_utc, limit=200)
    global_events = audit_log.get_audit_log("global", start=start_utc, end=end_utc, limit=200)
    for e in origin_events:
        e["scope"] = "origin"
    for e in global_events:
        e["scope"] = "global"
    merged_events = origin_events + global_events
    merged_events.sort(key=lambda e: e.get("timestamp", ""))

    return {
        "origin_id": origin_id,
        "start_time": start_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "end_time": end_dt.strftime("%Y-%m-%d %H:%M:%S"),
        "stats": stats,
        "hourly_buckets": hourly_buckets,
        "audit_events": merged_events,
    }


class PostmortemCreateRequest(BaseModel):
    start_time: str
    end_time: str


@router.post("/postmortems/{origin_id}")
async def create_postmortem(
    origin_id: str,
    req: PostmortemCreateRequest,
    origin: dict = Depends(verify_origin_ownership),
    current_user: dict = Depends(get_current_user),
):
    start_dt = _parse_time_bound(req.start_time, "start_time")
    end_dt = _parse_time_bound(req.end_time, "end_time")
    if start_dt > end_dt:
        raise HTTPException(status_code=422, detail="start_time must not be after end_time")

    timeline = build_incident_timeline(origin, start_dt, end_dt)

    narrative_result: Dict[str, Any] = {"narrative": None, "degraded": False}
    try:
        narrative_result = await gemini_service.generate_postmortem_narrative(timeline)
    except Exception as e:
        # The timeline is real data and valuable on its own -- a narration
        # failure must never turn a successful timeline build into a 500.
        logger.warning(f"Postmortem narrative generation failed: {e}")

    postmortem_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    item = {
        "id": postmortem_id,
        "origin_id": origin_id,
        "origin_label": origin.get("label", ""),
        "created_by": current_user.get("user_id"),
        "created_by_username": current_user.get("username", ""),
        "created_at": now.isoformat(),
        "start_time": timeline["start_time"],
        "end_time": timeline["end_time"],
        "stats": timeline["stats"],
        "hourly_buckets": timeline["hourly_buckets"],
        "audit_events": timeline["audit_events"],
        "ai_narrative": narrative_result.get("narrative"),
        "ai_narrative_degraded": narrative_result.get("degraded", False),
    }
    try:
        db.postmortems_table.put_item(Item=item)
    except Exception as e:
        logger.error(f"Failed to persist postmortem: {e}")
        raise HTTPException(status_code=500, detail="Failed to save postmortem report")

    return {"status": "success", "postmortem": item}


@router.get("/postmortems/{origin_id}")
async def list_postmortems(
    origin: dict = Depends(verify_origin_ownership),
):
    """No range key on waf_postmortems (HASH=id only) -- scan + filter +
    Python-side sort, the same shape services/audit_log.py's get_audit_log
    already uses, rather than adding a GSI for this."""
    origin_id = origin.get("id")
    try:
        # Paginated: scan() returns at most 1MB per call, so the unpaginated
        # version silently stopped listing once the table crossed that --
        # an origin's older reports would just disappear from the list with
        # no error. Still a scan rather than a GSI, per the note above.
        items = []
        scan_kwargs = {}
        while True:
            resp = db.postmortems_table.scan(**scan_kwargs)
            items.extend(resp.get("Items", []))
            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
            scan_kwargs["ExclusiveStartKey"] = last_key
    except Exception as e:
        logger.error(f"Failed to list postmortems: {e}")
        return {"postmortems": []}
    matching = [i for i in items if i.get("origin_id") == origin_id]
    matching.sort(key=lambda i: i.get("created_at", ""), reverse=True)
    # Full audit_events/hourly_buckets are not needed for a list view.
    summaries = [
        {
            "id": i.get("id"),
            "origin_id": i.get("origin_id"),
            "origin_label": i.get("origin_label"),
            "created_by_username": i.get("created_by_username"),
            "created_at": i.get("created_at"),
            "start_time": i.get("start_time"),
            "end_time": i.get("end_time"),
            "stats": i.get("stats"),
            "has_ai_narrative": bool(i.get("ai_narrative")),
        }
        for i in matching
    ]
    return {"postmortems": summaries}


@router.get("/postmortems/{origin_id}/{postmortem_id}")
async def get_postmortem(
    postmortem_id: str,
    origin: dict = Depends(verify_origin_ownership),
):
    try:
        item = db.postmortems_table.get_item(Key={"id": postmortem_id}).get("Item")
    except Exception as e:
        logger.error(f"Failed to fetch postmortem {postmortem_id}: {e}")
        raise HTTPException(status_code=500, detail="Failed to load postmortem report")
    if not item or item.get("origin_id") != origin.get("id"):
        raise HTTPException(status_code=404, detail="Postmortem not found")
    return {"postmortem": item}
