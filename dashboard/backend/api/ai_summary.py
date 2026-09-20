from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from services.gemini_service import gemini_service
from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService
from services.rbac import get_current_user
from services.tenant_service import get_user_origins_and_domains, build_tenant_origin_filter
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


@router.get("/notifications/feed")
async def get_notification_feed(
    limit: int = 50,
    current_user: dict = Depends(get_current_user)
):
    """
    Get persistent notification feed with AI explanations for Dashboard Notification Center.
    """
    try:
        if limit > 100:
            limit = 100
        items = db.get_all_alerts(max_items=1000)
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
    Mark specific or all notifications as read.
    """
    try:
        if alert_id:
            db.alerts_table.update_item(
                Key={"alert_id": alert_id},
                UpdateExpression="SET #r = :val",
                ExpressionAttributeNames={"#r": "read"},
                ExpressionAttributeValues={":val": True}
            )
        return {"success": True, "message": "Marked as read"}
    except Exception as e:
        logger.error(f"Error marking read: {e}")
        raise HTTPException(status_code=500, detail=str(e))
