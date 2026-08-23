from fastapi import APIRouter, HTTPException, Depends, Body
from pydantic import BaseModel
from typing import Optional, Dict, Any, List
from datetime import datetime, timedelta
from services.gemini_service import gemini_service
from services.clickhouse_service import ClickHouseService
from services.dynamodb_service import DynamoDBService
from services.rbac import get_current_user
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/ai", tags=["AI Threat Intelligence"])

ch = ClickHouseService()
db = DynamoDBService()

class SummarizeRangeRequest(BaseModel):
    query: Optional[str] = None  # e.g. "สรุป 3 วันล่าสุด", "เมื่อวานถึงตอนนี้"
    start_time: Optional[str] = None
    end_time: Optional[str] = None

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
            start_time = parsed_time.get("start_time")
            end_time = parsed_time.get("end_time")
            time_desc = parsed_time.get("description", req.query)
        elif req.start_time and req.end_time:
            start_time = req.start_time
            end_time = req.end_time
            time_desc = f"{start_time} ถึง {end_time}"
        else:
            now = datetime.now()
            start_time = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
            end_time = now.strftime("%Y-%m-%d %H:%M:%S")
            time_desc = "24 ชั่วโมงล่าสุด"

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
                # Total & Blocked
                count_query = f"""
                    SELECT 
                        count() AS total,
                        countIf(alert = 1 OR status_code IN (403, 429)) AS blocked
                    FROM access_logs
                    WHERE timestamp >= '{start_time}' AND timestamp <= '{end_time}'
                """
                count_res = ch.client.query(count_query)
                if count_res.result_rows:
                    stats["total_requests"] = int(count_res.result_rows[0][0])
                    stats["blocked_attacks"] = int(count_res.result_rows[0][1])

                # Top attack types
                type_query = f"""
                    SELECT attack_type, count() AS cnt
                    FROM access_logs
                    WHERE timestamp >= '{start_time}' AND timestamp <= '{end_time}' AND attack_type != ''
                    GROUP BY attack_type ORDER BY cnt DESC LIMIT 5
                """
                type_res = ch.client.query(type_query)
                stats["top_attack_types"] = [{"type": row[0], "count": int(row[1])} for row in type_res.result_rows]

                # Top attacker IPs
                ip_query = f"""
                    SELECT client_ip, country, count() AS cnt
                    FROM access_logs
                    WHERE timestamp >= '{start_time}' AND timestamp <= '{end_time}' AND (alert = 1 OR status_code IN (403, 429))
                    GROUP BY client_ip, country ORDER BY cnt DESC LIMIT 5
                """
                ip_res = ch.client.query(ip_query)
                stats["top_attacker_ips"] = [{"ip": row[0], "country": row[1], "count": int(row[2])} for row in ip_res.result_rows]

                # Top targeted URLs
                url_query = f"""
                    SELECT url, count() AS cnt
                    FROM access_logs
                    WHERE timestamp >= '{start_time}' AND timestamp <= '{end_time}' AND (alert = 1 OR status_code IN (403, 429))
                    GROUP BY url ORDER BY cnt DESC LIMIT 5
                """
                url_res = ch.client.query(url_query)
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

    except Exception as e:
        logger.error(f"Error in summarize_threat_range: {e}")
        raise HTTPException(status_code=500, detail=str(e))


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
        res = db.alerts_table.scan(Limit=limit)
        items = res.get("Items", [])
        # Sort newest first
        items.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
        return {
            "success": True,
            "count": len(items),
            "unread_count": sum(1 for x in items if not x.get("read", False)),
            "notifications": items
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
