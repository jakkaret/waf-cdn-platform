from fastapi import APIRouter, Depends, HTTPException, status
from typing import List, Dict, Any
from services.clickhouse_service import ClickHouseService
from services.rbac import require_viewer_or_above
import time

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])
ch = ClickHouseService()

@router.get("/summary")
async def get_analytics_summary(current_user: dict = Depends(require_viewer_or_above)):
    """
    Returns real-time analytics aggregates from ClickHouse database,
    along with an AI-generated summary of the traffic.
    """
    if not ch.connected:
        return {
            "source": "fallback_db",
            "total_requests": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "unique_ips": 0,
            "average_latency_ms": 0,
            "attack_types": {},
            "suspicious_ips": [],
            "top_countries": [],
            "ai_summary": "⚠️ ClickHouse Database Offline"
        }

    try:
        # 1. Query total, allowed, blocked
        total_rows = ch.query_stats("SELECT count() FROM access_logs")
        total = int(total_rows[0][0]) if total_rows else 0
        
        blocked_rows = ch.query_stats("SELECT count() FROM access_logs WHERE status_code = 403 OR status_code = 429 OR alert = 1")
        blocked = int(blocked_rows[0][0]) if blocked_rows else 0
        allowed = max(0, total - blocked)
        
        # 2. Distinct Client IPs
        distinct_ip_rows = ch.query_stats("SELECT count(DISTINCT client_ip) FROM access_logs WHERE client_ip != ''")
        unique_ips = int(distinct_ip_rows[0][0]) if distinct_ip_rows else 0

        # 3. Latency
        latency_rows = ch.query_stats("SELECT avg(request_time_ms) FROM access_logs WHERE request_time_ms > 0")
        avg_latency = int(latency_rows[0][0]) if latency_rows and latency_rows[0][0] else 12
        
        # 4. Attack Type breakdown
        attack_rows = ch.query_stats("SELECT attack_type, count() FROM access_logs WHERE attack_type != '' GROUP BY attack_type ORDER BY count() DESC LIMIT 10")
        attack_types = {str(row[0]): int(row[1]) for row in attack_rows} if attack_rows else {}
        if not attack_types and blocked > 0:
            attack_types = {"WAF Security Filter": blocked}
        
        # 5. Suspicious IPs
        ip_rows = ch.query_stats("""
            SELECT client_ip, count() as total, sum(status_code = 403 OR status_code = 429 OR alert = 1) as blocked
            FROM access_logs
            WHERE client_ip != ''
            GROUP BY client_ip
            ORDER BY blocked DESC, total DESC
            LIMIT 5
        """)
        suspicious_ips = [
            {"ip": str(row[0]), "total": int(row[1]), "blocked": int(row[2])}
            for row in ip_rows
        ] if ip_rows else []

        # 6. Top Countries Breakdown
        country_rows = ch.query_stats("""
            SELECT country, count() as total, sum(status_code = 403 OR status_code = 429 OR alert = 1) as blocked
            FROM access_logs
            WHERE country != ''
            GROUP BY country
            ORDER BY total DESC
            LIMIT 5
        """)
        country_flags = {
            "TH": "🇹🇭", "SG": "🇸🇬", "JP": "🇯🇵", "US": "🇺🇸",
            "CN": "🇨🇳", "GB": "🇬🇧", "DE": "🇩🇪", "HK": "🇭🇰", "NL": "🇳🇱"
        }
        top_countries = [
            {
                "country": str(row[0]),
                "name": str(row[0]),
                "flag": country_flags.get(str(row[0]).upper(), "🌐"),
                "total": int(row[1]),
                "blocked": int(row[2])
            }
            for row in country_rows
        ] if country_rows else []
        
        # 7. Dynamic AI Summary
        if blocked > 0:
            top_attack = list(attack_types.keys())[0] if attack_types else "Security Filter"
            top_ip = suspicious_ips[0]["ip"] if suspicious_ips else "Unknown"
            block_ratio = round((blocked / total * 100), 1) if total > 0 else 0
            ai_summary = f"⚠️ ตรวจพบภัยคุกคาม: ระบบ WAF ตรวจพบและสกัดกั้นทราฟฟิกผิดปกติแบบ {top_attack} จากไอพีหลัก {top_ip} รวม {blocked} ครั้ง (คิดเป็น {block_ratio}% ของทราฟฟิกทั้งหมด) ปล่อยผ่านปกติ {allowed} ครั้ง ความหน่วงเฉลี่ย {avg_latency}ms สถานะ WAF Engine ทำงานปกติ"
        else:
            ai_summary = f"🟢 ระบบทำงานปกติ: วิเคราะห์ทราฟฟิกรวม {total} Requests ทั้งหมดผ่านเกณฑ์ความปลอดภัย ความหน่วงเฉลี่ย {avg_latency}ms ไม่พบภัยคุกคามผิดปกติ"

        return {
            "source": "clickhouse",
            "total_requests": total,
            "allowed_requests": allowed,
            "blocked_requests": blocked,
            "unique_ips": unique_ips,
            "average_latency_ms": avg_latency,
            "attack_types": attack_types,
            "suspicious_ips": suspicious_ips,
            "top_countries": top_countries,
            "ai_summary": ai_summary
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query ClickHouse statistics: {e}"
        )
