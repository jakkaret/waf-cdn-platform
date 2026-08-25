from fastapi import APIRouter, Depends, HTTPException, Query, status
from typing import List, Dict, Any, Optional
from services.clickhouse_service import ClickHouseService
from services.rbac import require_viewer_or_above
from services.tenant_service import get_user_origins_and_domains
import logging

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/analytics", tags=["Analytics"])
ch = ClickHouseService()


def _build_domain_pattern_sql(domain_or_ip: str) -> str:
    """Build ClickHouse SQL fragment for a domain or IP pattern"""
    clean = str(domain_or_ip).strip().lower()
    if not clean or clean == "all":
        return ""
    if "juice" in clean or "3000" in clean:
        return "(url LIKE '%juice%' OR url LIKE '%rest%' OR url LIKE '%socket.io%' OR url LIKE '%assets/public%' OR url LIKE '%main.js%' OR url LIKE '%polyfills.js%' OR url LIKE '%scripts.js%')"
    elif "dvwa" in clean or "8080" in clean or ".php" in clean:
        return "(url LIKE '%dvwa%' OR url LIKE '%.php%' OR url LIKE '%vulnerabilities%')"
    elif "vampi" in clean or "5000" in clean:
        return "(url LIKE '%vampi%' OR url LIKE '%/api/v1/%')"
    elif "bwapp" in clean:
        return "(url LIKE '%bwapp%' OR url LIKE '%bWAPP%')"
    else:
        escaped = clean.replace("'", "\\'")
        return f"(url LIKE '%{escaped}%' OR client_ip LIKE '%{escaped}%')"


def _build_tenant_origin_filter(origin: Optional[str], user_domains: List[str], is_admin: bool) -> str:
    """Build strictly isolated ClickHouse SQL WHERE filter for the current tenant/user"""
    # 1. If specific origin selected
    if origin and str(origin).strip().upper() not in ["ALL", ""]:
        req_clean = str(origin).strip()
        # Non-admins can only view their own domains
        if not is_admin and user_domains:
            if not any(req_clean.lower() in d.lower() or d.lower() in req_clean.lower() for d in user_domains):
                return "1=0"  # Forbidden / Not user's domain
        return _build_domain_pattern_sql(req_clean)

    # 2. If 'ALL' is selected
    if is_admin:
        return ""  # Admins can view all global logs when 'ALL' is selected

    # 3. For standard tenant users: filter strictly by their registered domains/origins
    if not user_domains:
        return "1=0"  # No registered origins -> 0 logs

    clauses = []
    for d in user_domains:
        frag = _build_domain_pattern_sql(d)
        if frag:
            clauses.append(frag)

    return f"({' OR '.join(clauses)})" if clauses else "1=0"


@router.get("/summary")
async def get_analytics_summary(
    origin: Optional[str] = Query("ALL", description="Filter by specific origin/domain or ALL"),
    current_user: dict = Depends(require_viewer_or_above)
):
    """
    Returns real-time analytics aggregates from ClickHouse database,
    strictly isolated per tenant/user according to their registered origins.
    """
    user_id = current_user.get("user_id")
    role = current_user.get("role", "viewer")
    is_admin = (role == "admin")

    origin_ids, active_origins, user_domains = get_user_origins_and_domains(user_id)

    # Tenant Isolation: If non-admin user has NO origins registered yet, return clean empty state
    if not is_admin and not active_origins and not user_domains:
        return {
            "source": "tenant_isolated_empty",
            "scope": origin or "ALL",
            "total_requests": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "unique_ips": 0,
            "average_latency_ms": 0,
            "attack_types": {},
            "suspicious_ips": [],
            "top_countries": [],
            "ai_summary": "ℹ️ ยังไม่มีการผูก Origin Server สำหรับบัญชีนี้ กรุณาเพิ่ม Origin Server ในหน้า Origin Servers เพื่อเริ่มมอนิเตอร์ทราฟฟิกของคุณ"
        }

    if not ch.connected:
        return {
            "source": "offline",
            "scope": origin or "ALL",
            "total_requests": 0,
            "allowed_requests": 0,
            "blocked_requests": 0,
            "unique_ips": 0,
            "average_latency_ms": 12,
            "attack_types": {},
            "suspicious_ips": [],
            "top_countries": [],
            "ai_summary": "⚠️ ClickHouse Database Offline"
        }

    try:
        origin_clause = _build_tenant_origin_filter(origin, user_domains, is_admin)
        where_sql = f"WHERE {origin_clause}" if origin_clause else ""

        # 1. Total Requests
        total_rows = ch.query_stats(f"SELECT count() FROM access_logs {where_sql}")
        total = int(total_rows[0][0]) if total_rows and total_rows[0][0] else 0

        # If 0 requests found
        if total == 0:
            return {
                "source": "clickhouse",
                "scope": origin or "ALL",
                "total_requests": 0,
                "allowed_requests": 0,
                "blocked_requests": 0,
                "unique_ips": 0,
                "average_latency_ms": 0,
                "attack_types": {},
                "suspicious_ips": [],
                "top_countries": [],
                "ai_summary": f"ℹ️ ยังไม่มีบันทึกทราฟฟิกสำหรับ {origin if origin != 'ALL' else 'บัญชีของคุณ'} ในขณะนี้"
            }

        # 2. Blocked vs Allowed Requests
        blocked_cond = f"{where_sql} AND (status_code = 403 OR status_code = 429 OR alert = 1)" if where_sql else "WHERE (status_code = 403 OR status_code = 429 OR alert = 1)"
        blocked_rows = ch.query_stats(f"SELECT count() FROM access_logs {blocked_cond}")
        blocked = int(blocked_rows[0][0]) if blocked_rows and blocked_rows[0][0] else 0
        allowed = max(0, total - blocked)

        # 3. Distinct Client IPs
        distinct_ip_cond = f"{where_sql} AND client_ip != ''" if where_sql else "WHERE client_ip != ''"
        distinct_ip_rows = ch.query_stats(f"SELECT count(DISTINCT client_ip) FROM access_logs {distinct_ip_cond}")
        unique_ips = int(distinct_ip_rows[0][0]) if distinct_ip_rows and distinct_ip_rows[0][0] else 0

        # 4. Latency
        lat_cond = f"{where_sql} AND request_time_ms > 0" if where_sql else "WHERE request_time_ms > 0"
        latency_rows = ch.query_stats(f"SELECT avg(request_time_ms) FROM access_logs {lat_cond}")
        avg_latency = int(latency_rows[0][0]) if latency_rows and latency_rows[0][0] else 12

        # 5. Attack Type Breakdown
        atk_cond = f"{where_sql} AND attack_type != '' AND attack_type != 'NONE'" if where_sql else "WHERE attack_type != '' AND attack_type != 'NONE'"
        attack_rows = ch.query_stats(f"SELECT attack_type, count() FROM access_logs {atk_cond} GROUP BY attack_type ORDER BY count() DESC LIMIT 10")
        attack_types = {str(row[0]): int(row[1]) for row in attack_rows} if attack_rows else {}
        if not attack_types and blocked > 0:
            attack_types = {"WAF Security Filter": blocked}

        # 6. Suspicious IPs
        susp_cond = f"{where_sql} AND (status_code = 403 OR status_code = 429 OR alert = 1) AND client_ip != ''" if where_sql else "WHERE (status_code = 403 OR status_code = 429 OR alert = 1) AND client_ip != ''"
        ip_rows = ch.query_stats(f"""
            SELECT client_ip, count() as total, sum(status_code = 403 OR status_code = 429 OR alert = 1) as blocked
            FROM access_logs
            {susp_cond}
            GROUP BY client_ip
            ORDER BY blocked DESC, total DESC
            LIMIT 5
        """)
        suspicious_ips = [
            {"ip": str(row[0]), "total": int(row[1]), "count": int(row[1]), "blocked": int(row[2])}
            for row in ip_rows
        ] if ip_rows else []

        # 7. Top Countries Breakdown
        country_cond = f"{where_sql} AND country != ''" if where_sql else "WHERE country != ''"
        country_rows = ch.query_stats(f"""
            SELECT country, count() as total, sum(status_code = 403 OR status_code = 429 OR alert = 1) as blocked
            FROM access_logs
            {country_cond}
            GROUP BY country
            ORDER BY total DESC
            LIMIT 5
        """)
        country_flags = {
            "TH": "🇹🇭", "SG": "🇸🇬", "JP": "🇯🇵", "US": "🇺🇸",
            "CN": "🇨🇳", "GB": "🇬🇧", "DE": "🇩🇪", "HK": "🇭🇰", "NL": "🇳🇱"
        }
        country_names = {
            "TH": "Thailand", "SG": "Singapore", "JP": "Japan", "US": "United States",
            "CN": "China", "GB": "United Kingdom", "DE": "Germany", "HK": "Hong Kong", "NL": "Netherlands"
        }
        top_countries = [
            {
                "country": str(row[0]),
                "name": country_names.get(str(row[0]).upper(), str(row[0])),
                "flag": country_flags.get(str(row[0]).upper(), "🌐"),
                "total": int(row[1]),
                "count": int(row[1]),
                "blocked": int(row[2])
            }
            for row in country_rows
        ] if country_rows else []

        # 8. AI Threat Summary
        scope_title = f"Origin: {origin}" if (origin and origin.upper() != "ALL") else "Origin ทั้งหมดของคุณ"
        if blocked > 0:
            top_attack = list(attack_types.keys())[0] if attack_types else "Security Filter"
            top_ip = suspicious_ips[0]["ip"] if suspicious_ips else "Unknown"
            block_ratio = round((blocked / total * 100), 1) if total > 0 else 0
            ai_summary = f"⚠️ ข้อมูล {scope_title}: ตรวจพบและสกัดกั้นทราฟฟิกผิดปกติแบบ {top_attack} จากไอพี {top_ip} รวม {blocked:,} ครั้ง (คิดเป็น {block_ratio}% ของทราฟฟิก) จากทั้งหมด {total:,} คำขอ ความหน่วงเฉลี่ย {avg_latency}ms สถานะ WAF Engine ทำงานปกติ"
        else:
            ai_summary = f"🟢 ข้อมูล {scope_title}: วิเคราะห์ทราฟฟิกรวม {total:,} Requests ทั้งหมดผ่านเกณฑ์ความปลอดภัย ความหน่วงเฉลี่ย {avg_latency}ms ไม่พบภัยคุกคามผิดปกติ"

        return {
            "source": "clickhouse",
            "scope": origin or "ALL",
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
        logger.error(f"ClickHouse analytics error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to query ClickHouse statistics: {e}"
        )
