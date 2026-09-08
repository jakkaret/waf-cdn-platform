import re
import time
import asyncio
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from typing import List, Optional
import uuid
from datetime import datetime
from services.rbac import get_current_user, verify_origin_ownership
from services.dynamodb_service import DynamoDBService
from services.dns_service import verify_domain_dns

router = APIRouter(prefix="/api/domains", tags=["Domains"])
db = DynamoDBService()

# Ruling R7 (task-11-brief.md): domain_name flows into tenant_service's
# ClickHouse LIKE patterns (services/tenant_service.py -> api/analytics.py's
# _build_domain_pattern_sql -> raw f-string interpolation into ClickHouse),
# so it is constrained to a hostname shape at the point it enters the
# system, on *every* write path into domains_table -- not just the endpoint
# newly mounted for T11. Per task-11-brief.md's review (Critical finding):
# the legacy POST /api/domains below applied no validation at all and fed
# the identical sink, so the same _validate_hostname is reused on both
# DomainCreate and DomainCreatePayload rather than only the new one.
#
# This is entry validation as mitigation, not a fix for the underlying
# vulnerability: services/tenant_service.py, api/analytics.py, and
# services/clickhouse_service.py still build ClickHouse queries with
# backslash-replacement escaping only, which a value shaped like
# "x\' OR 1=1 --" already defeats once it reaches that sink (ClickHouse
# reads the resulting "\\'" as one literal backslash followed by a
# string-closing quote). That escaping is a separate, tracked
# parameterization refactor across several call sites -- explicitly out of
# scope here. Constraining domain_name to a hostname shape (no quotes,
# backslashes, '%', or '_') at both entry points closes this specific
# injection path without touching that sink.
_HOSTNAME_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_HOSTNAME_RE = re.compile(rf"^{_HOSTNAME_LABEL}(?:\.{_HOSTNAME_LABEL})+$")


def _validate_hostname(value: str) -> str:
    normalized = value.strip().lower()
    if len(normalized) > 253 or not _HOSTNAME_RE.match(normalized):
        raise ValueError(
            "domain_name must be a valid hostname: labels of letters, digits, "
            "and hyphens (a label may not start or end with a hyphen), each "
            "label at most 63 characters, with at least two labels (e.g. "
            "'example.com'), and at most 253 characters total."
        )
    return normalized


class DomainCreate(BaseModel):
    origin_id: str
    domain_name: str

    @field_validator("domain_name")
    @classmethod
    def _domain_name_must_be_hostname(cls, v: str) -> str:
        return _validate_hostname(v)

class DomainResponse(BaseModel):
    id: str
    origin_id: str
    domain_name: str
    verification_token: str
    dns_verified: bool
    ssl_status: str
    created_at: str

@router.post("", response_model=DomainResponse)
async def create_domain(payload: DomainCreate, current_user: dict = Depends(get_current_user)):
    # 1. Verify that current user owns the target origin
    verify_origin_ownership(payload.origin_id, current_user)
    
    # 2. Check if domain already exists
    # Scans/queries domains table for this domain_name
    from boto3.dynamodb.conditions import Attr
    response = db.domains_table.scan(
        FilterExpression=Attr("domain_name").eq(payload.domain_name)
    )
    if response.get("Items"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Domain name {payload.domain_name} is already registered."
        )
        
    # 3. Create domain record
    domain_id = str(uuid.uuid4())
    # Generate verification token
    verification_token = f"waf-token-{uuid.uuid4().hex[:16]}"
    now = datetime.now().isoformat() + "Z"
    
    domain_data = {
        "id": domain_id,
        "origin_id": payload.origin_id,
        "domain_name": payload.domain_name,
        "verification_token": verification_token,
        "dns_verified": False,
        "ssl_status": "none",
        "created_at": now,
        "updated_at": now
    }
    
    try:
        db.domains_table.put_item(Item=domain_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save domain: {e}"
        )
        
    return domain_data

@router.get("/origin/{origin_id}", response_model=List[DomainResponse])
async def list_domains_by_origin(origin_id: str, current_user: dict = Depends(get_current_user)):
    # Verify origin ownership
    verify_origin_ownership(origin_id, current_user)
    
    try:
        # Query domains table using GSI
        response = db.domains_table.query(
            IndexName="origin_id-index",
            KeyConditionExpression=boto3_key_query(origin_id)
        )
        return response.get("Items", [])
    except Exception as e:
        # Fallback to scan filter if index is not ready yet
        from boto3.dynamodb.conditions import Attr
        try:
            response = db.domains_table.scan(
                FilterExpression=Attr("origin_id").eq(origin_id)
            )
            return response.get("Items", [])
        except Exception as scan_err:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=f"Failed to query domains: {scan_err}"
            )

def boto3_key_query(origin_id: str):
    import boto3
    return boto3.dynamodb.conditions.Key("origin_id").eq(origin_id)

@router.delete("/{domain_id}")
async def delete_domain(domain_id: str, current_user: dict = Depends(get_current_user)):
    # 1. Fetch domain
    res = db.domains_table.get_item(Key={"id": domain_id})
    domain = res.get("Item")
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    # 2. Verify that current user owns the parent origin
    verify_origin_ownership(domain["origin_id"], current_user)
    
    # 3. Delete domain
    try:
        db.domains_table.delete_item(Key={"id": domain_id})
        invalidate_ssl_allowed_snapshot()
        return {"status": "success", "message": f"Domain {domain['domain_name']} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/{domain_id}/verify")
async def verify_domain_now(domain_id: str, current_user: dict = Depends(get_current_user)):
    # 1. Fetch domain
    res = db.domains_table.get_item(Key={"id": domain_id})
    domain = res.get("Item")
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    # 2. Verify that current user owns origin
    verify_origin_ownership(domain["origin_id"], current_user)
    
    # 3. Trigger check immediately
    domain_name = domain.get("domain_name")
    token = domain.get("verification_token")
    
    is_verified = verify_domain_dns(domain_name, token)
    
    if is_verified:
        db.domains_table.update_item(
            Key={"id": domain_id},
            UpdateExpression="SET dns_verified = :verified, ssl_status = :ssl",
            ExpressionAttributeValues={
                ":verified": True,
                ":ssl": "pending"
            }
        )
        invalidate_ssl_allowed_snapshot()
        return {
            "status": "success",
            "dns_verified": True,
            "ssl_status": "pending",
            "message": "Domain successfully verified!"
        }
    else:
        return {
            "status": "failed",
            "dns_verified": False,
            "message": "DNS records check failed. CNAME or TXT verification not found."
        }

# --- on-demand TLS ask endpoint -------------------------------------------
# Snapshot of the domains allowed to obtain a certificate, refreshed lazily.
_SSL_ALLOWED_SNAPSHOT: set = set()
_SSL_SNAPSHOT_AT: float = 0.0
_SSL_SNAPSHOT_LOCK = asyncio.Lock()
SSL_SNAPSHOT_REFRESH_SECONDS = 30.0
MAX_HOSTNAME_LENGTH = 253


def _load_ssl_allowed() -> set:
    """Every DNS-verified domain name, lowercased. One scan of a small table."""
    items = db.domains_table.scan().get("Items", [])
    return {
        str(i.get("domain_name", "")).strip().lower()
        for i in items
        if i.get("dns_verified", False) and i.get("domain_name")
    }


async def _ssl_allowed_set() -> set:
    global _SSL_ALLOWED_SNAPSHOT, _SSL_SNAPSHOT_AT
    now = time.monotonic()
    if _SSL_ALLOWED_SNAPSHOT and (now - _SSL_SNAPSHOT_AT) < SSL_SNAPSHOT_REFRESH_SECONDS:
        return _SSL_ALLOWED_SNAPSHOT
    async with _SSL_SNAPSHOT_LOCK:
        # Another request may have refreshed it while this one waited.
        now = time.monotonic()
        if _SSL_ALLOWED_SNAPSHOT and (now - _SSL_SNAPSHOT_AT) < SSL_SNAPSHOT_REFRESH_SECONDS:
            return _SSL_ALLOWED_SNAPSHOT
        try:
            _SSL_ALLOWED_SNAPSHOT = await asyncio.to_thread(_load_ssl_allowed)
            _SSL_SNAPSHOT_AT = now
        except Exception as exc:
            # Keep serving the previous snapshot rather than failing open or
            # failing every handshake because the database hiccuped.
            print(f"check-ssl-allowed: snapshot refresh failed, serving stale set: {exc}")
    return _SSL_ALLOWED_SNAPSHOT


@router.get("/check-ssl-allowed")
async def check_ssl_allowed(domain: str = ""):
    candidate = (domain or "").strip().lower()
    if not candidate:
        raise HTTPException(status_code=400, detail="domain parameter is required")
    # Reject implausible hostnames before touching any shared state.
    if len(candidate) > MAX_HOSTNAME_LENGTH or not _HOSTNAME_RE.match(candidate):
        raise HTTPException(status_code=400, detail="Domain not registered")

    allowed = await _ssl_allowed_set()
    if candidate not in allowed:
        raise HTTPException(status_code=400, detail="Domain not registered")

    return {"status": "allowed", "domain": candidate}


def invalidate_ssl_allowed_snapshot() -> None:
    """Force the next ask to reload -- call after a domain is verified or removed."""
    global _SSL_SNAPSHOT_AT
    _SSL_SNAPSHOT_AT = 0.0


import os

origins_domains_router = APIRouter(prefix="/api/origins", tags=["Domains"])

def format_domain(domain_data: dict) -> dict:
    dns_verified = domain_data.get("dns_verified", False)
    return {
        "domain_id": domain_data.get("id"),
        "origin_id": domain_data.get("origin_id"),
        "domain_name": domain_data.get("domain_name"),
        "verification_status": "verified" if dns_verified else "pending",
        "dns_verification_token": domain_data.get("verification_token"),
        "cname_target": os.getenv("WAF_CNAME_TARGET", "cdn.local"),
        "ssl_status": domain_data.get("ssl_status", "none"),
        "created_at": domain_data.get("created_at"),
    }

@origins_domains_router.get("/{origin_id}/domains")
async def list_domains_by_origin(origin_id: str, current_user: dict = Depends(get_current_user)):
    verify_origin_ownership(origin_id, current_user)
    
    try:
        from boto3.dynamodb.conditions import Key
        response = db.domains_table.query(
            IndexName="origin_id-index",
            KeyConditionExpression=Key("origin_id").eq(origin_id)
        )
        items = response.get("Items", [])
    except Exception:
        from boto3.dynamodb.conditions import Attr
        response = db.domains_table.scan(
            FilterExpression=Attr("origin_id").eq(origin_id)
        )
        items = response.get("Items", [])
        
    formatted = [format_domain(item) for item in items]
    return {"domains": formatted}

class DomainCreatePayload(BaseModel):
    domain_name: str

    @field_validator("domain_name")
    @classmethod
    def _domain_name_must_be_hostname(cls, v: str) -> str:
        return _validate_hostname(v)

@origins_domains_router.post("/{origin_id}/domains")
async def create_domain_under_origin(origin_id: str, payload: DomainCreatePayload, current_user: dict = Depends(get_current_user)):
    verify_origin_ownership(origin_id, current_user)

    domain_name = payload.domain_name

    from boto3.dynamodb.conditions import Attr
    response = db.domains_table.scan(
        FilterExpression=Attr("domain_name").eq(domain_name)
    )
    if response.get("Items"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Domain name {domain_name} is already registered."
        )
        
    domain_id = str(uuid.uuid4())
    verification_token = f"waf-token-{uuid.uuid4().hex[:16]}"
    now = datetime.now().isoformat() + "Z"
    
    domain_data = {
        "id": domain_id,
        "origin_id": origin_id,
        "domain_name": domain_name,
        "verification_token": verification_token,
        "dns_verified": False,
        "ssl_status": "none",
        "created_at": now,
        "updated_at": now
    }
    
    try:
        db.domains_table.put_item(Item=domain_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to save domain: {e}"
        )
        
    dns_instructions = {
        "cname_record": {
            "type": "CNAME",
            "name": domain_name,
            "value": os.getenv("WAF_CNAME_TARGET", "cdn.local")
        },
        "txt_record": {
            "type": "TXT",
            "name": f"_waf-challenge.{domain_name}",
            "value": verification_token
        }
    }
    
    return {
        "domain": format_domain(domain_data),
        "dns_instructions": dns_instructions
    }

@origins_domains_router.post("/{origin_id}/domains/{domain_id}/verify")
async def verify_domain_now_under_origin(origin_id: str, domain_id: str, current_user: dict = Depends(get_current_user)):
    verify_origin_ownership(origin_id, current_user)
    
    res = db.domains_table.get_item(Key={"id": domain_id})
    domain = res.get("Item")
    if not domain or domain.get("origin_id") != origin_id:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    domain_name = domain.get("domain_name")
    token = domain.get("verification_token")
    
    is_verified = verify_domain_dns(domain_name, token)
    
    if is_verified:
        db.domains_table.update_item(
            Key={"id": domain_id},
            UpdateExpression="SET dns_verified = :verified, ssl_status = :ssl",
            ExpressionAttributeValues={
                ":verified": True,
                ":ssl": "pending"
            }
        )
        return {
            "status": "verified",
            "message": "Domain successfully verified!"
        }
    else:
        return {
            "status": "failed",
            "message": "DNS records check failed. CNAME or TXT verification not found."
        }

@origins_domains_router.delete("/{origin_id}/domains/{domain_id}")
async def delete_domain_under_origin(origin_id: str, domain_id: str, current_user: dict = Depends(get_current_user)):
    verify_origin_ownership(origin_id, current_user)
    
    res = db.domains_table.get_item(Key={"id": domain_id})
    domain = res.get("Item")
    if not domain or domain.get("origin_id") != origin_id:
        raise HTTPException(status_code=404, detail="Domain not found")
        
    try:
        db.domains_table.delete_item(Key={"id": domain_id})
        invalidate_ssl_allowed_snapshot()
        return {"status": "success", "message": f"Domain {domain['domain_name']} deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
