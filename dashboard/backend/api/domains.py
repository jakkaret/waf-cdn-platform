from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from typing import List, Optional
import uuid
from datetime import datetime
from services.rbac import get_current_user, verify_origin_ownership
from services.dynamodb_service import DynamoDBService
from services.dns_service import verify_domain_dns

router = APIRouter(prefix="/api/domains", tags=["Domains"])
db = DynamoDBService()

class DomainCreate(BaseModel):
    origin_id: str
    domain_name: str

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

@router.get("/check-ssl-allowed")
async def check_ssl_allowed(domain: str):
    if not domain:
        raise HTTPException(status_code=400, detail="domain parameter is required")
        
    try:
        import boto3
        # Query using the domain_name-index GSI
        response = db.domains_table.query(
            IndexName="domain_name-index",
            KeyConditionExpression=boto3.dynamodb.conditions.Key("domain_name").eq(domain)
        )
        items = response.get("Items", [])
        
        # If GSI query fails or returns empty, fallback to scan
        if not items:
            from boto3.dynamodb.conditions import Attr
            response = db.domains_table.scan(
                FilterExpression=Attr("domain_name").eq(domain)
            )
            items = response.get("Items", [])
            
        if not items:
            raise HTTPException(status_code=400, detail="Domain not registered")
            
        domain_item = items[0]
        if not domain_item.get("dns_verified", False):
            raise HTTPException(status_code=400, detail="Domain DNS not verified")
            
        # Return 200 OK to Caddy indicating that it is allowed to request SSL cert
        return {"status": "allowed", "domain": domain}
        
    except HTTPException as he:
        raise he
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
