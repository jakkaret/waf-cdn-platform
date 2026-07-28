import asyncio
import time
from services.dynamodb_service import DynamoDBService
from services.dns_service import verify_domain_dns

async def dns_verification_worker():
    print("=" * 50)
    print("🚀 Starting DNS Verification Worker...")
    print("=" * 50)
    
    db = DynamoDBService()
    
    while True:
        try:
            # 1. Scan for unverified domains
            # In DynamoDB, we can filter by dns_verified = False (or attribute not exists, or equal to False)
            from boto3.dynamodb.conditions import Attr
            
            response = db.domains_table.scan(
                FilterExpression=Attr("dns_verified").eq(False)
            )
            unverified_domains = response.get("Items", [])
            
            if unverified_domains:
                print(f"[DNS Worker] Found {len(unverified_domains)} unverified domains to check...")
                
            for domain in unverified_domains:
                domain_id = domain.get("id")
                domain_name = domain.get("domain_name")
                token = domain.get("verification_token")
                
                print(f"[DNS Worker] Checking domain: {domain_name} (ID: {domain_id})")
                
                # Check DNS
                is_verified = verify_domain_dns(domain_name, token)
                
                if is_verified:
                    print(f"[DNS Worker] ✅ Domain {domain_name} successfully verified!")
                    # Update DynamoDB: set dns_verified = True, ssl_status = 'pending'
                    db.domains_table.update_item(
                        Key={"id": domain_id},
                        UpdateExpression="SET dns_verified = :verified, ssl_status = :ssl",
                        ExpressionAttributeValues={
                            ":verified": True,
                            ":ssl": "pending"
                        }
                    )
                    
        except Exception as e:
            print(f"[DNS Worker] Error in check loop: {e}")
            
        # Wait 10 seconds before next scan
        await asyncio.sleep(10)

if __name__ == "__main__":
    # If run directly, run the worker loop
    import dotenv
    dotenv.load_dotenv()
    try:
        asyncio.run(dns_verification_worker())
    except KeyboardInterrupt:
        print("DNS Worker stopped.")
