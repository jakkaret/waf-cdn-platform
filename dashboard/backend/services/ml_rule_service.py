import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from services.dynamodb_service import DynamoDBService
from services.rule_manager import RuleManager
import boto3
from boto3.dynamodb.conditions import Key, Attr

class MLRuleService:
    def __init__(self):
        self.db = DynamoDBService()
        self.rule_manager = RuleManager()
        # Ensure the table is accessible
        self.table = self.db.dynamodb.Table("waf_pending_rules")

    def create_pending_rule(self, rule_data: Dict[str, Any], created_by: str = "ml-auto") -> Dict[str, Any]:
        """Save a new pending rule to DynamoDB."""
        rule_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        item = {
            "rule_id": rule_id,
            "created_at": timestamp,
            "status": "pending",
            "pattern": rule_data.get("pattern", ""),
            "variable": rule_data.get("variable", "REQUEST_URI|REQUEST_BODY"),
            "attack_type": rule_data.get("attack_type", "Anomaly"),
            "severity": rule_data.get("severity", "CRITICAL"),
            "secrule_template": rule_data.get("secrule_template", ""),
            "source_url": rule_data.get("source_url", ""),
            "source_method": rule_data.get("source_method", "GET"),
            "created_by": created_by
        }
        
        self.table.put_item(Item=item)
        return item

    def list_rules(self, status: str = None) -> List[Dict[str, Any]]:
        """List rules, optionally filtered by status."""
        try:
            if status:
                response = self.table.query(
                    IndexName='status-index',
                    KeyConditionExpression=Key('status').eq(status)
                )
                items = response.get("Items", [])
            else:
                response = self.table.scan()
                items = response.get("Items", [])
            
            # Sort by created_at descending
            items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return items
        except Exception as e:
            print(f"Error fetching rules: {e}")
            return []

    def get_rule_detail(self, rule_id: str) -> Optional[Dict[str, Any]]:
        try:
            # Since created_at is the sort key, we need to query by rule_id and scan if we don't know created_at,
            # OR we can query the partition key. Wait, the partition key is rule_id and sort key is created_at.
            # Querying just the partition key works to get all items with that rule_id.
            response = self.table.query(
                KeyConditionExpression=Key('rule_id').eq(rule_id)
            )
            items = response.get("Items", [])
            if items:
                return items[0]
            return None
        except Exception as e:
            print(f"Error getting rule detail: {e}")
            return None

    def _get_next_rule_id(self) -> int:
        """Find the next available ModSecurity rule ID."""
        START_RULE_ID = 1000500
        existing_rules = self.rule_manager.list_rules()
        existing_ids = []
        for r in existing_rules:
            try:
                # Remove 'ml-' or 'custom-' prefix if present
                clean_id = r["id"].replace("custom-", "").replace("ml-", "")
                existing_ids.append(int(clean_id))
            except ValueError:
                continue
                
        if existing_ids:
            return max(max(existing_ids) + 1, START_RULE_ID)
        return START_RULE_ID

    def approve_rule(self, rule_id: str, approved_by: str) -> Dict[str, Any]:
        rule = self.get_rule_detail(rule_id)
        if not rule:
            raise ValueError("Rule not found")
            
        if rule.get("status") != "pending":
            raise ValueError(f"Rule is already {rule.get('status')}")

        # 1. Determine new ModSecurity Rule ID
        modsec_rule_id = self._get_next_rule_id()
        
        # 2. Build actual SecRule code
        secrule_code = rule["secrule_template"].replace("{RULE_ID}", str(modsec_rule_id))
        
        # 3. Write to custom-rules directory via RuleManager
        # We need a new method in RuleManager to write raw config or ml config
        self.rule_manager.write_ml_rule(modsec_rule_id, secrule_code)
        
        # 4. Update DynamoDB
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.table.update_item(
            Key={"rule_id": rule_id, "created_at": rule["created_at"]},
            UpdateExpression="SET #s = :status, reviewed_by = :reviewer, reviewed_at = :time, deployed_rule_id = :drid",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "approved",
                ":reviewer": approved_by,
                ":time": timestamp,
                ":drid": modsec_rule_id
            }
        )
        
        rule["status"] = "approved"
        rule["deployed_rule_id"] = modsec_rule_id
        return rule

    def reject_rule(self, rule_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
        rule = self.get_rule_detail(rule_id)
        if not rule:
            raise ValueError("Rule not found")
            
        if rule.get("status") != "pending":
            raise ValueError(f"Rule is already {rule.get('status')}")
            
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.table.update_item(
            Key={"rule_id": rule_id, "created_at": rule["created_at"]},
            UpdateExpression="SET #s = :status, reviewed_by = :reviewer, reviewed_at = :time, reject_reason = :reason",
            ExpressionAttributeNames={"#s": "status"},
            ExpressionAttributeValues={
                ":status": "rejected",
                ":reviewer": rejected_by,
                ":time": timestamp,
                ":reason": reason
            }
        )
        
        rule["status"] = "rejected"
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        rule = self.get_rule_detail(rule_id)
        if not rule:
            return False
            
        # If it was approved and deployed, we should ideally remove it from WAF too,
        # but for now we just remove the tracking record, or we could actually delete the .conf file.
        if rule.get("status") == "approved" and rule.get("deployed_rule_id"):
            try:
                self.rule_manager.delete_rule(f"ml-{rule['deployed_rule_id']}")
            except Exception:
                pass
                
        self.table.delete_item(
            Key={"rule_id": rule_id, "created_at": rule["created_at"]}
        )
        return True
