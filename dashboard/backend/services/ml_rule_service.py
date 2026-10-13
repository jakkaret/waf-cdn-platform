import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from services.dynamodb_service import DynamoDBService
from services.rule_manager import RuleManager
import boto3
from boto3.dynamodb.conditions import Key, Attr

# Newest request examples kept on a pending rule (record_hit).
MAX_EXAMPLES = 5


def _default_generator(created_by: str) -> str:
    """Generator of a rule stored before the field existed (or written without it)."""
    return "cve" if created_by == "cve-auto" else "rf-regex"


def _example(rule_data: Dict[str, Any], seen_at: str) -> Dict[str, Any]:
    return {
        "url": str(rule_data.get("source_url", ""))[:200],
        "method": rule_data.get("source_method", "GET"),
        "seen_at": seen_at,
    }


def with_defaults(item: Dict[str, Any]) -> Dict[str, Any]:
    """Fill the 2026-10-13 fields on rows written before they existed, so the API shape is stable."""
    item = dict(item)
    item.setdefault("generator", _default_generator(item.get("created_by", "")))
    item.setdefault("detector", "")
    item.setdefault("dedup_key", "")
    item["hit_count"] = int(item.get("hit_count") or 1)
    item.setdefault("examples", [])
    item.setdefault("last_seen_at", item.get("created_at", ""))
    return item


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
            "created_by": created_by,
            # CVE Auto-Patch (2026-09-22): empty string for every other
            # created_by. Used for dedup -- a scan never proposes a second
            # rule for a CVE ID that already has one in the queue.
            "cve_id": rule_data.get("cve_id", ""),
            # 2026-09-23: which origin's exposure prompted this proposal.
            # The CVE scanner knows it exactly (cve_feed.match_cves_to_origins
            # matches a CVE's keywords against one origin's tech_stack_tags).
            # The ML anomaly path does not: /api/ml/analyze receives only
            # url/method/body, with no Host, so it stores "" rather than
            # guessing -- an empty value here means "not attributable",
            # never "belongs to everyone".
            #
            # Attribution only. Approving a rule deploys it to ModSecurity
            # for every origin, so this does not make the queue per-tenant
            # and the endpoints stay admin-only (see api/ml_rules.py).
            "origin_id": rule_data.get("origin_id", ""),
            "origin_label": rule_data.get("origin_label", ""),
            # 2026-10-13: which generator wrote the rule ("rf-regex" = the
            # RandomForest path's fixed regex / 40-char literal, "gen3-detector"
            # = a Gen 3 value detector, "cve" = CVE Auto-Patch) and the key
            # repeats merge on. hit_count / examples / last_seen_at grow when
            # the same proposal comes back (record_hit) instead of the queue
            # getting one near-identical row per flagged request.
            "generator": rule_data.get("generator") or _default_generator(created_by),
            "detector": rule_data.get("detector", ""),
            "dedup_key": rule_data.get("dedup_key", ""),
            "hit_count": 1,
            "examples": [_example(rule_data, timestamp)],
            "last_seen_at": timestamp,
        }

        self.table.put_item(Item=item)
        return item

    def find_pending_by_dedup_key(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        """The pending rule a new proposal with this key should merge into, if any."""
        if not dedup_key:
            return None
        for item in self.list_rules("pending"):
            if item.get("dedup_key") == dedup_key:
                return item
        return None

    def record_hit(self, rule: Dict[str, Any], rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add one more request behind an existing pending rule (count, last seen, newest examples)."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        examples = [_example(rule_data, timestamp)] + list(rule.get("examples") or [])
        examples = examples[:MAX_EXAMPLES]
        hit_count = int(rule.get("hit_count") or 1) + 1
        self.table.update_item(
            Key={"rule_id": rule["rule_id"], "created_at": rule["created_at"]},
            UpdateExpression="SET hit_count = :n, examples = :ex, last_seen_at = :t",
            ExpressionAttributeValues={":n": hit_count, ":ex": examples, ":t": timestamp},
        )
        return {**rule, "hit_count": hit_count, "examples": examples, "last_seen_at": timestamp}

    def save_backtest(self, rule: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Keep the latest backtest on the rule so the queue shows it without re-running."""
        self.table.update_item(
            Key={"rule_id": rule["rule_id"], "created_at": rule["created_at"]},
            UpdateExpression="SET backtest = :b",
            ExpressionAttributeValues={":b": result},
        )
        return {**rule, "backtest": result}

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
            return [with_defaults(i) for i in items]
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
                return with_defaults(items[0])
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

    def reject_legacy_pending(self, rejected_by: str, reason: str) -> Dict[str, int]:
        """Reject every pending rule written by the retired RandomForest path ("rf-regex").

        2026-10-13: proposals come from Gen 3 only, and the RF rules left in the queue
        (~268 near-identical literals) only ever matched the request they came from.
        Gen3-detector and CVE rules are left alone. Pages through the status index, and
        each update is conditional on the rule still being pending, so a rule an admin
        approved meanwhile is skipped rather than overwritten.
        """
        pending, kwargs = [], {"IndexName": "status-index", "KeyConditionExpression": Key("status").eq("pending")}
        while True:
            response = self.table.query(**kwargs)
            pending.extend(response.get("Items", []))
            if not response.get("LastEvaluatedKey"):
                break
            kwargs["ExclusiveStartKey"] = response["LastEvaluatedKey"]

        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        rejected = skipped = 0
        for item in pending:
            if with_defaults(item)["generator"] != "rf-regex":
                continue
            try:
                self.table.update_item(
                    Key={"rule_id": item["rule_id"], "created_at": item["created_at"]},
                    UpdateExpression="SET #s = :status, reviewed_by = :reviewer, reviewed_at = :time, reject_reason = :reason",
                    ConditionExpression="#s = :pending",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={
                        ":status": "rejected",
                        ":pending": "pending",
                        ":reviewer": rejected_by,
                        ":time": timestamp,
                        ":reason": reason,
                    },
                )
                rejected += 1
            except Exception as e:  # ConditionalCheckFailed: reviewed meanwhile
                print(f"Skipping legacy rule {item.get('rule_id')}: {e}")
                skipped += 1
        return {"rejected": rejected, "skipped": skipped}

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
