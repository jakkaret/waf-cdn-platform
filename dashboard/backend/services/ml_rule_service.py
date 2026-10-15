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
    _pg = None  # PgPendingRuleRepository in PostgreSQL mode

    def __init__(self):
        self.db = DynamoDBService()
        self.rule_manager = RuleManager()
        from services.dynamodb_service import data_backend
        # postgres: waf.pending_rules through PgPendingRuleRepository (no I/O
        # here: api/ml_rules.py builds this at module level).
        self._pg = None
        if data_backend() == "postgres":
            from services.pg_store import PgPendingRuleRepository
            self._pg = PgPendingRuleRepository()
            self._table = None
        else:
            self._table = self.db.dynamodb.Table("waf_pending_rules")

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

        if self._pg is not None:
            return with_defaults(self._pg.create(item))
        self._table.put_item(Item=item)
        return item

    def find_pending_by_dedup_key(self, dedup_key: str) -> Optional[Dict[str, Any]]:
        """The pending rule a new proposal with this key should merge into, if any."""
        if not dedup_key:
            return None
        if self._pg is not None:
            found = self._pg.find_pending_by_dedup_key(dedup_key)
            return with_defaults(found) if found else None
        for item in self.list_rules("pending"):
            if item.get("dedup_key") == dedup_key:
                return item
        return None

    def record_hit(self, rule: Dict[str, Any], rule_data: Dict[str, Any]) -> Dict[str, Any]:
        """Add one more request behind an existing pending rule (count, last seen, newest examples)."""
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if self._pg is not None:
            updated = self._pg.record_hit(rule["rule_id"], _example(rule_data, timestamp), timestamp)
            return with_defaults(updated) if updated else rule
        examples = [_example(rule_data, timestamp)] + list(rule.get("examples") or [])
        examples = examples[:MAX_EXAMPLES]
        hit_count = int(rule.get("hit_count") or 1) + 1
        self._table.update_item(
            Key={"rule_id": rule["rule_id"], "created_at": rule["created_at"]},
            UpdateExpression="SET hit_count = :n, examples = :ex, last_seen_at = :t",
            ExpressionAttributeValues={":n": hit_count, ":ex": examples, ":t": timestamp},
        )
        return {**rule, "hit_count": hit_count, "examples": examples, "last_seen_at": timestamp}

    def save_backtest(self, rule: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Any]:
        """Keep the latest backtest on the rule so the queue shows it without re-running."""
        if self._pg is not None:
            self._pg.save_backtest(rule["rule_id"], result)
            return {**rule, "backtest": result}
        self._table.update_item(
            Key={"rule_id": rule["rule_id"], "created_at": rule["created_at"]},
            UpdateExpression="SET backtest = :b",
            ExpressionAttributeValues={":b": result},
        )
        return {**rule, "backtest": result}

    def list_rules(self, status: str = None) -> List[Dict[str, Any]]:
        """List rules, optionally filtered by status."""
        if self._pg is not None:
            try:
                return [with_defaults(i) for i in self._pg.list(status)]
            except Exception as e:
                print(f"Error fetching rules: {e}")
                return []
        try:
            if status:
                response = self._table.query(
                    IndexName='status-index',
                    KeyConditionExpression=Key('status').eq(status)
                )
                items = response.get("Items", [])
            else:
                response = self._table.scan()
                items = response.get("Items", [])
            
            # Sort by created_at descending
            items.sort(key=lambda x: x.get("created_at", ""), reverse=True)
            return [with_defaults(i) for i in items]
        except Exception as e:
            print(f"Error fetching rules: {e}")
            return []

    def get_rule_detail(self, rule_id: str) -> Optional[Dict[str, Any]]:
        if self._pg is not None:
            found = self._pg.get(rule_id)
            return with_defaults(found) if found else None
        try:
            # Since created_at is the sort key, we need to query by rule_id and scan if we don't know created_at,
            # OR we can query the partition key. Wait, the partition key is rule_id and sort key is created_at.
            # Querying just the partition key works to get all items with that rule_id.
            response = self._table.query(
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

    def _max_rule_id_on_disk(self) -> int:
        """Highest numeric id among the rule files (0 when none)."""
        ids = []
        for r in self.rule_manager.list_rules():
            try:
                ids.append(int(r["id"].replace("custom-", "").replace("ml-", "")))
            except ValueError:
                continue
        return max(ids) if ids else 0

    def approve_rule(self, rule_id: str, approved_by: str, on_approved=None,
                     on_deploy_failed=None) -> Dict[str, Any]:
        """Approve and deploy a pending rule.

        PostgreSQL, in three steps (nothing slow inside the transaction):
        1. one short transaction: lock, allocate the next ModSecurity id
           above both the files on disk and every id ever recorded (a deleted
           ml-<id>.conf must not hand out a used id again), mark approved and
           call on_approved(rule) -- the audit event -- so both commit together;
        2. after commit: write ml-<id>.conf and reload nginx;
        3. if step 2 fails: a compensating transaction puts the rule back to
           pending and calls on_deploy_failed(rule, error) (the approve event
           cannot be deleted: audit_logs is append-only), removes a file it
           wrote, then re-raises.
        """
        if self._pg is not None:
            from db import pool
            with pool.transaction():
                rule = self._pg.reserve_approval(rule_id, approved_by, self._max_rule_id_on_disk())
                if on_approved:
                    on_approved(rule)
            modsec_rule_id = rule["deployed_rule_id"]
            try:
                secrule_code = rule["secrule_template"].replace("{RULE_ID}", str(modsec_rule_id))
                self.rule_manager.write_ml_rule(modsec_rule_id, secrule_code)
            except Exception as exc:
                try:
                    with pool.transaction():
                        self._pg.undo_approval(rule_id, modsec_rule_id)
                        if on_deploy_failed:
                            on_deploy_failed(rule, exc)
                finally:
                    try:
                        self.rule_manager.delete_rule(f"ml-{modsec_rule_id}")
                    except Exception:
                        pass
                raise
            return with_defaults(rule)

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
        self._table.update_item(
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
        if on_approved:
            on_approved(rule)
        return rule

    def reject_rule(self, rule_id: str, rejected_by: str, reason: str = "") -> Dict[str, Any]:
        if self._pg is not None:
            return with_defaults(self._pg.reject(rule_id, rejected_by, reason))
        rule = self.get_rule_detail(rule_id)
        if not rule:
            raise ValueError("Rule not found")
            
        if rule.get("status") != "pending":
            raise ValueError(f"Rule is already {rule.get('status')}")
            
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._table.update_item(
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
        if self._pg is not None:
            return self._pg.reject_legacy(rejected_by, reason)
        pending, kwargs = [], {"IndexName": "status-index", "KeyConditionExpression": Key("status").eq("pending")}
        while True:
            response = self._table.query(**kwargs)
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
                self._table.update_item(
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
                
        if self._pg is not None:
            self._pg.delete(rule_id)
            return True
        self._table.delete_item(
            Key={"rule_id": rule_id, "created_at": rule["created_at"]}
        )
        return True
