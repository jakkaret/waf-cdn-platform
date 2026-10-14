import boto3
import os
import time
import uuid
from typing import List, Dict, Any, Optional
from datetime import datetime
from decimal import Decimal
from boto3.dynamodb.conditions import Attr, Key
from botocore.config import Config

from dotenv import load_dotenv, find_dotenv

load_dotenv(find_dotenv())
# Also try project root explicitly just in case
load_dotenv(os.path.join(os.path.dirname(__file__), '../../../.env'))

# In-Memory Cache for Alerts
_alerts_cache: List[Dict] = []
_alerts_cache_ts: float = 0.0
ALERTS_CACHE_TTL = 5.0  # Cache for 5 seconds

def invalidate_alerts_cache():
    global _alerts_cache_ts
    _alerts_cache_ts = 0.0

class DynamoDBService:
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "ap-southeast-1")

        # Migrated 2026-09-23 (scripts/migrate_alerts_to_origin_key.py).
        # waf_alerts was keyed (user_id, alert_id) with user_id hardcoded to
        # "default-user" by the only writer, so the partition key identified
        # nothing and every read was a full scan filtered in Python. v2 is
        # keyed (origin_id, alert_id): reads become per-origin queries and
        # the key means what it says. Rows whose Host could not be resolved
        # to a registered domain live in the UNATTRIBUTED partition.
        self.alerts_table_name = "waf_alerts_v2"
        self.rules_table_name = "waf_rules"
        self.users_table_name = "waf_users"
        endpoint_url = os.getenv("DYNAMODB_ENDPOINT_URL")
        self.dynamodb = boto3.resource(
            "dynamodb",
            region_name=self.region,
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
            endpoint_url=endpoint_url,
            # Fix 2026-09-07: no timeout meant a single stalled DynamoDB call
            # (e.g. a half-closed TCP connection) could hang this client
            # forever with no exception ever raised. Bound worst-case latency.
            config=Config(connect_timeout=3, read_timeout=5, retries={"max_attempts": 2}),
        )

        # Initialize tables
        self.alerts_table = self.dynamodb.Table(self.alerts_table_name)
        # Misnomer, kept because the physical table name cannot be changed
        # in place. "waf_rules" holds BOLA policies (services/bola_guard.py
        # is its only reader/writer, and it is empty in production), NOT
        # WAF rules: real SecRules live in modsecurity/custom-rules/*.conf
        # and are managed by services/rule_manager.py, which never touches
        # DynamoDB. Both names are bound so code reads honestly while the
        # existing accessor keeps working.
        self.rules_table = self.dynamodb.Table(self.rules_table_name)
        self.bola_policies_table = self.rules_table
        self.waf_users = self.dynamodb.Table(self.users_table_name)
        self.origins_table = self.dynamodb.Table("waf_origins")
        self.domains_table = self.dynamodb.Table("waf_domains")
        self.ssl_certs_table = self.dynamodb.Table("waf_ssl_certs")
        self.pending_rules_table = self.dynamodb.Table("waf_pending_rules")
        self.threat_patterns_table = self.dynamodb.Table("waf_threat_patterns")
        self.status_history_table = self.dynamodb.Table("waf_status_history")
        self.audit_log_table = self.dynamodb.Table("waf_audit_log")
        self.postmortems_table = self.dynamodb.Table("waf_postmortems")
    
    def convert_floats(self, obj):
        if isinstance(obj, float):
            return Decimal(str(obj))
        elif isinstance(obj, dict):
            return {k: self.convert_floats(v) for k, v in obj.items()}
        elif isinstance(obj, list):
            return [self.convert_floats(i) for i in obj]
        else:
            return obj
    # ALERTS
    def save_alert(
        self,
        user_id: str,
        alert_id: str,
        ip: str,
        url: str,
        status: str,
        message: str,
        ai_summary: str = None,
        rule_id: str = None,
        attack_type: str = None,
        severity: str = None,
        edge_node: str = None,
        domain: str = None,
        origin_id: str = None,
    ) -> bool:

        #บันทึก alert ที่จำเป็นลง DynamoDB (waf_alerts)

        try:
            # Partition key since the 2026-09-23 migration to waf_alerts_v2.
            # Resolved from the captured Host when the caller did not
            # already do it; an unresolvable Host lands in the
            # UNATTRIBUTED partition rather than being attributed to a
            # guessed owner.
            resolved_origin_id = str(origin_id or "").strip()
            if not resolved_origin_id and domain:
                resolved_origin_id = self.get_origin_id_for_domain(domain)
            item = {
                "origin_id": resolved_origin_id or self.ALERTS_UNATTRIBUTED,
                # No longer a key; kept because pre-migration rows carry it.
                "user_id": user_id,
                "alert_id": alert_id,
                "ip": ip,
                "url": url,
                "status": str(status),
                "message": message,
                "timestamp": datetime.now().isoformat() + "Z",
                "read": False
            }
            if ai_summary:
                item["ai_summary"] = ai_summary
            if rule_id:
                item["rule_id"] = rule_id
            if attack_type:
                item["attack_type"] = attack_type
            if severity:
                item["severity"] = severity
            if edge_node:
                item["edge_node"] = edge_node
            if domain:
                # 2026-09-22: the real tenant-scoping key for alerts.
                # user_id has always been a hardcoded "default-user"
                # placeholder (confirmed in services/telegram_listener.py,
                # the real production writer) -- it was never a usable
                # owner. The Host header, captured but previously discarded
                # in services/log_forward.py's log pipeline, is what
                # actually identifies which tenant's origin this alert
                # belongs to. See api/ai_summary.py's _alert_belongs_to_tenant.
                item["domain"] = str(domain).strip().lower()
            self.alerts_table.put_item(Item=item)
            # Update In-Memory Cache immediately
            global _alerts_cache, _alerts_cache_ts
            _alerts_cache = [item] + [x for x in _alerts_cache if x.get("alert_id") != alert_id]
            _alerts_cache_ts = time.monotonic()
            # (success is silent; failures are logged in the except below)
            return True
        except Exception as e:
            print("Failed to save alert:", e)
            return False

    ALERTS_UNATTRIBUTED = "unattributed"

    def get_alerts_for_origins(self, origin_ids: List[str], max_items: int = 2000) -> List[Dict]:
        """Alerts belonging to specific origins, by partition key.

        The point of the v2 key schema: a tenant's alerts are N indexed
        queries instead of scanning every tenant's rows and filtering in
        Python. Callers pass the origins the user can actually see
        (get_origins_visible_to_user, so viewer/editor grants included);
        the UNATTRIBUTED partition is deliberately NOT included here --
        those alerts have no resolvable owner and stay admin-only.
        """
        items: List[Dict] = []
        for origin_id in origin_ids:
            if not origin_id or len(items) >= max_items:
                continue
            kwargs = {
                "KeyConditionExpression": boto3.dynamodb.conditions.Key("origin_id").eq(str(origin_id)),
            }
            try:
                while len(items) < max_items:
                    response = self.alerts_table.query(**kwargs)
                    items.extend(response.get("Items", []))
                    last_key = response.get("LastEvaluatedKey")
                    if not last_key:
                        break
                    kwargs["ExclusiveStartKey"] = last_key
            except Exception as e:
                print(f"Failed to query alerts for origin {origin_id}:", e)
        return items[:max_items]

    def get_all_alerts(self, max_items: int = 2000) -> List[Dict]:
        """Fetch all alerts from DynamoDB with In-Memory Cache (TTL 5s) and full pagination"""
        global _alerts_cache, _alerts_cache_ts
        now = time.monotonic()
        if _alerts_cache and (now - _alerts_cache_ts) < ALERTS_CACHE_TTL:
            return _alerts_cache[:max_items]

        try:
            items = []
            response = self.alerts_table.scan()
            items.extend(response.get("Items", []))
            while "LastEvaluatedKey" in response and len(items) < max_items:
                response = self.alerts_table.scan(ExclusiveStartKey=response["LastEvaluatedKey"])
                items.extend(response.get("Items", []))
            items.sort(key=lambda x: str(x.get("timestamp", "")), reverse=True)
            _alerts_cache = items
            _alerts_cache_ts = now
            return items[:max_items]
        except Exception as e:
            print("Failed to fetch all alerts:", e)
            return _alerts_cache[:max_items] if _alerts_cache else []


    # ORIGINS
    def create_origin(self, origin_data: Dict) -> bool:
        try:
            self.origins_table.put_item(Item=origin_data)
            return True
        except Exception as e:
            print("Failed to create origin:", e)
            raise e

    def get_origins_by_user(self, admin_user_id: str) -> List[Dict]:
        try:
            response = self.origins_table.query(
                IndexName="admin_user_id-index",
                KeyConditionExpression=boto3.dynamodb.conditions.Key("admin_user_id").eq(admin_user_id)
            )
            return response.get("Items", [])
        except Exception as e:
            print("Failed to get origins by user:", e)
            return []

    def get_origin_id_for_domain(self, domain_name: str) -> str:
        """Resolve a Host header to the origin that owns it, exactly.

        Uses waf_domains' domain_name-index. Returns "" when the host is
        not a registered domain (direct-to-IP traffic, a probe for someone
        else's hostname, an unverified domain) -- callers must treat that
        as "not attributable" and never as "belongs to everyone".
        """
        clean = str(domain_name or "").strip().lower().rstrip(".")
        if ":" in clean and not clean.startswith("["):
            clean = clean.split(":", 1)[0]
        if not clean:
            return ""
        try:
            response = self.domains_table.query(
                IndexName="domain_name-index",
                KeyConditionExpression=boto3.dynamodb.conditions.Key("domain_name").eq(clean),
            )
            items = response.get("Items", [])
            return str(items[0].get("origin_id") or "") if items else ""
        except Exception as e:
            print(f"Failed to resolve origin for domain {clean}:", e)
            return ""

    def get_domains_by_origin_ids(self, origin_ids: List[str]) -> List[Dict]:
        """Domains belonging to the given origins, via waf_domains'
        origin_id-index.

        Callers used to scan() the whole table and filter origin_id in
        Python. Two problems with that, beyond reading every tenant's rows
        to answer a single-tenant question: scan() returns at most 1MB per
        call, and none of those call sites paginated -- so once the table
        crosses that size, domains start disappearing from tenant filters
        with no error anywhere. The GSI has existed since the table was
        created (scripts/create_origins_tables.py); it simply was not used.

        Origins per user are quota-capped (10), so this is a handful of
        indexed queries against one unbounded table read.
        """
        items: List[Dict] = []
        for origin_id in origin_ids:
            if not origin_id:
                continue
            try:
                kwargs = {
                    "IndexName": "origin_id-index",
                    "KeyConditionExpression": boto3.dynamodb.conditions.Key("origin_id").eq(str(origin_id)),
                }
                while True:
                    response = self.domains_table.query(**kwargs)
                    items.extend(response.get("Items", []))
                    last_key = response.get("LastEvaluatedKey")
                    if not last_key:
                        break
                    kwargs["ExclusiveStartKey"] = last_key
            except Exception as e:
                print(f"Failed to get domains for origin {origin_id}:", e)
        return items

    def get_origin_by_id(self, origin_id: str) -> Dict:
        try:
            response = self.origins_table.get_item(Key={"id": origin_id})
            return response.get("Item", {})
        except Exception as e:
            print("Failed to get origin by id:", e)
            return {}

    def update_origin(self, origin_id: str, update_data: Dict) -> bool:
        try:
            update_expr = "SET "
            expr_attr_values = {}
            expr_attr_names = {}
            for k, v in update_data.items():
                update_expr += f"#{k} = :{k}, "
                expr_attr_values[f":{k}"] = v
                expr_attr_names[f"#{k}"] = k
            
            update_expr = update_expr.rstrip(", ")
            
            self.origins_table.update_item(
                Key={"id": origin_id},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_attr_values,
                ExpressionAttributeNames=expr_attr_names
            )
            return True
        except Exception as e:
            print("Failed to update origin:", e)
            return False

    def add_origin_viewer(self, origin_id: str, viewer_user_id: str) -> bool:
        try:
            self.origins_table.update_item(
                Key={"id": origin_id},
                UpdateExpression="ADD viewer_user_ids :v",
                ExpressionAttributeValues={":v": {viewer_user_id}},
            )
            return True
        except Exception as e:
            print("Failed to add origin viewer:", e)
            return False

    def remove_origin_viewer(self, origin_id: str, viewer_user_id: str) -> bool:
        try:
            self.origins_table.update_item(
                Key={"id": origin_id},
                UpdateExpression="DELETE viewer_user_ids :v",
                ExpressionAttributeValues={":v": {viewer_user_id}},
            )
            return True
        except Exception as e:
            print("Failed to remove origin viewer:", e)
            return False

    # Team Workspace (2026-09-22): editor_user_ids mirrors viewer_user_ids
    # exactly -- same ADD/DELETE-on-a-Set update pattern, kept as its own
    # attribute rather than upgrading viewer_user_ids to a role map, so the
    # existing viewer grant/revoke code and every read of viewer_user_ids
    # elsewhere stays untouched.
    def add_origin_editor(self, origin_id: str, editor_user_id: str) -> bool:
        try:
            self.origins_table.update_item(
                Key={"id": origin_id},
                UpdateExpression="ADD editor_user_ids :v",
                ExpressionAttributeValues={":v": {editor_user_id}},
            )
            return True
        except Exception as e:
            print("Failed to add origin editor:", e)
            return False

    def remove_origin_editor(self, origin_id: str, editor_user_id: str) -> bool:
        try:
            self.origins_table.update_item(
                Key={"id": origin_id},
                UpdateExpression="DELETE editor_user_ids :v",
                ExpressionAttributeValues={":v": {editor_user_id}},
            )
            return True
        except Exception as e:
            print("Failed to remove origin editor:", e)
            return False

    def delete_origin(self, origin_id: str) -> bool:
        try:
            self.origins_table.update_item(
                Key={"id": origin_id},
                UpdateExpression="SET #status = :archived, archived_at = :now REMOVE deleted_at",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":archived": "archived",
                    ":now": datetime.now().isoformat() + "Z"
                }
            )
            return True
        except Exception as e:
            print("Failed to archive origin:", e)
            return False

    def restore_origin(self, origin_id: str) -> bool:
        try:
            self.origins_table.update_item(
                Key={"id": origin_id},
                UpdateExpression="SET #status = :active REMOVE archived_at, deleted_at",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":active": "active"
                }
            )
            return True
        except Exception as e:
            print("Failed to restore origin:", e)
            return False

    # ------------------------------------------------------------------
    # Named data-access methods (migration Phase 1). Every read/write of a
    # table outside this class goes through one of these, so the PostgreSQL
    # store can implement the same interface method by method.
    # ------------------------------------------------------------------
    @staticmethod
    def _scan_all(table, **kwargs) -> List[Dict]:
        """Every matching row: scan() returns at most 1 MB per page."""
        items: List[Dict] = []
        while True:
            page = table.scan(**kwargs)
            items.extend(page.get("Items", []))
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                return items
            kwargs["ExclusiveStartKey"] = last_key

    @staticmethod
    def _query_all(table, **kwargs) -> List[Dict]:
        items: List[Dict] = []
        while True:
            page = table.query(**kwargs)
            items.extend(page.get("Items", []))
            last_key = page.get("LastEvaluatedKey")
            if not last_key:
                return items
            kwargs["ExclusiveStartKey"] = last_key

    @staticmethod
    def _set_expression(fields: Dict[str, Any]):
        names, values, clauses = {}, {}, []
        for i, (k, v) in enumerate(fields.items()):
            names[f"#f{i}"] = k
            values[f":v{i}"] = v
            clauses.append(f"#f{i} = :v{i}")
        return "SET " + ", ".join(clauses), names, values

    def ping(self) -> bool:
        """Reachability probe for /api/system/status (raises on failure)."""
        return bool(self.domains_table.table_status)

    # ---- domains --------------------------------------------------------
    def get_domain(self, domain_id: str) -> Optional[Dict]:
        return self.domains_table.get_item(Key={"id": domain_id}).get("Item")

    def get_domain_by_name(self, domain_name: str) -> Optional[Dict]:
        items = self._scan_all(self.domains_table, FilterExpression=Attr("domain_name").eq(domain_name))
        return items[0] if items else None

    def list_domains(self, origin_id: Optional[str] = None,
                     dns_verified: Optional[bool] = None) -> List[Dict]:
        if origin_id is not None:
            items = self._query_all(
                self.domains_table, IndexName="origin_id-index",
                KeyConditionExpression=Key("origin_id").eq(str(origin_id)))
        elif dns_verified is not None:
            items = self._scan_all(self.domains_table, FilterExpression=Attr("dns_verified").eq(dns_verified))
        else:
            items = self._scan_all(self.domains_table)
        if dns_verified is not None:
            items = [d for d in items if bool(d.get("dns_verified", False)) == dns_verified]
        return items

    def create_domain(self, item: Dict) -> Dict:
        """Insert a domain row; DuplicateDomain if the name is taken."""
        if self.get_domain_by_name(item["domain_name"]):
            raise DuplicateDomain(f"Domain name {item['domain_name']} is already registered.")
        self.domains_table.put_item(Item=item)
        return item

    def update_domain(self, domain_id: str, fields: Dict[str, Any]) -> None:
        expr, names, values = self._set_expression(fields)
        self.domains_table.update_item(Key={"id": domain_id}, UpdateExpression=expr,
                                       ExpressionAttributeNames=names,
                                       ExpressionAttributeValues=values)

    def delete_domain(self, domain_id: str) -> None:
        self.domains_table.delete_item(Key={"id": domain_id})

    def delete_domains_for_origin(self, origin_id: str) -> int:
        rows = self._scan_all(self.domains_table, FilterExpression=Attr("origin_id").eq(origin_id))
        for row in rows:
            self.domains_table.delete_item(Key={"id": row["id"]})
        return len(rows)

    # ---- origins ----------------------------------------------------------
    def list_origins(self) -> List[Dict]:
        return self._scan_all(self.origins_table)

    def hard_delete_origin(self, origin_id: str) -> None:
        self.origins_table.delete_item(Key={"id": origin_id})

    # ---- hostnames ----------------------------------------------------------
    def verified_hostnames_active(self) -> List[tuple]:
        """[(hostname, origin_id)] for DNS-verified BYO domains and tunnel
        domains of origins that are not archived/deleted. Not de-duplicated:
        a host claimed by two origins appears twice (callers decide)."""
        origins = self.list_origins()
        active = {str(o.get("id")) for o in origins if o.get("status") not in ("archived", "deleted")}
        pairs: List[tuple] = []
        for d in self.list_domains():
            oid = str(d.get("origin_id") or "")
            if d.get("dns_verified") and d.get("domain_name") and oid in active:
                pairs.append((str(d["domain_name"]), oid))
        for o in origins:
            if str(o.get("id")) not in active:
                continue
            for host in o.get("tunnel_domains") or []:
                if host:
                    pairs.append((str(host), str(o.get("id"))))
        return pairs

    def hostname_owner_map(self) -> Dict[str, str]:
        """host -> owning admin_user_id for every BYO and tunnel hostname,
        verified or not and whatever the origin status (threat-intel
        attribution semantics)."""
        mapping: Dict[str, str] = {}
        owner_by_origin_id = {}
        for o in self.list_origins():
            origin_id, owner = o.get("id"), o.get("admin_user_id")
            if origin_id and owner:
                owner_by_origin_id[origin_id] = owner
            if owner:
                for d in (o.get("tunnel_domains") or []):
                    if d:
                        mapping[str(d).strip().lower()] = owner
        for d in self.list_domains():
            name, owner = d.get("domain_name"), owner_by_origin_id.get(d.get("origin_id"))
            if name and owner:
                mapping[str(name).strip().lower()] = owner
        return mapping

    # ---- alerts -------------------------------------------------------------
    def put_alert(self, item: Dict) -> None:
        self.alerts_table.put_item(Item=item)

    def mark_alert_read(self, origin_id: str, alert_id: str) -> None:
        self.alerts_table.update_item(
            Key={"origin_id": origin_id, "alert_id": alert_id},
            UpdateExpression="SET #r = :val",
            ExpressionAttributeNames={"#r": "read"},
            ExpressionAttributeValues={":val": True},
        )
        invalidate_alerts_cache()

    def mark_alerts_read(self, alerts: List[Dict]) -> int:
        """Mark the given alert rows read (each needs origin_id + alert_id).
        BatchWriteItem has no update, so full rows are rewritten."""
        n = 0
        with self.alerts_table.batch_writer() as batch:
            for a in alerts:
                if not a.get("origin_id") or not a.get("alert_id"):
                    continue
                batch.put_item(Item={**a, "read": True})
                n += 1
        invalidate_alerts_cache()
        return n

    # ---- postmortems ------------------------------------------------------
    def save_postmortem(self, item: Dict) -> None:
        self.postmortems_table.put_item(Item=item)

    def list_postmortems(self, origin_ids: List[str], limit: Optional[int] = None) -> List[Dict]:
        wanted = {str(o) for o in origin_ids}
        items = [i for i in self._scan_all(self.postmortems_table) if i.get("origin_id") in wanted]
        items.sort(key=lambda i: i.get("created_at", ""), reverse=True)
        return items[:limit] if limit else items

    def get_postmortem(self, postmortem_id: str) -> Optional[Dict]:
        return self.postmortems_table.get_item(Key={"id": postmortem_id}).get("Item")

    # ---- ssl certificates -------------------------------------------------
    def get_ssl_cert(self, hostname: str) -> Optional[Dict]:
        return self.ssl_certs_table.get_item(Key={"id": hostname}).get("Item")

    def upsert_ssl_cert(self, hostname: str, record: Dict) -> None:
        """Insert or update the probe result for one hostname (keyed by the
        hostname itself under "id"). Every field goes through a name
        placeholder: "status" is a DynamoDB reserved word."""
        existing = self.get_ssl_cert(hostname)
        if existing is None:
            self.ssl_certs_table.put_item(Item={**record, "id": hostname})
            return
        fields = {k: v for k, v in record.items() if k != "domain"}
        if not fields:
            return
        expr, names, values = self._set_expression(fields)
        self.ssl_certs_table.update_item(Key={"id": hostname}, UpdateExpression=expr,
                                         ExpressionAttributeNames=names,
                                         ExpressionAttributeValues=values)

    def set_ssl_last_alerted(self, hostname: str, ts: str) -> None:
        self.upsert_ssl_cert(hostname, {"last_alerted_at": ts})

    # ---- public status history -------------------------------------------
    def record_status_sample(self, component_id: str, date_bucket: str, name: str,
                             healthy: bool, expires_at: int) -> None:
        self.status_history_table.update_item(
            Key={"component_id": component_id, "date_bucket": date_bucket},
            UpdateExpression="SET #exp = :exp, #name = :name ADD #sc :one, #hc :healthy",
            ExpressionAttributeNames={"#exp": "expires_at", "#name": "name",
                                      "#sc": "sample_count", "#hc": "healthy_count"},
            ExpressionAttributeValues={":exp": expires_at, ":name": name, ":one": 1,
                                       ":healthy": 1 if healthy else 0},
        )

    def get_status_history(self, component_ids: List[str],
                           since: Optional[str] = None) -> Dict[str, List[Dict]]:
        """{component_id: [{date_bucket, sample_count, healthy_count, ...}]}
        with date_bucket >= since ('YYYY-MM-DD') when given."""
        result: Dict[str, List[Dict]] = {}
        for cid in component_ids:
            items = self._query_all(self.status_history_table,
                                    KeyConditionExpression=Key("component_id").eq(cid))
            if since:
                items = [i for i in items if str(i.get("date_bucket", "")) >= since]
            result[cid] = items
        return result

    # ---- threat intel -------------------------------------------------------
    def record_threat_hit(self, rule_id: str, bucket: str, attack_type: str,
                          tenant_hash: str, expires_at: int, updated_at: str) -> None:
        """Atomically +1 the (rule_id, hour bucket) counter and add the
        tenant hash to its contributor set."""
        self.threat_patterns_table.update_item(
            Key={"pattern_key": f"{rule_id}#{bucket}"},
            UpdateExpression=("SET #rid = :rid, #at = :at, #tb = :tb, #exp = :exp, #ua = :ua "
                              "ADD #hc :one, #th :hashes"),
            ExpressionAttributeNames={"#rid": "rule_id", "#at": "attack_type", "#tb": "time_bucket",
                                      "#exp": "expires_at", "#ua": "updated_at",
                                      "#hc": "hit_count", "#th": "tenant_hashes"},
            ExpressionAttributeValues={":rid": rule_id, ":at": attack_type, ":tb": bucket,
                                       ":exp": expires_at, ":ua": updated_at, ":one": 1,
                                       ":hashes": {tenant_hash}},
        )

    def list_threat_patterns(self) -> List[Dict]:
        """Rows with rule_id, attack_type, time_bucket ('YYYYMMDDHH'),
        hit_count and tenant_hashes (a set)."""
        return self._scan_all(self.threat_patterns_table)

    # ---- audit log ----------------------------------------------------------
    def put_audit_event(self, item: Dict) -> None:
        self.audit_log_table.put_item(Item=item)

    def query_audit_events(self, scope_id: str) -> List[Dict]:
        return self._query_all(self.audit_log_table,
                               KeyConditionExpression=Key("scope_id").eq(scope_id))

    # ---- BOLA policies (physical table waf_rules) -------------------------
    def list_bola_policies(self) -> List[Dict]:
        return self._scan_all(self.rules_table, FilterExpression=Attr("type").eq("bola_policy"))

    def put_bola_policy(self, item: Dict) -> None:
        self.rules_table.put_item(Item={**item, "type": "bola_policy"})

    def delete_bola_policy(self, policy_id: str) -> None:
        self.rules_table.delete_item(Key={"id": policy_id})


class DuplicateDomain(ValueError):
    """A domain with this name is already registered."""


# The DynamoDB-backed implementation, also the base of PgStore while method
# groups move to PostgreSQL (migration plan Phases 2-7).
_DynamoBackedStore = DynamoDBService


def data_backend() -> str:
    """'postgres' or 'dynamodb' (default), from env DATA_BACKEND."""
    return "postgres" if os.getenv("DATA_BACKEND", "dynamodb").strip().lower() == "postgres" else "dynamodb"


if data_backend() == "postgres":
    from services.pg_store import PgStore as DynamoDBService  # noqa: E402,F811
