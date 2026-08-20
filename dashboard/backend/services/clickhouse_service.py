import clickhouse_connect
from clickhouse_connect.driver.exceptions import ClickHouseError
import time
import uuid
from datetime import datetime

class ClickHouseService:
    def __init__(self, host='localhost', port=8123, username='default', password='mysecurepassword'):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.client = None
        self.connected = False
        self.connect()
        self.init_db()

    def connect(self):
        try:
            self.client = clickhouse_connect.get_client(
                host=self.host,
                port=self.port,
                username=self.username,
                password=self.password
            )
            self.connected = True
            print("✅ Successfully connected to ClickHouse DB!")
        except Exception as e:
            print(f"⚠️ Failed to connect to ClickHouse: {e}. Falling back to NoSQL only.")
            self.connected = False

    def init_db(self):
        if not self.connected:
            return
            
        try:
            # Create access_logs table
            self.client.command('''
                CREATE TABLE IF NOT EXISTS access_logs (
                    id UUID,
                    timestamp DateTime,
                    client_ip String,
                    method String,
                    url String,
                    status_code UInt16,
                    request_time_ms Float32,
                    user_agent String,
                    country String,
                    edge_node String,
                    alert UInt8,
                    attack_type String,
                    rule_id String
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, client_ip)
            ''')
            
            # Create security_audit_logs table
            self.client.command('''
                CREATE TABLE IF NOT EXISTS security_audit_logs (
                    id UUID,
                    timestamp DateTime,
                    client_ip String,
                    rule_id String,
                    message String,
                    severity String,
                    action String,
                    edge_node String
                ) ENGINE = MergeTree()
                ORDER BY (timestamp, rule_id)
            ''')
            print("✅ ClickHouse tables initialized.")
        except ClickHouseError as e:
            print(f"⚠️ Error initializing ClickHouse tables: {e}")
            self.connected = False

    def save_log(self, table_name, data: dict):
        if not self.connected:
            return False
            
        try:
            if table_name == 'access_logs':
                raw_id = data.get('request_id') or data.get('id') or data.get('log_id')
                if raw_id:
                    try:
                        log_uuid = uuid.UUID(str(raw_id))
                    except Exception:
                        log_uuid = uuid.uuid4()
                else:
                    log_uuid = uuid.uuid4()
                    
                raw_time = data.get('datetime') or data.get('timestamp')
                if raw_time:
                    try:
                        if isinstance(raw_time, str):
                            clean_time = raw_time.replace('Z', '')
                            if 'T' in clean_time:
                                dt = datetime.fromisoformat(clean_time)
                            else:
                                dt = datetime.strptime(clean_time, '%Y-%m-%d %H:%M:%S')
                        elif isinstance(raw_time, (int, float)):
                            dt = datetime.utcfromtimestamp(raw_time)
                        else:
                            dt = datetime.utcnow()
                    except Exception:
                        dt = datetime.utcnow()
                else:
                    dt = datetime.utcnow()
                    
                status_val = int(data.get('status') or data.get('status_code') or 0)
                is_alert = 1 if (data.get('alert') or status_val in [403, 429]) else 0
                
                row = [
                    log_uuid,
                    dt,
                    data.get('ip') or data.get('client_ip') or '',
                    data.get('method') or 'GET',
                    data.get('url') or '/',
                    status_val,
                    float(data.get('latency_ms') or data.get('request_time_ms') or 0.0),
                    data.get('user_agent') or '',
                    data.get('country') or 'TH',
                    data.get('edge_node') or 'sg',
                    is_alert,
                    data.get('attack_type') or '',
                    str(data.get('rule_id') or '')
                ]
                self.client.insert(table_name, [row], column_names=[
                    'id', 'timestamp', 'client_ip', 'method', 'url', 'status_code',
                    'request_time_ms', 'user_agent', 'country', 'edge_node', 'alert', 'attack_type', 'rule_id'
                ])
                return True
                
        except Exception as e:
            print(f"⚠️ ClickHouse insert error: {e}")
            return False

    def get_filter_options(self) -> dict:
        """Scan distinct status codes and methods dynamically from real data"""
        if not self.connected:
            return {
                "status_codes": [200, 403, 404, 500, 502],
                "methods": ["GET", "POST", "HEAD", "PUT", "DELETE"],
                "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
            }
            
        try:
            status_query = "SELECT DISTINCT status_code FROM access_logs WHERE status_code > 0 ORDER BY status_code ASC"
            status_rows = self.client.query(status_query).result_rows
            status_codes = [int(r[0]) for r in status_rows]
            
            method_query = "SELECT DISTINCT method FROM access_logs WHERE length(method) > 0 ORDER BY method ASC"
            method_rows = self.client.query(method_query).result_rows
            methods = [str(r[0]) for r in method_rows]
            
            return {
                "status_codes": status_codes if status_codes else [200, 403, 404, 500],
                "methods": methods if methods else ["GET", "POST"],
                "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
            }
        except Exception as e:
            print(f"⚠️ Error fetching filter options: {e}")
            return {
                "status_codes": [200, 403, 404, 500],
                "methods": ["GET", "POST"],
                "severities": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE"]
            }

    def get_logs(self, limit: int = 20, page: int = 1, search: str = "", status_filter: str = "ALL", severity_filter: str = "ALL", method_filter: str = "ALL") -> dict:
        if not self.connected:
            return {"logs": [], "total": 0, "page": page, "limit": limit, "total_pages": 1}
        
        limit = max(1, min(limit, 100))
        page = max(1, page)
        offset = (page - 1) * limit
        
        where_clauses = []
        
        if search:
            escaped_search = search.replace("'", "\\'")
            where_clauses.append(f"(client_ip ILIKE '%{escaped_search}%' OR url ILIKE '%{escaped_search}%' OR rule_id ILIKE '%{escaped_search}%' OR user_agent ILIKE '%{escaped_search}%' OR attack_type ILIKE '%{escaped_search}%')")
            
        if status_filter and status_filter != "ALL":
            if status_filter == "BLOCKED":
                where_clauses.append("status_code = 403")
            elif status_filter == "ALLOWED":
                where_clauses.append("status_code >= 200 AND status_code < 300")
            elif status_filter.isdigit():
                where_clauses.append(f"status_code = {int(status_filter)}")
                
        if method_filter and method_filter != "ALL":
            escaped_m = method_filter.replace("'", "\\'")
            where_clauses.append(f"method = '{escaped_m}'")
            
        if severity_filter and severity_filter != "ALL":
            if severity_filter == "CRITICAL":
                where_clauses.append("status_code = 403")
            elif severity_filter == "HIGH":
                where_clauses.append("status_code >= 500")
            elif severity_filter == "MEDIUM":
                where_clauses.append("status_code >= 400 AND status_code != 403")
            elif severity_filter == "LOW":
                where_clauses.append("status_code >= 300 AND status_code < 400")
            elif severity_filter == "NONE":
                where_clauses.append("status_code >= 200 AND status_code < 300")

        where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        query = f"""
            SELECT 
                toString(id) as log_id,
                formatDateTime(timestamp, '%Y-%m-%d %H:%i:%S') as datetime,
                client_ip as ip,
                method,
                url,
                status_code as status,
                user_agent,
                country,
                edge_node,
                attack_type,
                rule_id,
                CASE 
                    WHEN status_code = 403 THEN 'CRITICAL'
                    WHEN status_code >= 500 THEN 'HIGH'
                    WHEN status_code >= 400 THEN 'MEDIUM'
                    ELSE 'NONE'
                END as severity
            FROM access_logs
            {where_str}
            ORDER BY timestamp DESC
            LIMIT {limit} OFFSET {offset}
        """
        
        count_query = f"SELECT count() FROM access_logs {where_str}"
        
        try:
            res = self.client.query(query)
            count_res = self.client.query(count_query)
            total = count_res.result_rows[0][0] if count_res.result_rows else 0
            
            columns = [
                'log_id', 'datetime', 'ip', 'method', 'url', 'status', 
                'user_agent', 'country', 'edge_node', 'attack_type', 'rule_id', 'severity'
            ]
            
            logs = []
            for row in res.result_rows:
                row_dict = dict(zip(columns, row))
                if not row_dict.get('rule_id'):
                    row_dict['rule_id'] = 'WAF-CRS' if row_dict.get('status') == 403 else None
                logs.append(row_dict)
                
            total_pages = max(1, (total + limit - 1) // limit)
            
            return {
                "logs": logs,
                "total": total,
                "page": page,
                "limit": limit,
                "total_pages": total_pages
            }
        except Exception as e:
            print(f"⚠️ Error querying ClickHouse logs: {e}")
            return {"logs": [], "total": 0, "page": page, "limit": limit, "total_pages": 1}

    def query_stats(self, query):
        if not self.connected:
            return []
        try:
            result = self.client.query(query)
            return result.result_rows
        except Exception as e:
            print(f"⚠️ ClickHouse query error: {e}")
            return []
