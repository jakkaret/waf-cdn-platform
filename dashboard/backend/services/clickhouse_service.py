import clickhouse_connect
from clickhouse_connect.driver.exceptions import ClickHouseError
import time

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
            # Map dictionary to column order for insertion
            if table_name == 'access_logs':
                import uuid
                from datetime import datetime
                
                raw_id = data.get('request_id') or data.get('id')
                if raw_id:
                    try:
                        log_uuid = uuid.UUID(raw_id)
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
                        else:
                            dt = datetime.utcfromtimestamp(raw_time)
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
                    data.get('rule_id') or ''
                ]
                self.client.insert(table_name, [row], column_names=[
                    'id', 'timestamp', 'client_ip', 'method', 'url', 'status_code',
                    'request_time_ms', 'user_agent', 'country', 'edge_node', 'alert', 'attack_type', 'rule_id'
                ])
                return True
                
        except Exception as e:
            print(f"⚠️ ClickHouse insert error: {e}")
            return False

    def query_stats(self, query):
        if not self.connected:
            return []
        try:
            result = self.client.query(query)
            return result.result_rows
        except Exception as e:
            print(f"⚠️ ClickHouse query error: {e}")
            return []
