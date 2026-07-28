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
                row = [
                    data.get('id', ''),
                    data.get('timestamp', ''),
                    data.get('client_ip', ''),
                    data.get('method', ''),
                    data.get('url', ''),
                    int(data.get('status_code', 0)),
                    float(data.get('request_time_ms', 0.0)),
                    data.get('user_agent', ''),
                    data.get('country', 'TH'),
                    data.get('edge_node', 'sg'),
                    int(data.get('alert', 0)),
                    data.get('attack_type', ''),
                    data.get('rule_id', '')
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
