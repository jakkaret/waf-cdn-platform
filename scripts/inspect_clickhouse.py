import clickhouse_connect

try:
    client = clickhouse_connect.get_client(
        host='178.104.53.123',
        port=8123,
        username='default',
        password='mysecurepassword'
    )
    print("ClickHouse Server Version:", client.server_version)
    
    total = client.query("SELECT count() FROM access_logs").result_rows
    print("Total rows in access_logs:", total)
    
    blocked = client.query("SELECT count() FROM access_logs WHERE status_code = 403 OR status_code = 429").result_rows
    print("Total blocked requests:", blocked)
    
    attacks = client.query("SELECT attack_type, count() FROM access_logs WHERE attack_type != '' GROUP BY attack_type").result_rows
    print("Attack Types:", attacks)
    
    ips = client.query("SELECT client_ip, count(), sum(status_code = 403) FROM access_logs GROUP BY client_ip ORDER BY count() DESC LIMIT 5").result_rows
    print("Top IPs:", ips)
    
    countries = client.query("SELECT country, count() FROM access_logs GROUP BY country").result_rows
    print("Countries:", countries)
    
    samples = client.query("SELECT timestamp, client_ip, method, url, status_code, attack_type FROM access_logs ORDER BY timestamp DESC LIMIT 3").result_rows
    print("Sample recent rows:")
    for s in samples:
        print(" ", s)
except Exception as e:
    print("ClickHouse query error:", e)
