import ipaddress
import os
import threading
import time
import json
from typing import Dict, List
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer

import http.client
from dnslib import A, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer

DOMAIN = os.getenv("GEODNS_DOMAIN", "cdn.local.").lower().rstrip(".") + "."
TTL = int(os.getenv("GEODNS_TTL", "20"))

EDGES: Dict[str, str] = {
    "SG": os.getenv("EDGE_SG_IP", "172.28.0.11"),
    "JP": os.getenv("EDGE_JP_IP", "172.28.0.12"),
    "TH": os.getenv("EDGE_TH_IP", "172.28.0.13"),
}

REGION_CIDRS: Dict[str, List[ipaddress._BaseNetwork]] = {
    "SG": [ipaddress.ip_network("172.28.11.0/24")],
    "JP": [ipaddress.ip_network("172.28.22.0/24")],
    "TH": [ipaddress.ip_network("172.28.33.0/24")],
}

DEFAULT_REGION = os.getenv("GEODNS_DEFAULT_REGION", "TH").upper()
EDGE_INTERNAL_PORT = int(os.getenv("EDGE_INTERNAL_PORT", "80"))

NODE_STATUS: Dict[str, bool] = {
    "SG": True,
    "JP": True,
    "TH": True,
}

FAILOVER_PRIORITY = {
    "SG": "TH",
    "JP": "TH",
    "TH": "SG"
}

def choose_region_for_ip(client_ip: str) -> str:
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return DEFAULT_REGION

    for region, networks in REGION_CIDRS.items():
        if any(ip in net for net in networks):
            return region
    return DEFAULT_REGION

def check_node_health(ip: str) -> bool:
    try:
        conn = http.client.HTTPConnection(ip, EDGE_INTERNAL_PORT, timeout=2.0)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status == 200
    except Exception:
        return False

def health_check_loop():
    while True:
        for region, ip in EDGES.items():
            is_healthy = check_node_health(ip)
            if NODE_STATUS[region] != is_healthy:
                status_str = "UP" if is_healthy else "DOWN"
                print(f"[HealthCheck] {region} ({ip}) is now {status_str}", flush=True)
            NODE_STATUS[region] = is_healthy
        time.sleep(10)

class StatusHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/status':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            
            status_data = {k.lower(): v for k, v in NODE_STATUS.items()}
            self.wfile.write(json.dumps(status_data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()
            
    def log_message(self, format, *args):
        pass

def start_http_server():
    server_address = ('0.0.0.0', 8053)
    httpd = HTTPServer(server_address, StatusHandler)
    print("HTTP Status server started on port 8053", flush=True)
    httpd.serve_forever()


class GeoResolver(BaseResolver):
    def resolve(self, request, handler):
        qname = str(request.q.qname).lower()
        qtype = QTYPE[request.q.qtype]

        reply = request.reply()

        if qname != DOMAIN and not qname.endswith("." + DOMAIN):
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        if qtype not in {"A", "ANY"}:
            # Keep NOERROR for unsupported types (e.g. AAAA) so clients can
            # fall back to A queries without treating the name as non-existent.
            return reply

        client_ip = handler.client_address[0]
        chosen_region = choose_region_for_ip(client_ip)

        final_region = chosen_region
        if not NODE_STATUS.get(final_region, False):
            fallback = FAILOVER_PRIORITY.get(final_region, DEFAULT_REGION)
            if NODE_STATUS.get(fallback, False):
                print(f"Failover: {final_region.lower()} -> {fallback.lower()} ({final_region.lower()} is DOWN)", flush=True)
                final_region = fallback
            else:
                healthy = [r for r, status in NODE_STATUS.items() if status]
                if healthy:
                    fallback_any = healthy[0]
                    print(f"Failover: {final_region.lower()} -> {fallback_any.lower()} ({final_region.lower()} is DOWN)", flush=True)
                    final_region = fallback_any

        chosen_ip = EDGES.get(final_region, EDGES[DEFAULT_REGION])

        reply.add_answer(RR(rname=request.q.qname, rtype=QTYPE.A, rclass=1, ttl=TTL, rdata=A(chosen_ip)))

        print(
            f"query={qname} from={client_ip} region={chosen_region} answer={chosen_ip}",
            flush=True,
        )
        return reply


def start_server(tcp: bool = False):
    resolver = GeoResolver()
    server = DNSServer(resolver, port=53, address="0.0.0.0", tcp=tcp)
    server.start_thread()
    return server


if __name__ == "__main__":
    hc_thread = threading.Thread(target=health_check_loop, daemon=True)
    hc_thread.start()

    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    udp_server = start_server(tcp=False)
    tcp_server = start_server(tcp=True)
    print(f"GeoDNS started for domain={DOMAIN}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        udp_server.stop()
        tcp_server.stop()
