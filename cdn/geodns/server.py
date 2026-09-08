import bisect
import csv
import ipaddress
import os
import threading
import time
import json
from typing import Dict, List, Tuple
import http.client
from http.server import BaseHTTPRequestHandler, HTTPServer

import http.client
from dnslib import A, QTYPE, RCODE, RR
from dnslib.server import BaseResolver, DNSServer

DOMAIN = os.getenv("GEODNS_DOMAIN", "cdn.local.").lower().rstrip(".") + "."
TTL = int(os.getenv("GEODNS_TTL", "20"))

# Real 2-edge deployment: edge-th (Nonthaburi, Thailand) and edge-asia
# (Microsoft Azure East Asia / Hong Kong). This is a binary GeoIP split, not
# general multi-region logic -- a query from a Thailand-registered IP goes to
# edge-th, everything else goes to edge-asia. Extending past 2 real edges
# needs the region-selection logic reworked, not just a new EDGES entry.
# These names match each edge's own EDGE_REGION env var (see
# /opt/edge_node/.env and /root/edge_node/.env on each box) deliberately --
# keep them in sync so the healthz "region" field and this server's region
# keys always mean the same node.
EDGES: Dict[str, str] = {
    "edge-th": os.getenv("EDGE_TH_IP", "45.154.26.91"),
    "edge-asia": os.getenv("EDGE_ASIA_IP", "57.158.25.236"),
}

_default_env = os.getenv("GEODNS_DEFAULT_REGION", "edge-th")
DEFAULT_REGION = _default_env if _default_env in EDGES else "edge-th"
EDGE_INTERNAL_PORT = int(os.getenv("EDGE_INTERNAL_PORT", "80"))

NODE_STATUS: Dict[str, bool] = {name: True for name in EDGES}

FAILOVER_PRIORITY = {"edge-th": "edge-asia", "edge-asia": "edge-th"}

# --- Real GeoIP: Thailand IP ranges only (binary TH / not-TH split) -------
# Data source: DB-IP Lite country database via sapics/ip-location-db
# (https://github.com/sapics/ip-location-db), filtered to country=TH at
# container build time -- see Dockerfile. Licensed CC-BY 4.0 by DB-IP.com;
# attribution: https://db-ip.com
TH_RANGES_FILE = os.getenv("TH_RANGES_FILE", "/app/th_ranges.csv")
_TH_STARTS: List[int] = []
_TH_ENDS: List[int] = []


def _load_th_ranges() -> None:
    global _TH_STARTS, _TH_ENDS
    starts: List[int] = []
    ends: List[int] = []
    try:
        with open(TH_RANGES_FILE, newline="") as f:
            for row in csv.reader(f):
                if len(row) != 2:
                    continue
                start_ip, end_ip = row
                starts.append(int(ipaddress.ip_address(start_ip)))
                ends.append(int(ipaddress.ip_address(end_ip)))
    except FileNotFoundError:
        print(f"[GeoIP] {TH_RANGES_FILE} not found -- all traffic will default to {DEFAULT_REGION}", flush=True)
        return
    # Sort by range start so is_thailand_ip() can bisect.
    paired = sorted(zip(starts, ends))
    _TH_STARTS = [p[0] for p in paired]
    _TH_ENDS = [p[1] for p in paired]
    print(f"[GeoIP] loaded {len(_TH_STARTS)} Thailand IP ranges from {TH_RANGES_FILE}", flush=True)


def is_thailand_ip(ip_int: int) -> bool:
    if not _TH_STARTS:
        return False
    i = bisect.bisect_right(_TH_STARTS, ip_int) - 1
    return i >= 0 and ip_int <= _TH_ENDS[i]


def choose_region_for_ip(client_ip: str) -> str:
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return DEFAULT_REGION
    if ip.version != 4:
        # No IPv6 ranges loaded -- fall back rather than misclassify.
        return DEFAULT_REGION
    return "edge-th" if is_thailand_ip(int(ip)) else "edge-asia"

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
    _load_th_ranges()

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
