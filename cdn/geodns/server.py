import ipaddress
import os
import threading
from typing import Dict, List

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


def choose_region_for_ip(client_ip: str) -> str:
    try:
        ip = ipaddress.ip_address(client_ip)
    except ValueError:
        return DEFAULT_REGION

    for region, networks in REGION_CIDRS.items():
        if any(ip in net for net in networks):
            return region
    return DEFAULT_REGION


def edge_healthy(ip: str) -> bool:
    try:
        conn = http.client.HTTPConnection(ip, EDGE_INTERNAL_PORT, timeout=0.8)
        conn.request("GET", "/healthz")
        resp = conn.getresponse()
        resp.read()
        conn.close()
        return resp.status == 200
    except Exception:
        return False


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

        # fallback to first healthy edge if chosen region is unhealthy
        chosen_ip = EDGES.get(chosen_region, EDGES[DEFAULT_REGION])
        if not edge_healthy(chosen_ip):
            healthy = [ip for ip in EDGES.values() if edge_healthy(ip)]
            if healthy:
                chosen_ip = healthy[0]

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
    udp_server = start_server(tcp=False)
    tcp_server = start_server(tcp=True)
    print(f"GeoDNS started for domain={DOMAIN}", flush=True)
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        udp_server.stop()
        tcp_server.stop()
