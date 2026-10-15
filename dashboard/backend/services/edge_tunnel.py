"""WireGuard addresses of the CDN edges.

The edges reach Main (waf-nginx :8080, control-api :8070, this backend :8000)
over a WireGuard tunnel (deploy/wireguard/README.md) instead of plain HTTP
across the internet. Traffic that comes through the tunnel has the edge's
tunnel address as its source, not its public IP, so every check that trusts
an edge by source IP has to accept these too. Main's own tunnel address is
10.88.0.1 and is deliberately not listed.

Keep in sync with geo $from_trusted_proxy in
nginx/templates/conf.d/default.conf.template and EDGE_ALLOWED_IPS in
cdn/control-api/main.py.
"""

EDGE_TUNNEL_IPS = frozenset({
    "10.88.0.2",  # edge-th
    "10.88.0.3",  # edge-asia
})
