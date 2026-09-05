# WAF Project Architecture

Status: operational reference
Last verified: 2026-09-05 via SSH
Owner: update this file after topology, IP, service, or routing changes

## Request and service topology

```text
Internet
  |
  +-- Edge node (TH)
  |     +-- cdn-caddy-ssl :80/:443
  |     +-- cdn-edge-node (ModSecurity CRS nginx, internal :8080)
  |     +-- cdn-log-forwarder -> main dashboard API :8000
  |     +-- cdn-edge-node -> main WAF :8080
  |
  +-- Main node
  |     +-- caddy-ssl-termination :80/:443 -> dashboard :8000
  |     +-- waf-nginx (ModSecurity CRS, paranoia 1) :8080 -> dvwa
  |     +-- waf-redis :6379
  |     +-- waf-clickhouse :8123/:9000
  |     +-- waf-control-api :8070
  |     +-- frps :7000/:7500/:8085
  |     +-- waf-dashboard.service :8000
  |     +-- waf-ml.service :5000
  |     +-- waf-log-analyzer.service
  |
  +-- Lab/origin pool (separate from this git repository)
        +-- waf-dvwa-app :8080
        +-- waf-juice-shop :3000
        +-- waf-vampi :5000
        +-- waf-bwapp :8081
        +-- waf-origin-proxy :80/:443
        +-- waf-dvwa-db
```

## Origin connectivity: two tunnel mechanisms, both live in production

Two independent tunnel implementations run in parallel on the Lab node, both
legitimate — not redundant-by-accident:

- **FRP** (`waf-agent.service` on Lab, `frps.service` on Main, port 7000) — originally
  serves `dvwa` and `juice`, vhost-routed through Main's `waf-nginx` on port 8085.
- **Custom zero-trust tunnel protocol** (`cloudwaf-agent.service` on Lab, the tunnel
  server at `/opt/cloudwaf-tunnel/server.py` on Main, TLS port 8050 / vhost port 8060)
  — originally built for `vampi`, extended 2026-08-31 to also serve `dvwa`, `juice`,
  and `bwapp` as a resilience measure. Per-origin credential model
  (`cwt_<origin_id>_<secret>`), hostname-based routing, no inbound port ever opened on
  the origin.

Check `/var/lib/cloudwaf-tunnel/state.json` on Main for the custom tunnel's live agent
count and served hostnames before assuming either mechanism is currently up — Lab's
network path to Main has been an intermittent point of failure (see
`KNOWN_ISSUES.md` #5) for reasons that vary (KKU NAC session expiry, or a
port-level egress restriction), not a repository config problem.

The previously-noted Cloudflare Quick Tunnel bypass path (`dvwa-tunnel.service`,
`waf-tunnel.service`) was closed 2026-08-31 — see `KNOWN_ISSUES.md` #6. It no longer
exists as an exposure path.

## Rule synchronization

Dashboard API -> `scripts/sync_waf_rules.py` -> `docker cp` -> `nginx -t` ->
`nginx -s reload`.

The sync script has variables for SG, JP, and TH edge containers, but only TH is
currently deployed. SG and JP are aspirational until their nodes exist.

## Verification rule

Before SSH or deployment, verify the node address, service status, mounted config
path, and active listener. Do not treat this document as proof of current runtime
state.
