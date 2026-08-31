# WAF Project Architecture

Status: operational reference
Last verified: 2026-08-26 via SSH
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

The lab node has two exposure paths that bypass the WAF: the frp agent path and a
Cloudflare Quick Tunnel to the raw DVWA origin. See `KNOWN_ISSUES.md`.

## Rule synchronization

Dashboard API -> `scripts/sync_waf_rules.py` -> `docker cp` -> `nginx -t` ->
`nginx -s reload`.

The sync script has variables for SG, JP, and TH edge containers, but only TH is
currently deployed. SG and JP are aspirational until their nodes exist.

## Verification rule

Before SSH or deployment, verify the node address, service status, mounted config
path, and active listener. Do not treat this document as proof of current runtime
state.
