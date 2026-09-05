# WAF Project Known Issues

Status: operational issue register
Last verified: 2026-09-05 via SSH (issue text below dated per-issue; see resolution notes)
Owner: update status and verification date when an issue changes

## 1. Edge configuration is outside git

The deployed edge containers mount configuration from a separate untracked edge
directory, not the git clone on that node. SSH changes must be mirrored into the
repository and the deployed mount path.

## 2. A secret is committed

`docker-compose.yml` contains a plaintext control token. Do not add secrets to
tracked files. New secrets belong in an untracked environment or approved secret
store. Existing exposed credentials must be rotated through the normal change
process.

## 3. WAF container healthcheck is misleading — RESOLVED 2026-08-31

The image healthcheck tested HTTPS on 8443, while the deployed container listens on
8080 and TLS terminates at Caddy, so `unhealthy` was a permanent false alarm (confirmed
FailingStreak in the thousands with no actual traffic impact). Fixed with a
`healthcheck:` override in `docker-compose.yml` pointing at the real `:8080/healthz`.
Re-verified 2026-09-05: `waf-nginx` reports `Up (healthy)`.

## 4. Working trees contain runtime output

Local and VPS trees may contain `__pycache__`, access logs, and the backend virtual
environment. Do not infer that a clean-looking status means the deployed state is
known or synchronized.

## 5. Lab tunnel path is unreachable — recurring, cause has varied

**Instance 1 (resolved 2026-08-31)**: the lab agent could not reach the main tunnel
server; root cause was the Lab node's KKU network authentication (NAC captive portal)
session expiring, which silently blocks all outbound TCP except plain HTTP used for the
NAC login redirect. Resolved when the user re-authenticated the network session on the
Lab machine; both `waf-agent.service` (FRP) and `cloudwaf-agent.service` (custom
tunnel) reconnected automatically (`Restart=always`).

**Instance 2 (open, found 2026-09-05)**: recurred with a *different* signature —
`neverssl.com` succeeds (200, so this is not the NAC captive-portal pattern), but both
`178.104.53.123:7000` (FRP) and `:8050` (custom tunnel) return `Connection refused`
from Lab specifically. Verified from Main's side: both ports are listening, both
services (`frps.service`, the custom tunnel server) are running normally, `ufw` and the
`DOCKER-USER` iptables chain allow both ports with no Lab-specific block, and both
ports are reachable from an unrelated external host. The evidence again points to the
network path on the university side, not this repository's config — but the specific
mechanism (a port-level egress restriction rather than a full captive-portal redirect)
differs from Instance 1, so treat this as a related-but-distinct recurrence, not the
same bug reappearing. **Needs the user to check network/VPN status on the Lab machine
again; not fixable from this repo or via SSH troubleshooting alone.**

Impact while open: all four Lab-hosted apps (`dvwa`, `juice`, `vampi`, `bwapp`)
temporarily unreachable via the WAF-fronted hostnames. Edge, Main, the dashboard, and
ClickHouse are unaffected.

## 6. Raw DVWA public exposure via Cloudflare Quick Tunnel — RESOLVED 2026-08-31

The lab ran two Cloudflare Quick Tunnel services (`dvwa-tunnel.service`,
`waf-tunnel.service`) that published the raw Lab origins directly to the internet on
random public hostnames, bypassing ModSecurity entirely — separate from the edge/main
WAF path in item 5 above. Both services have been disabled
(`systemctl disable --now`) and verified closed (zero `cloudflared` processes running,
zero live TCP/UDP connections to Cloudflare). All four Lab apps now route exclusively
through the WAF-fronted paths (FRP or the custom tunnel protocol). Do not re-enable
either service without explicit approval — this was a confirmed WAF-bypass path.

## Handling

Re-check the relevant runtime evidence before acting. Update this register when the
status or impact changes; do not silently rewrite it during unrelated work.
