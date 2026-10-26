# WireGuard between the CDN edges and Main

The edges forward every visitor request to Main (waf-nginx :8080), pull the
rule bundle from control-api (:8070), send their logs and Caddy's
on-demand-TLS check to the backend (:8000). Before this link all of it went
over plain HTTP across the internet. Now it goes through a WireGuard tunnel.

| Host | Public IP | Tunnel IP |
|---|---|---|
| Main | 178.104.53.123 (UDP 51820) | 10.88.0.1 |
| edge-th | 45.154.26.91 | 10.88.0.2 |
| edge-asia | 57.158.25.236 (Azure, behind NAT) | 10.88.0.3 |

The edges dial Main (`PersistentKeepalive = 25`), so nothing has to be opened
on the edge side or in Azure. Each edge only routes `10.88.0.1/32` through the
tunnel.

## Set up

`wg-setup.sh` is installed on each host as `/usr/local/sbin/wg-setup.sh`.

1. On every host: `wg-setup.sh key`. This installs wireguard-tools, creates
   `/etc/wireguard/wg0.key` (600) and prints the **public** key. The private key
   never leaves the host; `wg0.conf` loads it with `PostUp`.
2. Main: `wg-setup.sh main <edge-th-pub> <edge-asia-pub>`.
3. Edges: `wg-setup.sh edge 10.88.0.2 <main-pub>` (edge-th) and
   `wg-setup.sh edge 10.88.0.3 <main-pub>` (edge-asia).
4. Firewalls for UDP 51820 to Main, from the two edge IPs only:
   - ufw on Main: `ufw allow from <edge-ip> to any port 51820 proto udp`
   - **the Hetzner Cloud Firewall in front of Main** (console): it drops
     everything not listed there before ufw sees it.
5. Check: `wg show wg0` on Main shows a recent handshake for both peers, and
   `ping 10.88.0.1` works from each edge.

`wg0.conf` clamps TCP MSS on traffic forwarded into the tunnel: the docker
bridges run at MTU 1500 and wg0 at 1420, and without the clamp small
responses work while large ones stall.

## What trusts the tunnel addresses

Requests through the tunnel arrive from 10.88.0.2/10.88.0.3, not from the
edges' public IPs, so these lists include them:

- `geo $from_trusted_proxy` in `nginx/templates/conf.d/default.conf.template`
  (believe the edge's X-Real-IP)
- `EDGE_ALLOWED_IPS` default in `cdn/control-api/main.py` (rule bundle, blocklist)
- `dashboard/backend/services/edge_tunnel.py`, used by `/api/cdn/logs/ingest`
  and the `KNOWN_EDGE_IPS` skip in `services/log_forward.py`

`tests/test_edge_tunnel_ips.py` keeps them in sync.

Main's firewall accepts the tunnel addresses only on `wg0`, so they cannot be
spoofed from the internet:

- `DOCKER-USER` (in the CLOUDWAF block of `/etc/ufw/after.rules`): from
  10.88.0.2/10.88.0.3 on wg0 to 8070 and 8080, everything else from wg0 dropped
- ufw: `allow in on wg0 from 10.88.0.2|10.88.0.3 to any port 8000 proto tcp`
- `DOCKER-USER`: from 10.88.0.2/10.88.0.3 on wg0 to the edges' shared Caddy
  certificate storage (waf-caddy-storage, 10.88.0.1:6380; the rule matches the
  container port 6379 after DNAT plus the original destination via conntrack).
  Added by `allow-caddy-storage.sh` (idempotent, also writes after.rules).

Since both edges were switched, the public path is closed
(`close-public-path.sh`): no rule lets the edges' public IPs reach 8080, 8070
or 8000 any more. If the tunnel is down, the edges cannot reach Main at all;
to fall back, restore `/etc/ufw/after.rules`, `user.rules`, `user6.rules` and
`iptables-restore` the `iptables.save` from that script's backup, then roll
the edges back.

control-api is published only on loopback and Main's WireGuard address
(docker-compose.yml). Docker must therefore start after wg0, or the binding
fails at boot: install `docker-after-wg.conf` as
`/etc/systemd/system/docker.service.d/10-wireguard.conf` and run
`systemctl daemon-reload` (done on Main 2026-10-15).

## Switch an edge to the tunnel

`edge-switch.sh check <dir>` tests the tunnel from inside each edge container;
`edge-switch.sh switch <dir>` does the steps below after a passing check, and
`edge-switch.sh rollback <dir> <backup>` undoes them. Afterwards, send two
probes tagged with a random string through the edge and run
`verify-edge.sh <edge-ip> <tunnel-ip> <tag>` on Main.

In the edge's compose directory (`/root/edge_node` on edge-th,
`/opt/edge_node` on edge-asia):

1. Back up `.env` and `edge/Caddyfile`.
2. `.env`: `MAIN_SERVER_IP=10.88.0.1` (compose builds the origin, control-api
   and backend URLs from it) and `CONTROL_API_URL=http://10.88.0.1:8070`.
3. `edge/Caddyfile`: `ask http://10.88.0.1:8000/api/domains/check-ssl-allowed`.
   The file is bind-mounted, so rewrite it in place (same inode), then
   `docker exec cdn-caddy-ssl caddy reload --config /etc/caddy/Caddyfile`.
4. `docker compose up -d` recreates cdn-edge-node and cdn-log-forwarder.

Rollback: restore the two files, `docker compose up -d`, `caddy reload`.

edge-asia's `cdn-log-forwarder` is not a compose container (it was started
with `docker run`, `EDGE_REGION=asia`), so `docker compose up -d` there fails
with a name conflict. Its config is saved as `log-forwarder.inspect.json` in
the switch backup; it was recreated with the same `docker run` options and
`MAIN_SERVER_URL=http://10.88.0.1:8000`. Keep `EDGE_REGION=asia` so its
ClickHouse rows keep `edge_node = edge-asia`.

## Status

- 2026-10-15: tunnel up on all three hosts; edge-th switched and verified
  (Main sees 10.88.0.2, no traffic left on the public ports, logs reach
  ClickHouse once, rule sync 200).
- 2026-10-15: edge-asia switched and verified the same way (10.88.0.3).
  Both edges now use only the tunnel; no TCP from their public IPs reaches
  Main's 8080/8070/8000.
- 2026-10-15: public path closed on Main. From the edges, 8080/8070/8000 on
  178.104.53.123 time out; over the tunnel all checks pass.
