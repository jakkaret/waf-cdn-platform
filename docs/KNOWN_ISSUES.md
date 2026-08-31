# WAF Project Known Issues

Status: operational issue register
Last verified: 2026-08-26 via SSH
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

## 3. WAF container healthcheck is misleading

The image healthcheck tests HTTPS on 8443, while the deployed container listens on
8080 and TLS terminates at Caddy. The `unhealthy` status can therefore be a false
alarm; verify the actual 8080 request path before changing the service.

## 4. Working trees contain runtime output

Local and VPS trees may contain `__pycache__`, access logs, and the backend virtual
environment. Do not infer that a clean-looking status means the deployed state is
known or synchronized.

## 5. Lab frp path is unreachable

The lab agent cannot connect to the main frp server on port 7000, while the server
and its local listener are healthy. The evidence points to the network path between
the university network and the public main-node address, not the repository config.

## 6. Raw DVWA is publicly exposed

The lab Quick Tunnel publishes the raw DVWA origin without the WAF and uses a random
public hostname. This is separate from the edge/main WAF path and must be considered
when testing reachability or security.

## Handling

Re-check the relevant runtime evidence before acting. Update this register when the
status or impact changes; do not silently rewrite it during unrelated work.
