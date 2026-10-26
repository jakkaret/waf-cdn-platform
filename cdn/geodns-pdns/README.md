# GeoDNS for the CDN edges (PowerDNS)

Every customer domain is a CNAME to `waf-token-<id>.cdn.waf-it-kku.online`.
`cdn.waf-it-kku.online` is delegated from the main zone (Hostinger) to
PowerDNS running on both edges, which picks the edge for each visitor:

| Visitor | Answer | When that edge fails |
|---|---|---|
| Thailand (by EDNS Client Subnet, else the resolver's address) | edge-th `45.154.26.91` | edge-asia |
| Everyone else | edge-asia `57.158.25.236` (Azure, Hong Kong) | edge-th |

"Fails" means `http://<edge>/healthz/deep` does not answer `OK`: that URL goes
through the edge's Caddy and nginx and on to Main over WireGuard, so an edge
that is up but cannot reach Main is taken out too. PowerDNS checks it in the
background (`ifurlup`); if both fail, both addresses are returned. Records have
TTL 60, so a failed edge stops getting new visitors within about a minute
(plus however long resolvers keep the old answer).

For about 5 seconds after PowerDNS starts the checks have not run yet and the
answers come from the backup set; then they settle.

## Files

- `pdns.conf`: bind backend for the zone, geoip backend only for its database
  (`country()`), LUA records on, EDNS Client Subnet on, no recursion.
- `zones/cdn.waf-it-kku.online.zone`: the zone. Bump the serial on every change.
- `geo/dbip-country-lite.mmdb`: not in git. Copy
  `dashboard/backend/data/geoip/dbip-country-lite.mmdb` from Main (DB-IP Lite,
  CC BY 4.0, the same file the dashboard uses).
- `docker-compose.yml`: `powerdns/pdns-auth-49:4.9.17`, host network, port 53
  bound to the edge's own interface address only.

## Install or update on an edge

```sh
# from the repo, per edge (edge-asia: user azure, sudo)
COPYFILE_DISABLE=1 tar --no-xattrs -cf /tmp/pdns.tar -C cdn geodns-pdns
scp /tmp/pdns.tar <edge>:/tmp/ && ssh <edge> 'sudo tar -xf /tmp/pdns.tar -C /opt --no-same-owner'
# geo/dbip-country-lite.mmdb into /opt/geodns-pdns/geo/ (see above)
ssh <edge> 'cd /opt/geodns-pdns && sudo env PDNS_LOCAL_ADDRESS=<addr> docker compose up -d'
#   edge-th: 45.154.26.91   edge-asia: 172.16.0.4 (Azure maps the public IP to it)
```

A zone change needs `docker restart geodns-pdns` on both edges (the bind
backend reads the file at start).

Check from anywhere:

```sh
dig @45.154.26.91 x.cdn.waf-it-kku.online +subnet=1.46.0.0/24    # Thai -> 45.154.26.91
dig @57.158.25.236 x.cdn.waf-it-kku.online +subnet=8.8.8.0/24    # US  -> 57.158.25.236
dig @45.154.26.91 google.com                                      # REFUSED (no recursion)
```

## Delegation (Hostinger, main zone `waf-it-kku.online`)

Do this only after both edges serve every site (shared Caddy storage,
`cdn/edge/Caddyfile`), or visitors sent to edge-asia get no certificate.

1. Add `ns1.waf-it-kku.online A 45.154.26.91` and
   `ns2.waf-it-kku.online A 57.158.25.236`.
2. Delete the `cdn` and `*.cdn` A records.
3. Add `cdn NS ns1.waf-it-kku.online.` and `cdn NS ns2.waf-it-kku.online.`

Old answers stay in resolvers' caches for up to the old TTL (about 4 hours);
during that time they still point at edge-th, which keeps working.

## Ports

UDP and TCP 53 must be open to the internet on both edges (edge-th: ufw;
edge-asia: Azure network security group). PowerDNS answers only for its own
zone, so it cannot be used to resolve other names.
