# GeoDNS for the CDN edges (PowerDNS)

Every customer domain is a CNAME to `waf-token-<id>.cdn.waf-it-kku.online`,
and platform subdomains (`app.`, `vampi.`, ...) match `*.waf-it-kku.online`.
PowerDNS on both edges serves the whole `waf-it-kku.online` zone (ns1 =
edge-th, ns2 = edge-asia) and picks the edge for each visitor:

| Visitor (EDNS Client Subnet, else the resolver's address) | Answer | When that edge fails |
|---|---|---|
| East Asia (HK, MO, CN, TW, JP, KR, PH) and Oceania | edge-asia `57.158.25.236` (Azure, Hong Kong) | edge-th |
| Everyone else, Thailand and its neighbours included | edge-th `45.154.26.91` (Bangkok) | edge-asia |

Why not "nearest edge": every cache miss continues to Main in Nuremberg over
WireGuard, and edge-th is closer to Main (183 ms RTT) than edge-asia (238 ms,
measured 2026-10-26). Visitors from Europe, Africa, the Americas and the rest
of Asia are both far from either edge, so they get the edge with the shorter
way on to Main; edge-asia only wins where it is much nearer the visitor.

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
- `zones/waf-it-kku.online.zone`: the whole zone. Bump the serial on every change.
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

## Nameservers (moved from Hostinger, 2026-10-26)

Hostinger cannot delegate a subdomain (it has no NS records below the apex),
so the zone itself moved; the records outside the CDN were copied from
Hostinger's export of that day.

1. Hostinger, DNS / Nameservers, "child nameservers": `ns1.waf-it-kku.online`
   45.154.26.91 and `ns2.waf-it-kku.online` 57.158.25.236 (glue at the registry;
   `whois -h whois.nic.online "nameserver ns1.waf-it-kku.online"`).
2. "Change nameservers" to `ns1.waf-it-kku.online` and `ns2.waf-it-kku.online`.

Roll back by changing the nameservers back to `cosmos.dns-parking.com` and
`nova.dns-parking.com` (the Hostinger zone still holds the old records). The
`.online` registry hands out the delegation with TTL 900, so either change
reaches resolvers in about 15 minutes plus Hostinger's processing.

Before a change, compare every name with the zone as it should be, e.g.
`dig @45.154.26.91 www.waf-it-kku.online` and `dig @57.158.25.236 ...`.

## Ports

UDP and TCP 53 must be open to the internet on both edges (edge-th: ufw;
edge-asia: Azure network security group). PowerDNS answers only for its own
zone, so it cannot be used to resolve other names.
