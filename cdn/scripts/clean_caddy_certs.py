"""Delete junk certificates from edge-th's Caddy storage.

Keeps only names we actually use(d); everything else (8,786 *.ld48stp821tyfk3q
names, ~550 random-hex subdomains from old test runs, scanner names like
notexists*/mail/m/9v, a foreign domain) goes. Run with --apply to delete;
without it, only prints what would happen. A full tar backup is made first.
"""
import os, shutil, sys
ROOT = "/var/lib/docker/volumes/edge_node_caddy_data/_data/caddy/certificates"
KEEP = {
    # platform lab subdomains
    "app.waf-it-kku.online", "bwapp.waf-it-kku.online", "dash.waf-it-kku.online",
    "dashboard.waf-it-kku.online", "edge.waf-it-kku.online", "juice.waf-it-kku.online",
    "labtest.waf-it-kku.online", "pos.waf-it-kku.online", "qa1.waf-it-kku.online",
    "qa2.waf-it-kku.online", "ryu.waf-it-kku.online", "vampi.waf-it-kku.online",
    "web.waf-it-kku.online", "installverify.waf-it-kku.online", "dvwa.waf-it-kku.online",
    "waf-it-kku.online", "www.waf-it-kku.online",
    # lab origin sites
    "juiceshop.originweb.site", "httpbin.originweb.site",
    # old edge name
    "waf-edge-th.duckdns.org", "www.waf-edge-th.duckdns.org",
}
apply = "--apply" in sys.argv
kept, gone = [], 0
for issuer in sorted(os.listdir(ROOT)):
    d = os.path.join(ROOT, issuer)
    for name in sorted(os.listdir(d)):
        if name in KEEP:
            kept.append(f"{issuer}/{name}")
            continue
        gone += 1
        if apply:
            shutil.rmtree(os.path.join(d, name))
print(("deleted" if apply else "would delete"), gone)
print("kept", len(kept)); print("\n".join(kept))
