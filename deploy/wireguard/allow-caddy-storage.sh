#!/usr/bin/env bash
# Let the edges' Caddy reach the shared certificate storage on Main
# (waf-caddy-storage, published on 10.88.0.1:6380 -> container 6379).
# DOCKER-USER sees the port after Docker's DNAT, so the rule matches the
# container port 6379 and pins the original destination with conntrack.
# Idempotent: live rule + the CLOUDWAF block of /etc/ufw/after.rules.
set -euo pipefail
RULES=/etc/ufw/after.rules
TS=$(date +%Y%m%d-%H%M%S)
cp -p "$RULES" "$RULES.bak-$TS"
python3 - "$RULES" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
anchor = "-A DOCKER-USER -i wg0 -s 10.88.0.3 -p tcp -m multiport --dports 8070,8080 -j RETURN\n"
add = ("# Edge Caddy -> shared certificate storage (waf-caddy-storage, 10.88.0.1:6380)\n"
       "-A DOCKER-USER -i wg0 -s 10.88.0.2 -p tcp --dport 6379 -m conntrack --ctorigdst 10.88.0.1 --ctorigdstport 6380 -j RETURN\n"
       "-A DOCKER-USER -i wg0 -s 10.88.0.3 -p tcp --dport 6379 -m conntrack --ctorigdst 10.88.0.1 --ctorigdstport 6380 -j RETURN\n")
if "ctorigdstport 6380" not in s:
    assert s.count(anchor) == 1, "CLOUDWAF DOCKER-USER block not found"
    open(p, "w").write(s.replace(anchor, anchor + add))
PY
for ip in 10.88.0.3 10.88.0.2; do
  iptables -C DOCKER-USER -i wg0 -s $ip -p tcp --dport 6379 -m conntrack --ctorigdst 10.88.0.1 --ctorigdstport 6380 -j RETURN 2>/dev/null \
    || iptables -I DOCKER-USER 3 -i wg0 -s $ip -p tcp --dport 6379 -m conntrack --ctorigdst 10.88.0.1 --ctorigdstport 6380 -j RETURN
done
iptables -S DOCKER-USER
echo "backup: $RULES.bak-$TS"
