#!/usr/bin/env bash
# Close the edges' public plaintext path to Main (8080/8070/8000): they use
# the WireGuard tunnel now. Backup first; rollback = restore the three files
# from $BK and `iptables-restore < $BK/iptables.save`.
set -euo pipefail
BK=/root/backups/close-public-$(date +%Y%m%d-%H%M%S); mkdir -p "$BK"; chmod 700 "$BK"
cp -p /etc/ufw/after.rules /etc/ufw/user.rules /etc/ufw/user6.rules "$BK/"; iptables-save > "$BK/iptables.save"
echo "BACKUP=$BK"

echo "== DOCKER-USER (live)"
iptables -D DOCKER-USER -s 57.158.25.236/32 -p tcp -m tcp --dport 8070 -j ACCEPT
iptables -I DOCKER-USER 4 -p tcp -m tcp --dport 8070 -j DROP
iptables -D DOCKER-USER ! -s 45.154.26.91/32 -p tcp -m tcp --dport 8070 -j DROP
iptables -D DOCKER-USER -s 45.154.26.91/32 -i eth0 -p tcp -m tcp --dport 8080 -j RETURN
iptables -D DOCKER-USER -s 57.158.25.236/32 -i eth0 -p tcp -m tcp --dport 8080 -j RETURN
iptables -S DOCKER-USER

echo "== after.rules (persist)"
python3 - <<'PY'
p = "/etc/ufw/after.rules"
s = open(p).read()
rep = {
    "-A DOCKER-USER -s 57.158.25.236 -p tcp --dport 8070 -j ACCEPT\n": "",
    "-A DOCKER-USER -p tcp --dport 8070 ! -s 45.154.26.91 -j DROP\n":
        "# 2026-10-15: the edges reach control-api only through WireGuard (above);\n"
        "# :8070 is closed to everything else, the edges' public IPs included.\n"
        "-A DOCKER-USER -p tcp --dport 8070 -j DROP\n",
    "-A DOCKER-USER -i eth0 -p tcp --dport 8080 -s 45.154.26.91 -j RETURN\n": "",
    "-A DOCKER-USER -i eth0 -p tcp --dport 8080 -s 57.158.25.236 -j RETURN\n": "",
    "# waf-nginx :8080 -- only the CDN edges; keep in sync with geo $from_trusted_proxy\n":
        "# waf-nginx :8080 -- only the CDN edges, and since 2026-10-15 only through\n"
        "# WireGuard (above); keep in sync with geo $from_trusted_proxy\n",
}
for old, new in rep.items():
    assert s.count(old) == 1, old
    s = s.replace(old, new)
open(p, "w").write(s)
PY
sed -n '/BEGIN CLOUDWAF/,/END CLOUDWAF/p' /etc/ufw/after.rules | grep -v "^#" 

echo "== ufw"
ufw --force delete allow from 45.154.26.91 to any port 8070 >/dev/null
ufw --force delete allow from 57.158.25.236 to any port 8070 proto tcp >/dev/null
ufw --force delete allow from 57.158.25.236 to any port 8070 proto udp >/dev/null
ufw --force delete allow from 45.154.26.91 to any port 8000 proto tcp >/dev/null
ufw --force delete allow from 57.158.25.236 to any port 8000 proto tcp >/dev/null
ufw status | grep -E "8000|8070|8080|51820"
echo DONE
