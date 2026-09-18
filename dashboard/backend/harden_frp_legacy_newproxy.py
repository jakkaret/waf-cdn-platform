"""PREPARED, NOT APPLIED -- closes the unscoped legacy NewProxy grant.

Today a NewProxy event whose identity resolves to the shared static FRP token
is allowed to bind ANY domain (api/tunnels.py, `if kind == "legacy"` inside the
NewProxy branch), and a second fallback trusts any run_id remembered from a
legacy Login. Both bypass the per-domain ownership check, so possession of the
one shared token is enough to claim another tenant's hostname -- the exact
condition SYSTEM-OPERATIONAL-REQUIREMENTS.md 10 forbids ("A tunnel must never
become a path to another tenant's origin").

Those branches existed only because the Lab's proxies carried no per-proxy
identity. As of 2026-09-07 all three carry domain-scoped JWTs in
/etc/waf-agent/frpc.toml, and frps reports exactly one connected client, so
the fallbacks are now dead weight that only widen the trust boundary.

Apply with:
  scp harden_frp_legacy_newproxy.py root@178.104.53.123:/tmp/
  ssh root@178.104.53.123 'cd /root/waf_project/dashboard/backend \
    && cp -p api/tunnels.py api/tunnels.py.bak-$(date +%Y%m%d-%H%M%S) \
    && .venv/bin/python /tmp/harden_frp_legacy_newproxy.py \
    && .venv/bin/python -m py_compile api/tunnels.py \
    && systemctl restart waf-dashboard'
Then force the client to re-register and confirm it still authorizes:
  ssh project@10.198.200.75 'sudo systemctl restart waf-agent'
  ssh root@178.104.53.123 'journalctl -u frps -n 10 --no-pager'
Rollback: restore the .bak file and restart waf-dashboard.
"""
p = "/root/waf_project/dashboard/backend/api/tunnels.py"
s = open(p).read()

old = '''        if kind == "legacy":
            # Shared legacy token is not scoped to one domain -- preserves
            # the already-deployed dvwa/juice/vampi/bwapp tunnels, which
            # authenticate this way.
            logger.info(f"FRP Webhook: Proxy '{proxy_name}' authorized for domain '{target_domain}' (legacy token)")
            return {"reject": False, "unchange": True}

'''
new = '''        if kind == "legacy":
            # The shared static token carries no domain claim, so it cannot
            # establish that this client owns `target_domain`. It stays valid
            # for Login (it is the frps connection secret) but must not by
            # itself authorize a proxy binding: every proxy now ships a
            # domain-scoped token in its frpc.toml `metadatas.token`.
            logger.warning(
                f"FRP Webhook: Blocked proxy '{proxy_name}' for domain '{target_domain}' -- "
                f"shared legacy token is not scoped to a domain"
            )
            return {
                "reject": True,
                "reject_reason": "Tunnel token is not scoped to a domain; regenerate the agent config",
                "unchange": True,
            }

'''
assert s.count(old) == 1, f"legacy-allow anchor found {s.count(old)} times"
s = s.replace(old, new)

old_runid = '''        run_id = str(user_block.get("run_id") or "").strip()
        if _is_legacy_run_id(run_id):
            logger.info(
                f"FRP Webhook: Proxy '{proxy_name}' authorized for domain "
                f"'{target_domain}' (legacy connection, run_id={run_id})"
            )
            return {"reject": False, "unchange": True}

'''
assert s.count(old_runid) == 1, f"run_id fallback anchor found {s.count(old_runid)} times"
s = s.replace(old_runid, "")

open(p, "w").write(s)
print("hardened: legacy NewProxy allow removed, run_id fallback removed")
