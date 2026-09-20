import os
import time
import httpx
import hashlib
import logging
from datetime import timedelta
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, Request, Query
from typing import List, Dict, Any, Optional, Tuple
from services.rbac import require_viewer_or_above, get_current_user
from services.tenant_service import get_user_origins_and_domains, invalidate_tenant_cache
from services.dynamodb_service import DynamoDBService
from services.auth_service import AuthService
import services.origin_service as origin_service

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/tunnels", tags=["Private Tunnels"])
db = DynamoDBService()
auth_service = AuthService()

FRP_DASHBOARD_URL = os.getenv("FRP_DASHBOARD_URL", "http://127.0.0.1:7500/api/proxy/http")
FRP_ADMIN_USER = os.getenv("FRP_ADMIN_USER", "admin")
FRP_ADMIN_PASS = os.getenv("FRP_ADMIN_PASS", "admin1234")
LEGACY_STATIC_TOKEN = os.getenv("FRP_AUTH_TOKEN", "28cda1cc8790af9e459528ec6e325bcc4adf2ceb3f4b6f74de1f9c0a9a58b277")
# A tunnel token authenticates a persistent connection (Restart=always,
# meant to run unattended for months), not a browser login session -- see
# the 2026-09-20 fix notes on create_tunnel_token/get_tunnel_config below.
TUNNEL_TOKEN_DEFAULT_EXPIRE_DAYS = 365

RESERVED_SUBDOMAINS = {
    "main.waf-it-kku.online", "waf-it-kku.online", "www.waf-it-kku.online",
    "dash.waf-it-kku.online", "api.waf-it-kku.online", "auth.waf-it-kku.online",
    "main", "waf-it-kku", "www", "dash", "api", "auth", "admin", "core"
}

_TUNNELS_CACHE: Dict[str, Tuple[float, Dict[str, Any]]] = {}
CACHE_TTL = 3.0

# Served verbatim by main.py at GET /install-agent.sh (the URL the
# linux_oneliner command below pipes into `sudo bash`). Plain string, not an
# f-string -- every "{" here is bash (${VAR} / heredocs), not a Python
# placeholder; values come from the CLI args the user's own copy-pasted
# command supplies, mirroring the connection-token/proxy-metadatas split the
# frp_webhook_gatekeeper below actually enforces.
INSTALL_AGENT_SCRIPT = """#!/bin/bash
set -e

TOKEN=""
DOMAIN=""
PORT="3000"
IP="127.0.0.1"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --token) TOKEN="$2"; shift 2 ;;
    --domain) DOMAIN="$2"; shift 2 ;;
    --port) PORT="$2"; shift 2 ;;
    --ip) IP="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [[ -z "$TOKEN" || -z "$DOMAIN" ]]; then
  echo "Usage: install-agent.sh --token <jwt> --domain <domain> [--port <port>] [--ip <ip>]" >&2
  exit 1
fi

LEGACY_TOKEN="__CLOUDWAF_LEGACY_TOKEN__"
PROXY_NAME="$(echo "$DOMAIN" | tr '.' '-')"

mkdir -p /etc/waf-agent

if [[ ! -x /usr/local/bin/waf-agent ]]; then
  echo "==> Installing frpc 0.61.1 as /usr/local/bin/waf-agent..."
  ARCH="$(uname -m)"
  case "$ARCH" in
    x86_64) FRP_ARCH="amd64" ;;
    aarch64|arm64) FRP_ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH" >&2; exit 1 ;;
  esac
  TMP_DIR="$(mktemp -d)"
  curl -sSL "https://github.com/fatedier/frp/releases/download/v0.61.1/frp_0.61.1_linux_${FRP_ARCH}.tar.gz" -o "$TMP_DIR/frp.tar.gz"
  tar -xzf "$TMP_DIR/frp.tar.gz" -C "$TMP_DIR"
  install -m 755 "$TMP_DIR"/frp_0.61.1_linux_${FRP_ARCH}/frpc /usr/local/bin/waf-agent
  rm -rf "$TMP_DIR"
fi

cat > /etc/waf-agent/frpc.toml <<EOF
# CloudWAF Private Tunnel Configuration
serverAddr = "main.waf-it-kku.online"
serverPort = 7000
user = "$LEGACY_TOKEN"

auth.method = "token"
auth.token = "$LEGACY_TOKEN"

[[proxies]]
name = "$PROXY_NAME"
type = "http"
localIP = "$IP"
localPort = $PORT
customDomains = ["$DOMAIN"]
metadatas.token = "$TOKEN"
metadatas.port = "$PORT"
EOF

cat > /etc/systemd/system/waf-agent.service <<'EOF'
[Unit]
Description=CloudWAF Private Tunnel Agent
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/waf-agent -c /etc/waf-agent/frpc.toml
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now waf-agent

echo "==> waf-agent installed and started. Check status: systemctl status waf-agent"
"""


def render_install_agent_script() -> str:
    """Fills the __CLOUDWAF_LEGACY_TOKEN__ placeholder from the one canonical
    LEGACY_STATIC_TOKEN (env-sourced, declared above) at request time, so the
    real value exists in exactly one place in source rather than being
    duplicated as a second hardcoded literal inside the script template."""
    return INSTALL_AGENT_SCRIPT.replace("__CLOUDWAF_LEGACY_TOKEN__", LEGACY_STATIC_TOKEN)

# Fix 2026-09-07: connections using the shared legacy token pass Login (which
# reads content["privilege_key"] at the top level) but NewProxy events for
# that same connection carry no reusable identity at all -- a live capture
# during a real reconnect attempt showed content["user"] == {"user": "",
# "metas": null, "run_id": "..."} for the already-deployed dvwa/juice/bwapp
# tunnels, because their frpc.toml only sets connection-level auth.token and
# no per-proxy metadatas. NewProxy's identity check only looks at user/metas,
# so it always resolved to "none" and rejected every proxy on these
# connections -- this is what broke them when the gatekeeper was added.
# FRP mirrors the same run_id across Login and every later NewProxy/
# CloseProxy call on that connection, so remember which run_ids passed
# Login via the legacy token and trust NewProxy calls that share one,
# instead of re-deriving an identity NewProxy was never actually given.
_LEGACY_RUN_IDS: Dict[str, float] = {}
_LEGACY_RUN_ID_TTL = 24 * 3600  # a control connection can legitimately live for days

# 2026-09-19 fix: Origin ownership used to be assigned to whoever happened to
# view the Tunnels/Origins page first after a proxy came online (see
# origin_service.auto_sync_tunnel_origins), not the account that actually
# minted the tunnel token -- a first-viewer race, not real RBAC. NewProxy
# below already decodes and verifies the domain-scoped JWT for every proxy
# that gets this far (the "jwt" branch), so it is the one place that
# authoritatively knows the true owner at the moment a tunnel registers.
# Record it here; auto_sync_tunnel_origins reads it via get_proxy_owner()
# instead of trusting its caller's own user_id.
_PROXY_OWNERS: Dict[str, str] = {}


def get_proxy_owner(proxy_name: str) -> Optional[str]:
    return _PROXY_OWNERS.get(proxy_name)


def _remember_legacy_run_id(run_id: str) -> None:
    if not run_id:
        return
    now = time.time()
    _LEGACY_RUN_IDS[run_id] = now
    if len(_LEGACY_RUN_IDS) > 500:
        cutoff = now - _LEGACY_RUN_ID_TTL
        for rid, ts in list(_LEGACY_RUN_IDS.items()):
            if ts < cutoff:
                del _LEGACY_RUN_IDS[rid]


def _is_legacy_run_id(run_id: str) -> bool:
    if not run_id:
        return False
    ts = _LEGACY_RUN_IDS.get(run_id)
    return ts is not None and (time.time() - ts) < _LEGACY_RUN_ID_TTL


class CreateTunnelTokenRequest(BaseModel):
    domain: str
    label: Optional[str] = None
    expires_days: Optional[int] = 365


def _match_proxy_to_origin(proxy_name: str, origin_label: str, origin_ip: str, domain: str = "") -> bool:
    p_name = proxy_name.lower().replace('-', '.').replace('_', '.')
    d_name = domain.lower().replace('-', '.').replace('_', '.') if domain else ""
    o_lbl = origin_label.lower().replace('-', '.').replace('_', '.')
    o_ip = origin_ip.lower().replace('-', '.').replace('_', '.')

    # 1. Exact or direct substring match on domain
    if d_name:
        if d_name == o_ip or d_name in o_lbl:
            return True
    if p_name and (p_name == o_ip or p_name in o_lbl):
        return True

    # 2. Extract specific subdomain components (excluding common base domain tokens)
    ignored_parts = {"online", "com", "net", "org", "local", "localhost", "waf", "kku", "it", "agent", "tunnel", "server"}
    p_parts = [p for p in p_name.split('.') if len(p) >= 3 and p not in ignored_parts]
    d_parts = [p for p in d_name.split('.') if len(p) >= 3 and p not in ignored_parts]
    o_parts = [p for p in o_ip.split('.') if len(p) >= 3 and p not in ignored_parts]

    check_parts = set(p_parts + d_parts)
    for p in check_parts:
        if p in o_parts or (f"({p}" in o_lbl or f" {p}" in o_lbl or f"-{p}" in o_lbl or f".{p}" in o_lbl):
            return True
    return False


def _assert_domain_claimable(domain_clean: str, current_user: dict) -> None:
    """Refuse to mint a tunnel token for a domain the caller does not own.

    A tunnel token is a bearer claim over one hostname: the FRP gatekeeper
    authorizes a proxy binding purely on the `domain` inside it. Issuing one for
    a domain registered to another account would therefore hand over that
    account's traffic, so both issuing endpoints funnel through here.
    """
    if domain_clean in RESERVED_SUBDOMAINS:
        raise HTTPException(
            status_code=400,
            detail=f"Domain '{domain_clean}' is reserved for WAF Core infrastructure.",
        )
    user_id = current_user.get("user_id")
    is_admin = current_user.get("role") == "admin"
    for d in db.domains_table.scan().get("Items", []):
        if str(d.get("domain_name", "")).lower() != domain_clean:
            continue
        origin_id = d.get("origin_id")
        if not origin_id:
            continue
        origin_rec = db.get_origin_by_id(origin_id)
        if origin_rec and origin_rec.get("admin_user_id") != user_id and not is_admin:
            raise HTTPException(
                status_code=403,
                detail="This domain is already registered by another account.",
            )


@router.post("/token")
async def create_tunnel_token(payload: CreateTunnelTokenRequest, current_user: dict = Depends(get_current_user)):
    """
    Generate a cryptographic signed JWT Tunnel Token tied to the user and domain.
    """
    user_id = current_user.get("user_id")
    username = current_user.get("username", "user")
    domain_clean = payload.domain.strip().lower()

    _assert_domain_claimable(domain_clean, current_user)

    # Generate Token
    # 2026-09-20 fix: expires_sec was computed here and never used -- this
    # endpoint's own response below has always claimed "expires_in_days:
    # 365" while the token itself silently carried auth_service's login-
    # session default (60 minutes, see ACCESS_TOKEN_EXPIRE_MINUTES). A
    # tunnel token authenticates a long-lived, persistent connection
    # (Restart=always, meant to run for months), not a browser session --
    # confirmed live on a real Lab deploy: its frpc.toml tokens had expired
    # ~8h after being issued, silently breaking every proxy on that agent
    # with "Invalid or expired WAF Tunnel Token" until someone happened to
    # notice and re-ran the installer.
    expires_sec = (payload.expires_days or TUNNEL_TOKEN_DEFAULT_EXPIRE_DAYS) * 86400
    token_data = {
        "sub": user_id,
        "user_id": user_id,
        "username": username,
        "domain": domain_clean,
        "type": "tunnel_token",
    }
    token = auth_service.create_access_token(token_data, expires_delta=timedelta(seconds=expires_sec))

    return {
        "success": True,
        "token": token,
        "domain": domain_clean,
        "user_id": user_id,
        "username": username,
        "expires_in_days": payload.expires_days or 365,
    }


@router.get("/config-generator")
async def get_tunnel_config(
    domain: str = Query(
        ...,
        description="The domain this agent config will bind. Required: the caller must "
                    "own it, and there is no sensible default to fall back on.",
    ),
    port: int = 3000,
    local_ip: str = "127.0.0.1",
    platform: str = "linux",
    current_user: dict = Depends(get_current_user)
):
    """
    Generate personalized one-liner commands with user-specific signed Tunnel Token.
    """
    user_id = current_user.get("user_id")
    username = current_user.get("username", "user")
    domain_clean = domain.strip().lower()
    _assert_domain_claimable(domain_clean, current_user)

    # Generate user-specific token
    # 2026-09-20 fix: same bug as create_tunnel_token above -- no
    # expires_delta meant this silently used auth_service's 60-minute
    # login-session default instead of a lifetime appropriate for a
    # persistent tunnel connection. This is the endpoint the 1-Click
    # installer's copy-paste command actually calls, so this was the one
    # that broke a real Lab deploy's tunnels ~1h after every fresh install.
    token_data = {
        "sub": user_id,
        "user_id": user_id,
        "username": username,
        "domain": domain_clean,
        "type": "tunnel_token",
    }
    token = auth_service.create_access_token(
        token_data, expires_delta=timedelta(days=TUNNEL_TOKEN_DEFAULT_EXPIRE_DAYS)
    )

    safe_name = f"waf-agent-{domain_clean.replace('.', '-')}"

    # Two tokens are in play, and the FRP gatekeeper (frp_webhook_gatekeeper
    # above) requires each at a different scope: the connection-level
    # auth.token is checked against the shared LEGACY_STATIC_TOKEN at Login
    # (it carries no domain claim, so NewProxy explicitly rejects it -- see
    # the "legacy" branch under op == "NewProxy"); the domain-scoped JWT must
    # ride in metadatas.token on the [[proxies]] block, which is what
    # NewProxy actually reads (content["metas"]["token"]) to authorize the
    # binding. Verified against a live reconnect: this is the exact layout
    # that produced "login to server success" + "start proxy success".
    #
    # metadatas.port: FRP's admin dashboard API (what origin_service.py's
    # auto-create and get_tunnels_status below poll) returns conf.localIP
    # but never conf.localPort -- frps genuinely does not track the client's
    # local port at all, confirmed against a live proxy (verified 2026-09-19).
    # metadatas IS returned in full by that same API, so the local port rides
    # along there too, next to the token, instead of a field FRP will never
    # give back.
    toml_config = (
        f'# CloudWAF Private Tunnel Configuration\n'
        f'serverAddr = "main.waf-it-kku.online"\n'
        f'serverPort = 7000\n'
        f'user = "{LEGACY_STATIC_TOKEN}"\n\n'
        f'auth.method = "token"\n'
        f'auth.token = "{LEGACY_STATIC_TOKEN}"\n\n'
        f'[[proxies]]\n'
        f'name = "{domain_clean.replace(".", "-")}"\n'
        f'type = "http"\n'
        f'localIP = "{local_ip}"\n'
        f'localPort = {port}\n'
        f'customDomains = ["{domain_clean}"]\n'
        f'metadatas.token = "{token}"\n'
        f'metadatas.port = "{port}"\n'
    )
    linux_command = (
        f"curl -sSL https://waf-it-kku.online/install-agent.sh | sudo bash -s -- "
        f"--token {token} --domain {domain_clean} --port {port} --ip {local_ip}"
    )
    # frpc 0.61.1 dropped the old --proxy_type/--custom_domains/--local_port
    # CLI flags entirely (config is toml-only now), so a proxy can no longer
    # be described on the command line -- write the same toml_config to disk
    # and mount it in, instead of maintaining a second, incompatible format.
    # /etc/waf-agent is root:root 755 (verified on a real non-root deploy
    # user): a plain `cat > /etc/waf-agent/...` redirect fails with Permission
    # denied *before* `docker run` even executes, and `-v` against the
    # now-missing path makes Docker silently create it as an empty directory,
    # which then fails the bind-mount ("not a directory") -- `sudo` alone on
    # `cat` does not help because the shell, not `cat`, performs the `>`
    # redirection, so it must be `sudo tee` instead. Every privileged step
    # gets its own explicit `sudo`, matching the linux_oneliner above.
    docker_command = (
        f"sudo mkdir -p /etc/waf-agent && sudo tee /etc/waf-agent/{safe_name}.toml > /dev/null <<'EOF'\n"
        f"{toml_config}"
        f"EOF\n"
        f"sudo docker run -d --name {safe_name} --restart=always --net=host "
        f"-v /etc/waf-agent/{safe_name}.toml:/etc/frp/frpc.toml:ro "
        f"snowdreamtech/frpc:0.61.1 -c /etc/frp/frpc.toml"
    )

    return {
        "success": True,
        "domain": domain_clean,
        "port": port,
        "token": token,
        "commands": {
            "linux_oneliner": linux_command,
            "docker_command": docker_command,
            "raw_toml": toml_config
        },
        "linux_command": linux_command,
        "docker_command": docker_command,
        "toml_config": toml_config
    }


def _extract_raw_token(user_block: Dict[str, Any], priv_key: str = "") -> str:
    """Pulls the client's token out of an FRP plugin event's identity block.
    `user_block` is `content` itself for Login, or `content["user"]` for
    NewProxy/CloseProxy -- FRP mirrors the same user/metas fields from the
    original Login onto every later plugin event for that connection.
    """
    user_field = str(user_block.get("user") or "").strip()
    metadatas = user_block.get("metadatas") or user_block.get("metas") or {}
    meta_token = str(metadatas.get("token") or "").strip()
    return meta_token or user_field or (priv_key if priv_key.startswith("eyJ") else "")


def _resolve_frp_identity(raw_token: str, priv_key: str = "", ts: int = 0) -> Tuple[str, Optional[Dict[str, Any]]]:
    """Returns ("legacy", None), ("jwt", payload), or ("none", None).

    Legacy check first (dual-mode: raw match or the MD5-hashed variant),
    then a real JWT tunnel token. Shared between Login (which only needs to
    know "is this someone", per the caller's existing behaviour) and
    NewProxy (which additionally needs the decoded payload to check the
    domain claim -- see the docstring on frp_webhook_gatekeeper).
    """
    if priv_key == LEGACY_STATIC_TOKEN or raw_token == LEGACY_STATIC_TOKEN:
        return "legacy", None
    if priv_key and ts:
        for delta in (0, -1, 1, -2, 2, -3, 3, -4, 4, -5, 5):
            expected_hash = hashlib.md5((LEGACY_STATIC_TOKEN + str(ts + delta)).encode()).hexdigest()
            if expected_hash.lower() == priv_key.lower():
                return "legacy", None
    if raw_token:
        payload = auth_service.decode_token(raw_token)
        if payload:
            return "jwt", payload
    return "none", None


@router.post("/frp-hook")
async def frp_webhook_gatekeeper(req: Dict[str, Any]):
    """
    FRP v0.61.1 HTTP Plugin Webhook Gatekeeper.
    Intercepts Login & NewProxy events to enforce User Token Validation and Domain Ownership.
    """
    op = req.get("op", "")
    content = req.get("content", {})

    if op == "Login":
        ts = content.get("timestamp", 0)
        priv_key = str(content.get("privilege_key") or "").strip()
        raw_token = _extract_raw_token(content, priv_key)

        kind, payload = _resolve_frp_identity(raw_token, priv_key, ts)

        if kind == "legacy":
            logger.info(f"FRP Webhook: Authorized Login via Legacy System Token (IP: {content.get('client_address')})")
            _remember_legacy_run_id(str(content.get("run_id") or "").strip())
            return {"reject": False, "unchange": True}

        if kind == "jwt":
            user_id = payload.get("user_id") or payload.get("sub")
            logger.info(f"FRP Webhook: Authorized User '{payload.get('username')}' (ID: {user_id}) Login")
            return {"reject": False, "unchange": True}

        logger.warning(f"FRP Webhook: Rejecting unauthorized client: {content.get('client_address')}")
        return {"reject": True, "reject_reason": "Authentication failed: Invalid or expired WAF Tunnel Token", "unchange": True}

    elif op == "NewProxy":
        custom_domains = content.get("custom_domains") or ([content.get("domain")] if content.get("domain") else [])
        proxy_name = content.get("proxy_name", "")
        target_domain = str(custom_domains[0] if custom_domains else proxy_name).strip().lower()

        if not target_domain:
            return {"reject": False, "unchange": True}

        # Check Reserved Domains
        if target_domain in RESERVED_SUBDOMAINS:
            logger.warning(f"FRP Webhook: Blocked attempt to bind reserved domain '{target_domain}'")
            return {"reject": True, "reject_reason": f"Domain '{target_domain}' is reserved by CloudWAF Core", "unchange": True}

        # Domain ownership: mirror the identity check from Login. FRP's
        # plugin protocol nests it under content["user"] for this op
        # (content["user"]["user"] / content["user"]["metas"]), same shape
        # as Login's top-level fields, so _extract_raw_token/_resolve_frp_identity
        # are reused unchanged, just pointed at the nested block.
        # Fix 2026-09-07 (verified by tcpdump on lo:8000 during a live
        # reconnect): FRP puts a proxy's own `metadatas` at the TOP level of
        # content -- content["metas"] -- and only mirrors the *connection*
        # level identity into content["user"], which for a token-auth client
        # is {"user": "", "metas": null, "run_id": "..."}. Reading only
        # content["user"] therefore never saw a per-proxy token, so a proxy
        # whose frpc.toml carried a correctly scoped token still fell through
        # to the identity-less reject. Prefer the proxy's own token, then fall
        # back to the connection-level block.
        user_block = content.get("user") or {}
        proxy_metas = content.get("metas") or {}
        raw_token = str(proxy_metas.get("token") or "").strip() or _extract_raw_token(user_block)
        kind, payload = _resolve_frp_identity(raw_token)

        if kind == "legacy":
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

        if kind == "jwt":
            token_domain = str(payload.get("domain") or "").strip().lower()
            if token_domain == target_domain:
                owner_id = payload.get("user_id") or payload.get("sub")
                if owner_id:
                    _PROXY_OWNERS[proxy_name] = owner_id
                logger.info(f"FRP Webhook: Proxy '{proxy_name}' authorized for domain '{target_domain}' (owned by token)")
                return {"reject": False, "unchange": True}
            logger.warning(
                f"FRP Webhook: Blocked cross-domain proxy attempt -- token scoped to "
                f"'{token_domain}' tried to register '{target_domain}'"
            )
            return {"reject": True, "reject_reason": "Token is not authorized for this domain", "unchange": True}

        logger.warning(f"FRP Webhook: Blocked NewProxy with no valid identity for domain '{target_domain}'")
        return {"reject": True, "reject_reason": "Authentication failed: Invalid or expired WAF Tunnel Token", "unchange": True}

    elif op == "CloseProxy":
        proxy_name = content.get("proxy_name", "")
        logger.info(f"FRP Webhook: Proxy closed: {proxy_name}")
        return {"reject": False, "unchange": True}

    # Fail-closed: an operation this gatekeeper does not recognise must not
    # default-allow (a future FRP protocol addition, or a malformed op).
    logger.warning(f"FRP Webhook: Rejecting unrecognised operation '{op}'")
    return {"reject": True, "reject_reason": f"Unrecognised operation '{op}'", "unchange": True}


@router.get("/status")
async def get_tunnels_status(
    scope: Optional[str] = Query("my", description="Scope of tunnels: 'my' for user-owned only, 'all' for admin global view"),
    current_user: dict = Depends(get_current_user)
):
    """
    Query FRP daemon with multi-tenant isolation and 3-second caching.
    """
    user_id = current_user.get("user_id")
    user_role = current_user.get("role", "user")
    is_admin = (user_role == "admin")
    view_all = is_admin and (scope == "all")

    cache_key = f"{user_id}:{user_role}:{scope}"
    now = time.time()

    # 1. Immediate cache return (< 0.1ms)
    if cache_key in _TUNNELS_CACHE:
        cached_time, cached_res = _TUNNELS_CACHE[cache_key]
        if now - cached_time < CACHE_TTL:
            return cached_res

    # Auto-sync online tunnels to DynamoDB origins
    await origin_service.auto_sync_tunnel_origins(user_id, user_role)
    _, active_origins, user_domains = get_user_origins_and_domains(user_id)

    all_origins = db.origins_table.scan().get("Items", []) if view_all else active_origins
    all_users_map = {}
    if is_admin:
        try:
            users_list = db.waf_users.scan().get("Items", [])
            all_users_map = {u.get("user_id"): u.get("username", "Unknown") for u in users_list}
        except Exception:
            pass

    try:
        async with httpx.AsyncClient(timeout=1.2) as client:
            res = await client.get(
                FRP_DASHBOARD_URL,
                auth=(FRP_ADMIN_USER, FRP_ADMIN_PASS)
            )
            if res.status_code != 200:
                result = {
                    "success": False,
                    "error": f"FRP dashboard returned HTTP {res.status_code}",
                    "tunnels": [],
                    "count": 0,
                    "active_count": 0,
                    "scope": scope
                }
                _TUNNELS_CACHE[cache_key] = (now, result)
                return result

            data = res.json()
            proxies = data.get("proxies", [])
            user_tunnels = []
            active_count = 0

            for p in proxies:
                conf = p.get("conf") or {}
                raw_name = p.get("name", "")
                
                # Check if proxy name is namespaced with User JWT Token (e.g. eyJhbGci...app-user)
                owner_from_token = None
                display_name = raw_name
                token_username = None
                if "." in raw_name and raw_name.startswith("eyJ"):
                    token_part, actual_name = raw_name.rsplit(".", 1)
                    token_payload = auth_service.decode_token(token_part)
                    if token_payload:
                        owner_from_token = token_payload.get("user_id") or token_payload.get("sub")
                        token_username = token_payload.get("username")
                        display_name = actual_name

                custom_domains = conf.get("customDomains") or conf.get("custom_domains") or []
                domain_val = custom_domains[0] if custom_domains else display_name
                domain_lower = str(domain_val).lower()

                matching_origin = next(
                    (o for o in all_origins if _match_proxy_to_origin(display_name, o.get("label", ""), o.get("ip", ""), domain=domain_val)),
                    None
                )

                # Determine true owner
                owner_id = owner_from_token or (matching_origin.get("admin_user_id") if matching_origin else None)
                if not owner_id and is_admin:
                    owner_id = user_id

                is_mine = (owner_id == user_id)
                # Tenancy isolation filter
                is_user_tunnel = is_mine or any(
                    domain_lower in d or d in domain_lower for d in user_domains
                ) or view_all

                if not is_user_tunnel:
                    continue

                status_val = p.get("status", "offline")
                is_online = status_val == "online"
                if is_online:
                    active_count += 1

                cur_conns = p.get("curConns") if "curConns" in p else p.get("cur_conns", 0)
                traffic_in = p.get("todayTrafficIn") if "todayTrafficIn" in p else p.get("today_traffic_in", 0)
                traffic_out = p.get("todayTrafficOut") if "todayTrafficOut" in p else p.get("today_traffic_out", 0)
                local_ip = conf.get("localIP") or conf.get("local_ip") or "127.0.0.1"
                # frps' dashboard API never carries localPort (confirmed
                # live, see the note in config-generator above) -- metadatas
                # is the one thing here that's ours end to end, so the port
                # we embedded there at generation time is the only reliable
                # source; the localPort/local_port reads stay only for any
                # tunnel whose config predates this fix.
                local_port = (
                    (conf.get("metadatas") or {}).get("port")
                    or conf.get("localPort") or conf.get("local_port") or 80
                )

                owner_name = token_username or all_users_map.get(owner_id, "You" if is_mine else "User")

                user_tunnels.append({
                    "name": display_name,
                    "full_name": raw_name,
                    "domain": domain_val,
                    "origin_id": matching_origin.get("id") if matching_origin else None,
                    "owner_id": owner_id,
                    "owner_username": owner_name,
                    "is_mine": is_mine,
                    "url": f"https://{domain_val}" if domain_val else "-",
                    "local_target": f"{local_ip}:{local_port}",
                    "status": status_val,
                    "is_online": is_online,
                    "connections": cur_conns,
                    "traffic_in_bytes": traffic_in,
                    "traffic_out_bytes": traffic_out,
                    "last_start": p.get("lastStartTime") or p.get("last_start_time", "-"),
                    "last_close": p.get("lastCloseTime") or p.get("last_close_time", "-"),
                })

            result = {
                "success": True,
                "hub_host": "main.waf-it-kku.online",
                "hub_port": 7000,
                "scope": "all" if view_all else "my",
                "is_admin": is_admin,
                "tunnels": user_tunnels,
                "count": len(user_tunnels),
                "active_count": active_count
            }
            _TUNNELS_CACHE[cache_key] = (now, result)
            return result

    except Exception as e:
        logger.error(f"Failed to query FRP daemon status: {e}")
        return {
            "success": False,
            "error": str(e),
            "tunnels": [],
            "count": 0,
            "active_count": 0,
            "scope": scope
        }


@router.delete("/{target_identifier}")
async def deregister_tunnel(target_identifier: str, current_user: dict = Depends(get_current_user)):
    user_id = current_user.get("user_id")
    user_role = current_user.get("role")
    target_clean = target_identifier.strip().lower()

    global _TUNNELS_CACHE
    _TUNNELS_CACHE.clear()

    all_origins = db.origins_table.scan().get("Items", [])
    matched_origin = None

    for o in all_origins:
        o_lbl = str(o.get("label", "")).lower()
        o_ip = str(o.get("ip", "")).lower()
        o_id = str(o.get("id", ""))
        if (target_clean == o_id or target_clean in o_lbl or target_clean in o_ip or
            any(part in o_ip for part in target_clean.split('.') if len(part) >= 4)):
            if o.get("admin_user_id") == user_id or user_role == "admin":
                matched_origin = o
                break

    if matched_origin:
        origin_service.delete_origin(matched_origin.get("id"))
        return {
            "status": "success",
            "message": f"Tunnel '{matched_origin.get('label')}' deregistered successfully."
        }

    if user_role == "admin":
        return {
            "status": "success",
            "message": f"Tunnel '{target_identifier}' removed."
        }

    raise HTTPException(status_code=404, detail=f"Tunnel or Origin '{target_identifier}' not found under your account.")
