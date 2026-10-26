"""
Synthetic content for the deception layer (honeypot).

Every fake artefact is generated in memory from a per-site profile. The
profile is derived from HMAC(DECEPTION_INTERNAL_KEY, host), so:

  * one site always serves the same fake data (an attacker who repeats a
    request, or reads /etc/passwd then /etc/shadow, sees a consistent box);
  * two sites never serve the same data (comparing hashes across sites
    gives nothing away);
  * nobody can predict the data without the key.

Secrets placed in the fake data (admin password, DB password, AWS keys,
API key, app key) are honeytokens: they exist nowhere else, so a request
that carries one is an attacker replaying loot. managed_ruleset writes
them into a ModSecurity @pm rule (see honeytoken_rule) and the deception
service recognises them per host.

Nothing here reads files, opens sockets or calls out: the content is fake
by construction.
"""

from __future__ import annotations

import base64
import functools
import hashlib
import hmac
import html
import json
import os
import random
import re
import string
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

KEY_ENV = "DECEPTION_INTERNAL_KEY"
_DEFAULT_KEY = b"waf-deception-local"

ALNUM = string.ascii_letters + string.digits
_AWS_ID = string.ascii_uppercase + "234567"
_BCRYPT = "./" + string.ascii_uppercase + string.ascii_lowercase + string.digits
_HEX = "0123456789abcdef"

MAX_DELAY_SECONDS = 10.0
HONEYTOKEN_RULE_ID = 3190001


# ---------------------------------------------------------------------------
# Per-site profile
# ---------------------------------------------------------------------------

def _key() -> bytes:
    k = os.getenv(KEY_ENV, "")
    return k.encode("utf-8") if k else _DEFAULT_KEY


def normalize_host(host: Optional[str]) -> str:
    h = (host or "").strip().lower()
    if h.startswith("["):
        return ""
    h = h.split(":", 1)[0].rstrip(".")
    return h if re.fullmatch(r"[a-z0-9.-]{1,253}", h) else ""


def _derive(key: bytes, host: str, kind: str, alphabet: str, n: int) -> str:
    out = []
    counter = 0
    while len(out) < n:
        digest = hmac.new(key, f"{kind}|{host}|{counter}".encode(), hashlib.sha256).digest()
        out.extend(alphabet[b % len(alphabet)] for b in digest)
        counter += 1
    return "".join(out[:n])


_WORDS = [
    "Harbor", "Falcon", "Granite", "Maple", "Orchid", "Cobalt", "Summit", "Willow",
    "Lantern", "Meadow", "Copper", "Saffron", "Juniper", "Pioneer", "Thunder", "Velvet",
]
_FIRST = [
    "somchai", "nattapong", "kanya", "pimchanok", "anan", "supaporn", "david", "sarah",
    "michael", "emily", "wei", "yuki", "arthit", "malee", "thanawat", "jirapat",
]
_LAST = "abcdeghjklmnprstuwy"
_ADMINS = ["admin", "administrator", "sysadmin", "webmaster", "itadmin"]
_SERVICE_ACCOUNTS = [
    ("deploy", "Deploy User,,,", "/home/deploy", "/bin/bash"),
    ("jenkins", "Jenkins CI,,,", "/var/lib/jenkins", "/bin/bash"),
    ("backup", "Backup Operator,,,", "/home/backupop", "/bin/sh"),
    ("monitor", "Monitoring Agent,,,", "/home/monitor", "/usr/sbin/nologin"),
    ("git", "Git Service,,,", "/home/git", "/usr/bin/git-shell"),
    ("appuser", "Application Service Account,,,", "/home/appuser", "/bin/sh"),
    ("secops", "Security Operations,,,", "/home/secops", "/bin/bash"),
]
_MYSQL_VERSIONS = ["8.0.36-0ubuntu0.22.04.1", "8.0.39-0ubuntu0.22.04.1", "8.0.40-0ubuntu0.24.04.1", "5.7.44-log"]
_KERNELS = ["5.15.0-122-generic", "5.15.0-131-generic", "6.8.0-45-generic", "6.8.0-51-generic"]
_COLUMNS = ["id", "username", "email", "password_hash", "role", "created_at", "last_login"]
_TABLES = ["users", "sessions", "orders", "order_items", "payments", "api_keys", "audit_log", "settings"]


@dataclass(frozen=True)
class Site:
    host: str
    slug: str
    mail_domain: str
    hostname: str
    private_ip: str
    db_host: str
    db_name: str
    db_user: str
    mysql_version: str
    kernel: str
    ncols: int
    admin_user: str
    os_accounts: Tuple[Tuple[str, int, str, str, str], ...]
    users: Tuple[Dict[str, object], ...]
    tokens: Dict[str, str] = field(default_factory=dict)
    salts: Tuple[str, ...] = ()
    seed: int = 0
    key: bytes = _DEFAULT_KEY

    @property
    def columns(self) -> List[str]:
        return _COLUMNS[: self.ncols]

    def rng(self, purpose: str) -> random.Random:
        return random.Random(f"{self.seed}|{purpose}")


def honeytoken_values(site: "Site") -> List[str]:
    return [site.tokens[k] for k in sorted(site.tokens)]


@functools.lru_cache(maxsize=2048)
def _build_site(host: str, key: bytes) -> Site:
    seed = int.from_bytes(hmac.new(key, f"site|{host}".encode(), hashlib.sha256).digest()[:8], "big")
    rng = random.Random(seed)

    labels = [l for l in host.split(".") if l]
    if labels and labels[0] == "www":
        labels = labels[1:]
    slug = re.sub(r"[^a-z0-9]", "", labels[0]) if labels else ""
    if not slug or slug.isdigit():
        slug = "app"
    mail_domain = ".".join(labels) if len(labels) >= 2 else "corp.internal"

    octet2, octet3 = rng.randint(0, 31), rng.randint(1, 254)
    private_ip = f"10.{octet2}.{octet3}.{rng.randint(10, 60)}"
    db_host = f"10.{octet2}.{octet3}.{rng.randint(61, 120)}"

    admin_user = rng.choice(_ADMINS)
    services = rng.sample(_SERVICE_ACCOUNTS, 4)
    os_accounts = [(admin_user, 1000, "Administrator,,,", f"/home/{admin_user}", "/bin/bash")]
    for i, (name, gecos, home, shell) in enumerate(services, start=1):
        os_accounts.append((name, 1000 + i, gecos, home, shell))

    def bcrypt_hash(tag: str) -> str:
        return "$2y$10$" + _derive(key, host, f"bcrypt|{tag}", _BCRYPT, 53)

    base = datetime(2024, 1, 15, tzinfo=timezone.utc) + timedelta(days=rng.randint(0, 400))
    users = []
    names = rng.sample(_FIRST, rng.randint(5, 8))
    for i, first in enumerate([admin_user] + names, start=1):
        username = first if i == 1 else f"{first}.{rng.choice(_LAST)}"
        created = base + timedelta(days=17 * i + rng.randint(0, 9), minutes=rng.randint(0, 1439))
        users.append({
            "id": i,
            "username": username,
            "email": f"{username}@{mail_domain}",
            "password_hash": bcrypt_hash(username),
            "role": "admin" if i == 1 else rng.choice(["editor", "user", "user", "user", "support"]),
            "created_at": created.strftime("%Y-%m-%d %H:%M:%S"),
            "last_login": (created + timedelta(days=rng.randint(20, 200))).strftime("%Y-%m-%d %H:%M:%S"),
        })

    word = _WORDS[int(_derive(key, host, "admin-word", string.digits, 4)) % len(_WORDS)]
    tokens = {
        "admin_password": word + _derive(key, host, "admin-digits", string.digits, 4)
        + _derive(key, host, "admin-tail", ALNUM, 2),
        "db_password": _derive(key, host, "db-password", ALNUM, 20),
        "aws_access_key_id": "AKIA" + _derive(key, host, "aws-id", _AWS_ID, 16),
        "aws_session_key_id": "ASIA" + _derive(key, host, "aws-sts-id", _AWS_ID, 16),
        "aws_secret_access_key": _derive(key, host, "aws-secret", ALNUM, 40),
        "api_key": _derive(key, host, "api-key", _HEX, 32),
        "app_key": _derive(key, host, "app-key", ALNUM, 43),
    }
    salts = tuple(_derive(key, host, f"wp-salt-{i}", ALNUM + "!#%^*()-_=+[]{}<>~", 64) for i in range(8))

    return Site(
        host=host,
        slug=slug,
        mail_domain=mail_domain,
        hostname=f"{rng.choice(['web', 'app', 'prod-web', 'www'])}-{rng.randint(1, 4):02d}",
        private_ip=private_ip,
        db_host=db_host,
        db_name=rng.choice([f"{slug}_prod", f"{slug}_db", f"{slug}_production", f"{slug}"]),
        db_user=rng.choice([f"{slug}_app", f"{slug}_rw", "webapp"]),
        mysql_version=rng.choice(_MYSQL_VERSIONS),
        kernel=rng.choice(_KERNELS),
        ncols=rng.randint(4, 7),
        admin_user=admin_user,
        os_accounts=tuple(os_accounts),
        users=tuple(users),
        tokens=tokens,
        salts=salts,
        seed=seed,
        key=key,
    )


def site_for(host: Optional[str]) -> Site:
    # Hostless requests (direct IP, lab) carry no honeytokens worth tracking,
    # so they get one fixed profile that does not depend on the key.
    h = normalize_host(host)
    return _build_site(h, _key() if h else _DEFAULT_KEY)


# ---------------------------------------------------------------------------
# Request context
# ---------------------------------------------------------------------------

def _decode(text: str, rounds: int = 3) -> str:
    s = text or ""
    for _ in range(rounds):
        nxt = urllib.parse.unquote_plus(s)
        if nxt == s:
            break
        s = nxt
    return s.replace("\x00", "")


@dataclass
class Ctx:
    uri: str
    method: str
    body: str
    accept: str = ""
    path: str = ""
    raw_query: str = ""
    text: str = ""          # decoded query + body, case preserved, comments collapsed

    @classmethod
    def build(cls, uri: str, method: str = "GET", body: str = "", accept: str = "") -> "Ctx":
        uri = (uri or "/")[:4096]
        body = (body or "")[:4096]
        path, _, query = uri.partition("?")
        text = _decode(query) + " " + _decode(body)
        text = re.sub(r"/\*.{0,512}?\*/", " ", text)
        return cls(uri=uri, method=(method or "GET").upper(), body=body, accept=(accept or "").lower(),
                   path=_decode(path), raw_query=query, text=text)

    @property
    def wants_json(self) -> bool:
        p = self.path.lower()
        if any(s in p for s in ("/api/", "/v1/", "/v2/", "/graphql", ".json")):
            return True
        if "json" in self.accept:
            return True
        return "text/html" not in self.accept


# ---------------------------------------------------------------------------
# Small HTML shell, so HTML responses look like one site
# ---------------------------------------------------------------------------

def _page(site: Site, title: str, inner: str) -> str:
    brand = html.escape(site.slug.capitalize())
    return (
        "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n"
        f"<title>{html.escape(title)} | {brand}</title>\n"
        "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
        "<style>body{font-family:Arial,Helvetica,sans-serif;margin:0;color:#222}"
        "header{background:#1f2d3d;color:#fff;padding:12px 24px}main{padding:24px}"
        "table{border-collapse:collapse}td,th{border:1px solid #ccc;padding:4px 8px;font-size:13px}"
        "</style>\n</head>\n<body>\n"
        f"<header><strong>{brand}</strong></header>\n<main>\n{inner}\n</main>\n</body>\n</html>\n"
    )


# ---------------------------------------------------------------------------
# Files (path traversal / sensitive file probes)
# ---------------------------------------------------------------------------

_SYSTEM_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin\n"
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin\n"
    "sync:x:4:65534:sync:/bin:/bin/sync\n"
    "games:x:5:60:games:/usr/games:/usr/sbin/nologin\n"
    "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin\n"
    "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin\n"
    "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin\n"
    "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin\n"
    "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin\n"
    "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
    "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin\n"
    "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin\n"
    "irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin\n"
    "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin\n"
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
    "systemd-network:x:100:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin\n"
    "systemd-resolve:x:101:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin\n"
    "syslog:x:102:106::/home/syslog:/usr/sbin/nologin\n"
    "messagebus:x:103:107::/nonexistent:/usr/sbin/nologin\n"
    "_apt:x:104:65534::/nonexistent:/usr/sbin/nologin\n"
    "mysql:x:105:111:MySQL Server,,,:/nonexistent:/bin/false\n"
)


def passwd(site: Site) -> str:
    lines = [f"{n}:x:{uid}:{uid}:{gecos}:{home}:{shell}" for n, uid, gecos, home, shell in site.os_accounts]
    return _SYSTEM_PASSWD + "\n".join(lines) + "\n"


def shadow(site: Site) -> str:
    out = []
    day = 19000 + site.rng("shadow").randint(300, 900)
    for line in _SYSTEM_PASSWD.splitlines():
        name = line.split(":", 1)[0]
        pw = "*" if name != "root" else "$6$" + _derive(site.key, site.host, "root-salt", ALNUM, 16) + "$" + _derive(site.key, site.host, "root-hash", ALNUM + "./", 86)
        out.append(f"{name}:{pw}:{day}:0:99999:7:::")
    for n, *_ in site.os_accounts:
        pw = "$6$" + _derive(site.key, site.host, f"salt-{n}", ALNUM, 16) + "$" + _derive(site.key, site.host, f"hash-{n}", ALNUM + "./", 86)
        out.append(f"{n}:{pw}:{day + 3}:0:99999:7:::")
    return "\n".join(out) + "\n"


def etc_hosts(site: Site) -> str:
    return (
        "127.0.0.1\tlocalhost\n"
        f"127.0.1.1\t{site.hostname}\n"
        f"{site.private_ip}\t{site.hostname}.internal {site.hostname}\n"
        f"{site.db_host}\tdb-01.internal db-01\n"
        f"{site.db_host.rsplit('.', 1)[0]}.{int(site.db_host.rsplit('.', 1)[1]) + 1}\tcache-01.internal cache-01\n\n"
        "# The following lines are desirable for IPv6 capable hosts\n"
        "::1     ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\n"
        "ff02::1 ip6-allnodes\nff02::2 ip6-allrouters\n"
    )


WIN_INI = "; for 16-bit app support\r\n[fonts]\r\n[extensions]\r\n[mci extensions]\r\n[files]\r\n[Mail]\r\nMAPI=1\r\n"


def dotenv(site: Site) -> str:
    t = site.tokens
    return (
        f"APP_NAME={site.slug.capitalize()}\nAPP_ENV=production\nAPP_KEY=base64:{t['app_key']}=\n"
        f"APP_DEBUG=false\nAPP_URL=https://{site.host or site.mail_domain}\n\n"
        "LOG_CHANNEL=stack\nLOG_LEVEL=warning\n\n"
        f"DB_CONNECTION=mysql\nDB_HOST={site.db_host}\nDB_PORT=3306\nDB_DATABASE={site.db_name}\n"
        f"DB_USERNAME={site.db_user}\nDB_PASSWORD={t['db_password']}\n\n"
        "CACHE_DRIVER=redis\nSESSION_DRIVER=redis\nQUEUE_CONNECTION=redis\n"
        f"REDIS_HOST={site.db_host.rsplit('.', 1)[0]}.{int(site.db_host.rsplit('.', 1)[1]) + 1}\nREDIS_PORT=6379\n\n"
        f"MAIL_MAILER=smtp\nMAIL_HOST=smtp.{site.mail_domain}\nMAIL_PORT=587\nMAIL_USERNAME=noreply@{site.mail_domain}\n\n"
        f"AWS_ACCESS_KEY_ID={t['aws_access_key_id']}\nAWS_SECRET_ACCESS_KEY={t['aws_secret_access_key']}\n"
        f"AWS_DEFAULT_REGION=ap-southeast-1\nAWS_BUCKET={site.slug}-prod-uploads\n\n"
        f"PAYMENT_API_KEY={t['api_key']}\n"
    )


def proc_environ(site: Site) -> str:
    env = [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        f"HOSTNAME={site.hostname}", "HOME=/var/www", "APP_ENV=production",
        f"DB_HOST={site.db_host}", f"DB_DATABASE={site.db_name}", f"DB_USERNAME={site.db_user}",
        f"DB_PASSWORD={site.tokens['db_password']}", "PHP_VERSION=8.2.24",
    ]
    return "\x00".join(env) + "\x00"


def wp_config(site: Site) -> str:
    names = ["AUTH_KEY", "SECURE_AUTH_KEY", "LOGGED_IN_KEY", "NONCE_KEY",
             "AUTH_SALT", "SECURE_AUTH_SALT", "LOGGED_IN_SALT", "NONCE_SALT"]
    salts = "\n".join(f"define( '{n}', '{s}' );" for n, s in zip(names, site.salts))
    return (
        "<?php\n/**\n * The base configuration for WordPress\n */\n\n"
        f"define( 'DB_NAME', '{site.db_name}' );\ndefine( 'DB_USER', '{site.db_user}' );\n"
        f"define( 'DB_PASSWORD', '{site.tokens['db_password']}' );\ndefine( 'DB_HOST', '{site.db_host}' );\n"
        "define( 'DB_CHARSET', 'utf8mb4' );\ndefine( 'DB_COLLATE', '' );\n\n"
        f"{salts}\n\n$table_prefix = 'wp_';\n\ndefine( 'WP_DEBUG', false );\n\n"
        "if ( ! defined( 'ABSPATH' ) ) {\n\tdefine( 'ABSPATH', __DIR__ . '/' );\n}\n\n"
        "require_once ABSPATH . 'wp-settings.php';\n"
    )


def git_config(site: Site) -> str:
    return (
        "[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
        f"[remote \"origin\"]\n\turl = ssh://git@git.internal:2222/web/{site.slug}.git\n"
        "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
        "[branch \"main\"]\n\tremote = origin\n\tmerge = refs/heads/main\n"
        f"[user]\n\tname = deploy\n\temail = deploy@{site.mail_domain}\n"
    )


def aws_credentials(site: Site) -> str:
    return (
        f"[default]\naws_access_key_id = {site.tokens['aws_access_key_id']}\n"
        f"aws_secret_access_key = {site.tokens['aws_secret_access_key']}\nregion = ap-southeast-1\n"
    )


def ssh_key(site: Site) -> str:
    raw = _derive(site.key, site.host, "ssh-key", ALNUM + "+/", 70 * 6)
    lines = [raw[i:i + 70] for i in range(0, len(raw), 70)]
    return "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n" \
        + "\n".join(lines) + "\n-----END OPENSSH PRIVATE KEY-----\n"


def sql_dump(site: Site) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    cols = _COLUMNS
    rows = ",\n".join(
        "(" + ",".join(str(u[c]) if c == "id" else "'" + str(u[c]) + "'" for c in cols) + ")" for u in site.users
    )
    return (
        f"-- MySQL dump 10.13  Distrib {site.mysql_version.split('-')[0]}, for Linux (x86_64)\n--\n"
        f"-- Host: {site.db_host}    Database: {site.db_name}\n"
        "-- ------------------------------------------------------\n"
        f"-- Server version\t{site.mysql_version}\n\n"
        "/*!40101 SET NAMES utf8mb4 */;\n/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;\n\n"
        "DROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (\n"
        "  `id` int unsigned NOT NULL AUTO_INCREMENT,\n  `username` varchar(64) NOT NULL,\n"
        "  `email` varchar(191) NOT NULL,\n  `password_hash` varchar(255) NOT NULL,\n"
        "  `role` varchar(32) NOT NULL DEFAULT 'user',\n  `created_at` datetime NOT NULL,\n"
        "  `last_login` datetime DEFAULT NULL,\n  PRIMARY KEY (`id`),\n  UNIQUE KEY `users_email_unique` (`email`)\n"
        f") ENGINE=InnoDB AUTO_INCREMENT={len(site.users) + 1} DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;\n\n"
        "LOCK TABLES `users` WRITE;\n"
        f"INSERT INTO `users` VALUES\n{rows};\nUNLOCK TABLES;\n\n"
        "DROP TABLE IF EXISTS `settings`;\nCREATE TABLE `settings` (\n  `name` varchar(64) NOT NULL,\n"
        "  `value` text,\n  PRIMARY KEY (`name`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n\n"
        "LOCK TABLES `settings` WRITE;\nINSERT INTO `settings` VALUES "
        f"('smtp_host','smtp.{site.mail_domain}'),('payment_api_key','{site.tokens['api_key']}'),"
        "('maintenance','0');\nUNLOCK TABLES;\n\n"
        f"-- Dump completed on {now}\n"
    )


def config_php(site: Site) -> str:
    return (
        "<?php\nreturn [\n"
        f"    'db' => [\n        'host' => '{site.db_host}',\n        'name' => '{site.db_name}',\n"
        f"        'user' => '{site.db_user}',\n        'pass' => '{site.tokens['db_password']}',\n    ],\n"
        f"    'admin_email' => '{site.admin_user}@{site.mail_domain}',\n"
        f"    'api_key' => '{site.tokens['api_key']}',\n];\n"
    )


# (variant, regex over the decoded, lowercased target) -- first match wins
_FILE_VARIANTS: List[Tuple[str, "re.Pattern[str]"]] = [
    ("shadow", re.compile(r"shadow")),
    ("passwd", re.compile(r"passwd")),
    ("hosts", re.compile(r"etc[/\\]hosts\b")),
    ("win_ini", re.compile(r"(?:win|boot|system)\.ini")),
    ("environ", re.compile(r"proc[/\\]\w+[/\\]environ")),
    ("dotenv", re.compile(r"(?:^|[/\\=])\.env(?:\.[a-z]+)?(?:$|[?&#\s])")),
    ("wp_config", re.compile(r"wp-config")),
    ("git_head", re.compile(r"\.git[/\\]head\b")),
    ("git_config", re.compile(r"\.git(?:[/\\]|$)")),
    ("aws_credentials", re.compile(r"\.aws[/\\]credentials|/credentials$")),
    ("ssh_key", re.compile(r"id_(?:rsa|ed25519|ecdsa)\b|\.ssh[/\\]")),
    ("sql_dump", re.compile(r"\.sql(?:\.gz|\.zip|\.bak)?(?:$|[?&#\s])|backup|dump|db[-_]?bak")),
    ("config_php", re.compile(r"config(?:uration)?\.(?:php|inc)|php://filter")),
]


def file_variant(target: str) -> Optional[str]:
    t = target.lower()
    for name, rx in _FILE_VARIANTS:
        if rx.search(t):
            return name
    return None


def render_file(site: Site, variant: str, ctx: Ctx) -> Tuple[str, str, Dict[str, str]]:
    extra: Dict[str, str] = {}
    if variant == "shadow":
        return "text/plain", shadow(site), extra
    if variant == "hosts":
        return "text/plain", etc_hosts(site), extra
    if variant == "win_ini":
        return "text/plain", WIN_INI, extra
    if variant == "environ":
        return "text/plain", proc_environ(site), extra
    if variant == "dotenv":
        return "text/plain", dotenv(site), extra
    if variant == "wp_config":
        # Requested directly, a .php file is executed and prints nothing; a
        # backup copy (wp-config.php.bak, ~, .save) is what leaks source.
        if re.search(r"wp-config\.php$", ctx.path.lower()) and not ctx.raw_query:
            return "text/html; charset=UTF-8", "", extra
        return "text/plain", wp_config(site), extra
    if variant == "git_head":
        return "text/plain", "ref: refs/heads/main\n", extra
    if variant == "git_config":
        return "text/plain", git_config(site), extra
    if variant == "aws_credentials":
        return "text/plain", aws_credentials(site), extra
    if variant == "ssh_key":
        return "text/plain", ssh_key(site), extra
    if variant == "sql_dump":
        name = f"{site.db_name}_{datetime.now(timezone.utc):%Y%m%d}.sql"
        extra["Content-Disposition"] = f'attachment; filename="{name}"'
        return "application/octet-stream", sql_dump(site), extra
    if variant == "config_php":
        src = config_php(site)
        if "base64-encode" in ctx.text.lower():
            return "text/html; charset=UTF-8", base64.b64encode(src.encode()).decode(), extra
        return "text/plain", src, extra
    return "text/plain", passwd(site), extra


# ---------------------------------------------------------------------------
# SQL injection emulation (MySQL flavoured)
# ---------------------------------------------------------------------------

_SLEEP = re.compile(r"(?i)\b(?:sleep|pg_sleep)\s*\(\s*(\d{1,3}(?:\.\d+)?)\s*\)")
_WAITFOR = re.compile(r"(?i)\bwaitfor\s+delay\s+['\"](\d{1,2}):(\d{1,2}):(\d{1,2})['\"]")
_BENCH = re.compile(r"(?i)\bbenchmark\s*\(\s*(\d{1,12})\s*,")
_NUM_CMP = re.compile(r"(?<![\w.])(-?\d{1,12})\s*(=|<>|!=|>=|<=|>|<)\s*(-?\d{1,12})(?![\w.])")
_STR_CMP = re.compile(r"'([^']{0,40})'\s*(=|<>|!=)\s*'([^']{0,40})'")
_UNION = re.compile(r"(?i)\bunion(?:\s+all|\s+distinct)?\s+select\s+(.{1,800}?)(?=\s+from\b|\s*--|\s*#|;|$)")
_ORDER_BY = re.compile(r"(?i)\border\s+by\s+(\d{1,3})\b")
_SCHEMA = re.compile(r"(?i)information_schema|\bschema_name\b|\btable_name\b|\bpg_tables\b|\bsys\.tables\b|\bshow\s+tables\b")
_ERROR_FN = re.compile(r"(?i)\b(?:extractvalue|updatexml)\s*\(")


def _cmp(a, op, b) -> bool:
    return {"=": a == b, "<>": a != b, "!=": a != b, ">": a > b, "<": a < b, ">=": a >= b, "<=": a <= b}[op]


def conditions_hold(text: str) -> bool:
    """False when the payload carries an obviously false comparison (1=2,
    'a'='b'): the blind-SQLi 'false' probe. Everything else is true."""
    for a, op, b in _NUM_CMP.findall(text):
        if not _cmp(int(a), op, int(b)):
            return False
    for a, op, b in _STR_CMP.findall(text):
        if op in ("=",) and a != b or op in ("<>", "!=") and a == b:
            return False
    return True


def sql_delay(text: str) -> float:
    m = _SLEEP.search(text)
    if m:
        seconds = float(m.group(1))
    else:
        m = _WAITFOR.search(text)
        if m:
            seconds = int(m.group(1)) * 3600 + int(m.group(2)) * 60 + int(m.group(3))
        else:
            m = _BENCH.search(text)
            seconds = int(m.group(1)) / 5_000_000 if m else 0.0
    if seconds <= 0 or not conditions_hold(text):
        return 0.0
    return min(seconds, MAX_DELAY_SECONDS)


def _split_top(expr: str) -> List[str]:
    parts, depth, quote, cur = [], 0, "", []
    for ch in expr:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = ""
            continue
        if ch in "'\"":
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
        elif ch == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
            continue
        cur.append(ch)
    parts.append("".join(cur).strip())
    return [p for p in parts if p != ""]


def _eval_sql(site: Site, expr: str, depth: int = 0) -> Optional[str]:
    e = expr.strip()
    low = e.lower()
    if depth > 3 or not e:
        return None
    if low == "null":
        return None
    m = re.fullmatch(r"0x([0-9a-f]{2,400})", low)
    if m and len(m.group(1)) % 2 == 0:
        raw = bytes.fromhex(m.group(1))
        return raw.decode("latin-1") if all(32 <= b < 127 for b in raw) else ""
    m = re.fullmatch(r"(['\"])(.{0,200})\1", e)
    if m:
        return m.group(2)
    if re.fullmatch(r"-?\d{1,12}", e):
        return e
    if re.fullmatch(r"(?:database|schema)\(\s*\)", low):
        return site.db_name
    if re.fullmatch(r"(?:version\(\s*\)|@@version)", low):
        return site.mysql_version
    if re.fullmatch(r"(?:(?:current_|session_|system_)?user\(\s*\))", low):
        return f"{site.db_user}@{site.private_ip}"
    if re.fullmatch(r"@@hostname", low):
        return site.hostname
    m = re.fullmatch(r"(?i)(concat|concat_ws)\s*\((.*)\)", e, flags=re.S)
    if m:
        args = [_eval_sql(site, a, depth + 1) for a in _split_top(m.group(2))]
        if m.group(1).lower() == "concat_ws":
            sep, rest = (args[0] or ""), args[1:]
            return sep.join(a for a in rest if a is not None)
        return None if any(a is None for a in args) else "".join(args)
    m = re.fullmatch(r"(?i)(?:ifnull|coalesce)\s*\((.*)\)", e, flags=re.S)
    if m:
        for a in _split_top(m.group(1)):
            v = _eval_sql(site, a, depth + 1)
            if v is not None:
                return v
        return None
    m = re.fullmatch(r"(?i)cast\s*\((.*)\s+as\s+\w+(?:\(\d+\))?\s*\)", e, flags=re.S)
    if m:
        return _eval_sql(site, m.group(1), depth + 1)
    return None


def _mysql_error(near: str) -> str:
    near = re.sub(r"[^\x20-\x7e]", "", near)[:80]
    return ("You have an error in your SQL syntax; check the manual that corresponds to your "
            f"MySQL server version for the right syntax to use near '{near}' at line 1")


def _quote_unbalanced(text: str) -> bool:
    body = re.split(r"--\s|#|--$", text, maxsplit=1)
    if len(body) > 1:
        return False
    return text.count("'") % 2 == 1 or text.count('"') % 2 == 1


def render_sql(site: Site, ctx: Ctx) -> Tuple[str, str, Dict[str, str]]:
    text = ctx.text
    cols = site.columns
    error: Optional[str] = None
    rows: List[Dict[str, object]] = [{c: u[c] for c in cols} for u in site.users]

    m = _ERROR_FN.search(text)
    if m:
        inner = text[m.end():m.end() + 400]
        cm = re.search(r"(?i)concat\s*\(.*?\)", inner, flags=re.S)
        leak = _eval_sql(site, cm.group(0)) if cm else None
        error = f"XPATH syntax error: '{(leak or '~' + site.db_name)[:31]}'"
    if error is None:
        om = _ORDER_BY.search(text)
        if om and int(om.group(1)) > len(cols):
            error = f"Unknown column '{om.group(1)}' in 'order clause'"
    um = _UNION.search(text) if error is None else None
    if um:
        items = _split_top(um.group(1))
        if len(items) != len(cols):
            error = "The used SELECT statements have a different number of columns"
        elif _SCHEMA.search(text):
            rows = [{c: None for c in cols} for _ in _TABLES]
            for r, t in zip(rows, _TABLES):
                r[cols[1]] = t
                r[cols[2]] = site.db_name
        else:
            rows.append({c: _eval_sql(site, it) for c, it in zip(cols, items)})
    if error is None and not um and _quote_unbalanced(text):
        snippet = text.strip().split("'", 1)[-1]
        error = _mysql_error("'" + snippet)
    if error is None and not conditions_hold(text):
        rows = []

    if ctx.wants_json:
        if error:
            body = json.dumps({"status": "error", "error": f"SQLSTATE[42000]: Syntax error or access violation: 1064 {error}"
                               if error.startswith("You have") else f"SQLSTATE[HY000]: General error: {error}"}, indent=2)
        else:
            body = json.dumps({"status": "success", "count": len(rows), "data": rows}, indent=2, default=str)
        return "application/json", body, {}
    if error:
        inner = f"<h2>Database error</h2>\n<p>{html.escape(error)}</p>"
    else:
        head = "".join(f"<th>{html.escape(c)}</th>" for c in cols)
        body_rows = "".join(
            "<tr>" + "".join(f"<td>{html.escape('' if r.get(c) is None else str(r.get(c)))}</td>" for c in cols) + "</tr>"
            for r in rows
        )
        inner = f"<h2>Results</h2>\n<p>{len(rows)} record(s)</p>\n<table><tr>{head}</tr>{body_rows}</table>"
    return "text/html; charset=UTF-8", _page(site, "Search", inner), {}


def schema_dump(site: Site) -> str:
    """Kept for the template catalogue preview: what a schema-enumeration
    union returns for this site."""
    return json.dumps({
        "status": "success",
        "count": len(_TABLES),
        "data": [{"table_schema": site.db_name, "table_name": t} for t in _TABLES],
    }, indent=2)


# ---------------------------------------------------------------------------
# Command injection
# ---------------------------------------------------------------------------

_CMD = re.compile(
    r"(?:[;&|`\n]|\$\()\s*(id|whoami|uname|hostname|pwd|ls|cat|echo|env|printenv|ifconfig|ip|ps|"
    r"ping|nslookup|dig|curl|wget|nc|ncat|bash|sh|python3?|perl|which|w|uptime|head|tail)\b(?!\s*=)([^;&|`)\n]{0,120})"
)


def _safe_word(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.:/-]", "", s)[:64]


def render_command(site: Site, ctx: Ctx) -> Tuple[str, str, Dict[str, str]]:
    out: List[str] = []
    for cmd, arg in _CMD.findall(ctx.text)[:4]:
        arg = arg.strip()
        if cmd == "id":
            out.append("uid=33(www-data) gid=33(www-data) groups=33(www-data)")
        elif cmd == "whoami":
            out.append("www-data")
        elif cmd == "uname":
            out.append(f"Linux {site.hostname} {site.kernel} #{site.rng('k').randint(100, 160)}-Ubuntu SMP "
                       "x86_64 x86_64 x86_64 GNU/Linux" if "-a" in arg else "Linux")
        elif cmd == "hostname":
            out.append(site.hostname)
        elif cmd == "pwd":
            out.append("/var/www/html")
        elif cmd == "ls":
            out.append("assets\nconfig\nindex.php\nuploads\nvendor\n.env\n.htaccess" if "-a" in arg
                       else "assets\nconfig\nindex.php\nuploads\nvendor")
        elif cmd in ("cat", "head", "tail"):
            variant = file_variant(arg) if arg else None
            if variant:
                out.append(render_file(site, variant, ctx)[1].rstrip("\n"))
            else:
                out.append(f"{cmd}: {_safe_word(arg) or '-'}: No such file or directory")
        elif cmd == "echo":
            out.append(_safe_word(arg.strip("'\"")))
        elif cmd in ("env", "printenv"):
            out.append(proc_environ(site).replace("\x00", "\n").rstrip())
        elif cmd in ("ifconfig", "ip"):
            out.append(f"eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 9001\n"
                       f"        inet {site.private_ip}  netmask 255.255.255.0  broadcast {site.private_ip.rsplit('.', 1)[0]}.255")
        elif cmd == "ps":
            out.append("  PID TTY          TIME CMD\n    1 ?        00:00:12 php-fpm8.2\n   27 ?        00:03:41 php-fpm8.2\n"
                       f" {site.rng('ps').randint(3000, 9000)} ?        00:00:00 sh")
        elif cmd in ("uptime", "w"):
            out.append(f" 09:{site.rng('up').randint(10, 59)}:07 up {site.rng('up2').randint(20, 190)} days,  0 users,  load average: 0.21, 0.18, 0.15")
        elif cmd == "which":
            out.append(f"/usr/bin/{_safe_word(arg)}" if arg else "")
        # ping / nslookup / dig / curl / wget / nc / shells: blind, print nothing
    body = "\n".join(o for o in out if o) + ("\n" if out else "")
    if ctx.wants_json:
        return "application/json", json.dumps({"status": "ok", "output": body}), {}
    return "text/html; charset=UTF-8", _page(site, "Tools", f"<pre>{html.escape(body)}</pre>"), {}


# ---------------------------------------------------------------------------
# SSRF (cloud metadata)
# ---------------------------------------------------------------------------

_URL_IN = re.compile(r"(?i)\b(?:https?|gopher|dict)://([^/\s&\"'<>]{1,255})(/[^\s&\"'<>]{0,300})?")
_METADATA_HOSTS = ("169.254.169.254", "metadata.google.internal", "100.100.100.200", "[fd00:ec2::254]", "fd00:ec2::254")
_INTERNAL_HOST = re.compile(r"(?i)^(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|"
                            r"172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|\[?::1\]?|[a-z0-9-]+\.internal|[a-z0-9-]+\.local)(?::\d+)?$")


def ssrf_target(text: str) -> Optional[Tuple[str, str]]:
    for host, path in _URL_IN.findall(text):
        h = host.lower()
        if h.split(":")[0] in _METADATA_HOSTS or h in _METADATA_HOSTS or _INTERNAL_HOST.match(h):
            return h, path or "/"
    return None


def render_ssrf(site: Site, ctx: Ctx) -> Tuple[str, str, Dict[str, str]]:
    target = ssrf_target(ctx.text) or ("", "/")
    host, path = target
    if host.split(":")[0] not in _METADATA_HOSTS:
        return "text/html", (
            "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n</head>\n<body>\n"
            "<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\n"
            "working. Further configuration is required.</p>\n</body>\n</html>\n"
        ), {}
    role = f"{site.slug}-ec2-role"
    p = path.rstrip("/")
    rng = site.rng("imds")
    instance = "i-0" + "".join(rng.choice(_HEX) for _ in range(16))
    if p.endswith("iam/security-credentials"):
        return "text/plain", role, {}
    if "/iam/security-credentials/" in p:
        now = datetime.now(timezone.utc)
        token = _derive(site.key, site.host, "sts-token", ALNUM + "+/", 356)
        return "text/plain", json.dumps({
            "Code": "Success",
            "LastUpdated": (now - timedelta(minutes=rng.randint(5, 50))).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "Type": "AWS-HMAC",
            "AccessKeyId": site.tokens["aws_session_key_id"],
            "SecretAccessKey": site.tokens["aws_secret_access_key"],
            "Token": token,
            "Expiration": (now + timedelta(hours=6)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        }, indent=2), {}
    leaf = p.rsplit("/", 1)[-1]
    simple = {
        "instance-id": instance,
        "ami-id": "ami-0" + "".join(rng.choice(_HEX) for _ in range(16)),
        "instance-type": rng.choice(["t3.medium", "t3.large", "m5.large"]),
        "local-ipv4": site.private_ip,
        "local-hostname": f"ip-{site.private_ip.replace('.', '-')}.ap-southeast-1.compute.internal",
        "hostname": f"ip-{site.private_ip.replace('.', '-')}.ap-southeast-1.compute.internal",
        "region": "ap-southeast-1",
        "availability-zone": "ap-southeast-1" + rng.choice("abc"),
    }
    if leaf in simple:
        return "text/plain", simple[leaf], {}
    if p.endswith("/latest") or p in ("", "/"):
        return "text/plain", "dynamic\nmeta-data\nuser-data", {}
    return "text/plain", (
        "ami-id\nami-launch-index\nhostname\niam/\ninstance-id\ninstance-type\nlocal-hostname\n"
        "local-ipv4\nmac\nnetwork/\nplacement/\nsecurity-groups"
    ), {}


# ---------------------------------------------------------------------------
# XSS, admin panels, honeytoken replay
# ---------------------------------------------------------------------------

XSS_REGEX = re.compile(
    r"(?i)<\s*script\b|<\s*(?:img|svg|iframe|body|video|audio|details|input)\b[^>]{0,200}\bon[a-z]{3,20}\s*=|"
    r"javascript\s*:|\bon(?:error|load|mouseover|focus|toggle|begin)\s*=|<\s*svg\b"
)


def render_xss(site: Site, ctx: Ctx) -> Tuple[str, str, Dict[str, str]]:
    # The payload is reflected escaped. Reflecting it raw would turn the
    # honeypot into a real XSS on the customer's domain.
    q = ctx.text.strip()[:200]
    inner = (f"<h2>Search results for &ldquo;{html.escape(q)}&rdquo;</h2>\n"
             "<p>No results found. Try different keywords.</p>")
    return "text/html; charset=UTF-8", _page(site, "Search", inner), {}


ADMIN_PATH = re.compile(
    r"(?i)^/(?:wp-login\.php|wp-admin|admin(?:istrator)?|phpmyadmin|pma|manager/html|user/login|"
    r"login|signin|cpanel|backend|cms)(?:[/?.]|$)"
)


def render_admin(site: Site, ctx: Ctx, logged_in: bool = False) -> Tuple[str, str, Dict[str, str]]:
    wp = "wp-" in ctx.path.lower()
    if logged_in or ctx.method == "POST":
        users = len(site.users)
        rng = site.rng("dash")
        inner = (
            f"<h2>Dashboard</h2>\n<p>Welcome back, {html.escape(site.admin_user)}.</p>\n"
            f"<table><tr><th>Users</th><th>Orders (30d)</th><th>Revenue (30d)</th><th>Pending reviews</th></tr>"
            f"<tr><td>{users * rng.randint(180, 900)}</td><td>{rng.randint(300, 4000)}</td>"
            f"<td>{rng.randint(80, 900)},{rng.randint(100, 999)} THB</td><td>{rng.randint(0, 30)}</td></tr></table>\n"
            "<p><a href=\"?page=users\">Users</a> · <a href=\"?page=settings\">Settings</a> · "
            "<a href=\"?page=backup\">Backup</a></p>"
        )
        return "text/html; charset=UTF-8", _page(site, "Dashboard", inner), {}
    action = "wp-login.php" if wp else "login"
    user_field = "log" if wp else "username"
    pass_field = "pwd" if wp else "password"
    inner = (
        f"<h2>{'Log In' if wp else 'Administrator login'}</h2>\n"
        f"<form method=\"post\" action=\"{action}\">\n"
        f"<p><label>Username<br><input type=\"text\" name=\"{user_field}\" autocomplete=\"username\"></label></p>\n"
        f"<p><label>Password<br><input type=\"password\" name=\"{pass_field}\" autocomplete=\"current-password\"></label></p>\n"
        "<p><button type=\"submit\">Log In</button></p>\n</form>"
    )
    return "text/html; charset=UTF-8", _page(site, "Log In", inner), {}


def find_honeytoken(site: Site, corpus: str) -> Optional[str]:
    for kind, value in site.tokens.items():
        if value and value in corpus:
            return kind
    return None


def honeytoken_rule(hosts: List[str]) -> str:
    """ModSecurity rule that hands any request carrying a honeytoken from
    any listed site to the deception layer (status 418, like DECEIVE)."""
    head = "# Generated by services/managed_ruleset.py -- do not edit. Honeytokens served by the deception layer.\n"
    values = sorted({v for h in hosts if normalize_host(h) for v in honeytoken_values(site_for(h))})
    if not values:
        return head
    return head + (
        "SecRule ARGS|ARGS_NAMES|REQUEST_URI|REQUEST_HEADERS|REQUEST_BODY "
        f"\"@pm {' '.join(values)}\" "
        f"\"id:{HONEYTOKEN_RULE_ID},phase:2,deny,status:418,log,t:none,severity:'CRITICAL',"
        "msg:'Honeytoken replay',tag:'action:deceive',tag:'honeytoken'\"\n"
    )
