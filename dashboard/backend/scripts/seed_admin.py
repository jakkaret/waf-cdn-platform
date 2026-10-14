"""Create (or promote) an account directly in the PostgreSQL store.

Self-registration never grants admin (api/auth.py), so the first admin after
a database reset is created here by an operator on the server.

    # owner account; a random password is written to a root-only file
    DATA_BACKEND=postgres python scripts/seed_admin.py \
        --email owner@example.com --username owner --role admin \
        --generate-password /root/.waf-secrets/owner_login_password

    # accounts from an env file of `export PREFIX_EMAIL=...` / `PREFIX_PASSWORD=...`
    DATA_BACKEND=postgres python scripts/seed_admin.py \
        --from-env /root/t_creds.env --prefix ADMIN --role admin

Idempotent: an existing account keeps its password; only its role is set.
Passwords are never printed.
"""
from __future__ import annotations

import argparse
import os
import secrets
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def _read_env_file(path: str) -> dict:
    values = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, sep, value = line.partition("=")
        if sep:
            parts = shlex.split(value) if value else [""]
            values[key.strip()] = parts[0] if parts else ""
    return values


def _write_secret(path: str, value: str) -> None:
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(value + "\n")
    os.chmod(target, 0o600)


def seed(email: str, username: str, role: str, password: str | None) -> str:
    from services.auth_service import AuthService

    auth = AuthService()
    if getattr(auth, "backend", "") != "postgres":
        sys.exit("DATA_BACKEND=postgres is required")
    existing = auth.get_user_by_email(email)
    if existing:
        if existing.get("role") != role:
            auth.update_user_role(existing["user_id"], role)
            return f"exists, role set to {role}: {email}"
        return f"exists, unchanged ({role}): {email}"
    if not password:
        sys.exit(f"no password for new account {email}")
    auth.create_user(email=email, username=username, password=password, role=role)
    return f"created ({role}): {email}"


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--email")
    p.add_argument("--username")
    p.add_argument("--role", choices=["admin", "viewer"], default="viewer")
    p.add_argument("--password-file", help="read the password from this file")
    p.add_argument("--generate-password", metavar="PATH",
                   help="new account only: write a random password to PATH (0600)")
    p.add_argument("--from-env", help="env file with PREFIX_EMAIL / PREFIX_PASSWORD")
    p.add_argument("--prefix", help="variable prefix in --from-env (e.g. ADMIN)")
    args = p.parse_args(argv)

    password = None
    email = args.email
    if args.from_env:
        if not args.prefix:
            p.error("--from-env needs --prefix")
        env = _read_env_file(args.from_env)
        email = env.get(f"{args.prefix}_EMAIL")
        password = env.get(f"{args.prefix}_PASSWORD")
        if not email:
            p.error(f"{args.prefix}_EMAIL not found in {args.from_env}")
    if not email:
        p.error("--email or --from-env is required")
    if args.password_file:
        password = Path(args.password_file).read_text().strip()

    from services.auth_service import AuthService
    if args.generate_password and not AuthService().get_user_by_email(email):
        password = secrets.token_urlsafe(18)
        _write_secret(args.generate_password, password)

    username = args.username or email.split("@", 1)[0]
    print(seed(email, username, args.role, password))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
