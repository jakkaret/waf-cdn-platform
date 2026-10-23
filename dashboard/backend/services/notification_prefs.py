"""Who is told what, per person and site (migration 0014).

Kinds of Telegram message and their defaults by role on the site:

    kind      owner  editor  viewer  support*
    attacks   on     on      on      on       attack incidents (start, end)
    outages   on     on      off     on       site unreachable / back
    certs     on     on      off     on       HTTPS certificate expiring
    team      on     -       -       -        someone else changed the site
    digest    off    off     off     off      daily summary at 08:00

    * Support = a platform admin who is not on the site's team, and only
      where it may see the site at all (unattributed traffic, support grant).

A row in notification_prefs overrides a default; NULL keeps it. Sensitivity
is per site (origin_alert_settings), so everyone on a site sees the same
incidents in the Alert Center.
"""
from typing import Any, Dict, List, Optional

from db import pool

KINDS = ("attacks", "outages", "certs", "team", "digest")
DEFAULTS = {
    "owner":   {"attacks": True, "outages": True,  "certs": True,  "team": True,  "digest": False},
    "editor":  {"attacks": True, "outages": True,  "certs": True,  "team": False, "digest": False},
    "viewer":  {"attacks": True, "outages": False, "certs": False, "team": False, "digest": False},
    "support": {"attacks": True, "outages": True,  "certs": True,  "team": False, "digest": False},
}
# Only the owner can be told of team changes; nobody else can turn it on.
CHANGEABLE = {
    "owner": set(KINDS),
    "editor": {"attacks", "outages", "certs", "digest"},
    "viewer": {"attacks", "outages", "certs", "digest"},
}

# Blocks in 5 minutes for the whole site / for one IP before an incident opens.
SENSITIVITY = {"low": (200, 100), "medium": (50, 30), "high": (20, 10)}
DEFAULT_SENSITIVITY = "medium"


def role_on(origin: Dict[str, Any], user_id: str) -> Optional[str]:
    if not origin or not user_id:
        return None
    if str(origin.get("admin_user_id") or "") == str(user_id):
        return "owner"
    if str(user_id) in {str(u) for u in origin.get("editor_user_ids") or []}:
        return "editor"
    if str(user_id) in {str(u) for u in origin.get("viewer_user_ids") or []}:
        return "viewer"
    return None


def _rows(origin_id: Optional[str]) -> Dict[str, Dict[str, Any]]:
    if not origin_id:
        return {}
    return {str(r["user_id"]): r for r in pool.q("SELECT * FROM notification_prefs WHERE origin_id = %s::uuid",
                                                 (origin_id,))}


def effective(role: str, row: Optional[Dict[str, Any]]) -> Dict[str, bool]:
    base = dict(DEFAULTS[role])
    for k in CHANGEABLE.get(role, ()):
        if row and row.get(k) is not None:
            base[k] = bool(row[k])
    return base


def filter_users(users: List[Dict[str, Any]], origin: Dict[str, Any], kind: str) -> List[Dict[str, Any]]:
    """Of the users allowed to see this site's alert, those who want `kind`."""
    origin_id = str(origin.get("id") or origin.get("origin_id") or "") or None
    rows = _rows(origin_id)
    out = []
    for u in users:
        role = role_on(origin, u.get("user_id")) or ("support" if u.get("role") == "admin" else None)
        if role and effective(role, rows.get(str(u.get("user_id"))))[kind]:
            out.append(u)
    return out


def sensitivities(origin_ids: List[str]) -> Dict[str, str]:
    ids = [o for o in origin_ids if o]
    if not ids:
        return {}
    return {str(r["origin_id"]): r["sensitivity"] for r in pool.q(
        "SELECT origin_id, sensitivity FROM origin_alert_settings WHERE origin_id = ANY(%s::uuid[])", (ids,))}


def thresholds(sensitivity: Optional[str]) -> tuple:
    return SENSITIVITY.get(sensitivity or DEFAULT_SENSITIVITY, SENSITIVITY[DEFAULT_SENSITIVITY])


def set_sensitivity(origin_id: str, sensitivity: str, user_id: str) -> None:
    if sensitivity not in SENSITIVITY:
        raise ValueError("unknown sensitivity")
    pool.exec_("INSERT INTO origin_alert_settings (origin_id, sensitivity, updated_by) VALUES (%s, %s, %s) "
               "ON CONFLICT (origin_id) DO UPDATE SET sensitivity = EXCLUDED.sensitivity, "
               "updated_by = EXCLUDED.updated_by, updated_at = now()", (origin_id, sensitivity, user_id))


def set_prefs(user_id: str, origin_id: str, role: str, changes: Dict[str, bool]) -> Dict[str, bool]:
    """Store what this role may change; other keys are ignored."""
    allowed = {k: bool(v) for k, v in changes.items() if k in CHANGEABLE.get(role, ()) and v is not None}
    if allowed:
        cols = ", ".join(allowed)
        marks = ", ".join(["%s"] * len(allowed))
        updates = ", ".join(f"{k} = EXCLUDED.{k}" for k in allowed)
        pool.exec_(f"INSERT INTO notification_prefs (user_id, origin_id, {cols}) VALUES (%s, %s, {marks}) "
                   f"ON CONFLICT (user_id, origin_id) DO UPDATE SET {updates}, updated_at = now()",
                   (user_id, origin_id, *allowed.values()))
    return effective(role, _rows(origin_id).get(str(user_id)))
