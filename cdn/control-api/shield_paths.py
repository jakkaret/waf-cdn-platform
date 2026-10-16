"""One place that decides whether a request path is one the shield protects.

C2/H85/H86 (security audit run 1): the gates compared the raw path with the
configured patterns character by character, so other spellings of a
protected URL reached the origin without a challenge: "/LOGIN" or
"/Login" on a case-insensitive origin, "/%6cogin", "//login",
"/static/../login", "/login;jsessionid=x". Every spelling is reduced here to
the form the origin most likely resolves it to before matching, and the
match ignores case.
"""
import fnmatch
import re
from urllib.parse import unquote

_MAX_DECODE_ROUNDS = 3
_PARAMS_RE = re.compile(r";[^/]*")


def normalize_path(raw_uri: str) -> str:
    """Path part of a request URI, percent-decoded (repeatedly, so double
    encoding is undone too), backslashes as slashes, repeated slashes merged,
    "." and ".." segments resolved, lowercased."""
    path = str(raw_uri or "/")
    # Split by hand: urlsplit() would read "//login" as a host name.
    path = path.split("#", 1)[0].split("?", 1)[0]
    for _ in range(_MAX_DECODE_ROUNDS):
        decoded = unquote(path)
        if decoded == path:
            break
        path = decoded
    path = path.replace("\\", "/").replace("\x00", "")
    segments: list = []
    parts = path.split("/")
    for index, segment in enumerate(parts):
        last = index == len(parts) - 1
        if segment == "..":
            if segments:
                segments.pop()
        elif segment in ("", "."):
            # Keep a trailing slash ("/admin/") but no empty segments in between.
            if last and segments:
                segments.append("")
        else:
            segments.append(segment)
    return ("/" + "/".join(segments)).lower()


def path_candidates(raw_uri: str) -> set:
    """The normalized path, and the same path without ";param" segment
    parameters (a Java origin serves "/login;jsessionid=1" as "/login")."""
    path = normalize_path(raw_uri)
    return {path, _PARAMS_RE.sub("", path) or "/"}


def _matches(path: str, patterns) -> bool:
    return any(fnmatch.fnmatchcase(path, str(pattern).strip().lower()) for pattern in patterns or [])


def is_protected(raw_uri: str, login_paths, exclude_paths=None) -> bool:
    """True when any spelling of the path matches a protected pattern and is
    not excluded."""
    return any(
        _matches(path, login_paths) and not _matches(path, exclude_paths)
        for path in path_candidates(raw_uri)
    )
