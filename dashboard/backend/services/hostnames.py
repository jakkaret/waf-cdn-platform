"""One canonical form for a hostname, used wherever the system takes one in
(P3.3, N5/H67/H68 of security audit run 1).

Spellings of the same name ("Shop.Example.COM.", " shop.example.com") used
to pass the ownership checks differently on different paths, and some paths
(the tunnel config generator, FRP auto-sync) took any string at all. Every
entry point now goes through canonical_host(): lowercase, no surrounding
space, no trailing dot, IDNA (punycode) for non-ASCII names, and the shape
of a DNS hostname. The database refuses anything else (migration 0007).
"""
import re

_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
HOSTNAME_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")

INVALID_MESSAGE = (
    "domain_name must be a valid hostname: labels of letters, digits, "
    "and hyphens (a label may not start or end with a hyphen), each "
    "label at most 63 characters, with at least two labels (e.g. "
    "'example.com'), and at most 253 characters total."
)


def canonical_host(value) -> str:
    """The canonical form of `value`, or ValueError when it is not a hostname."""
    text = str(value or "").strip().lower()
    if text.endswith("."):
        text = text[:-1]
    if text and not text.isascii():
        try:
            text = text.encode("idna").decode("ascii")
        except UnicodeError:
            raise ValueError(INVALID_MESSAGE) from None
    if len(text) > 253 or not HOSTNAME_RE.match(text):
        raise ValueError(INVALID_MESSAGE)
    return text


def canonical_or_none(value):
    try:
        return canonical_host(value)
    except ValueError:
        return None
