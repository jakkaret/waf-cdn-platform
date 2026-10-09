"""
Canonical request form for Gen 3 feature extraction (training and serving).

The model should judge what a request says, not how the client happened to
encode it. Local testing with GoTestWAF, sqlmap and Nuclei (29/09/2026,
ml/security_test/RESULTS_20260929.md) showed three encoding artefacts deciding
scores:

- The same SQLi scored 0.99 as a form body but 0.22 as JSON and 0.34 as
  multipart, although the libinjection detector fired in all three: the JSON /
  multipart syntax characters moved the structural features, and in the training
  data JSON bodies are mostly benign (a dataset fingerprint).
- A Base64-wrapped SQLi scored 0.001: no detector could see it.
- Plain benign text scored near the threshold partly because "%20" counted as an
  encoded byte.

canonical_request() therefore rewrites a request, like a WAF's transformation
pipeline, before any feature is computed:

1. Query and form body: decode one URL-encoding layer, then re-escape only the
   characters that delimit pairs ("%", "&", "=", "+", "#") and spaces as "+".
   Double encoding (%2527) survives as %2527; single encoding of ordinary
   characters (%20, %27, %53%45%4C...) is undone, so the content is visible.
2. JSON and multipart/form-data bodies become form bodies ("k=v&k=v") of their
   scalar leaves / fields; binary file parts are dropped (their field name kept).
3. A value that looks like Base64 is replaced by its decoding only when the
   decoded text is printable and trips a detector (ml/value_features.unit_hits),
   so tokens, JWTs and IDs stay untouched.

Everything else (method, other body types) passes through unchanged. The
function must stay deterministic and cheap: it runs on every request.

The three encoding features (encoded_char_ratio, double_encoded_count,
encoded_attack_token_count) are the exception: they describe HOW the client
encoded the request, so canonical_features() takes them from the raw request,
with "%20" ignored. Encoding ordinary characters can hide a payload (and CSIC's
parameter-tampering attacks lean on it: CSIC-only recall 60.5% with it, 56.0%
without); encoding a space is what every client does.
"""

import base64
import binascii
import json
import re
from urllib.parse import parse_qsl, unquote_plus

from ml.feature_engineering import ENCODED_ATTACK_TOKEN_PATTERN, ENCODED_BYTE_PATTERN, extract_features_from_request
from ml.value_features import is_binary, normalize_unit, unit_hits

MAX_PAIRS = 256
_SPACE_ENCODING = re.compile(r"%20", re.I)
_DOUBLE_ENCODED = re.compile(r"%25[0-9a-fA-F]{2}")
MAX_VALUE = 8192
_B64 = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")
_MULTIPART_NAME = re.compile(r'name="([^"]*)"', re.I)


def _enc(text):
    """Escape only what delimits pairs; every other character (Thai included) stays decoded."""
    return (str(text).replace("%", "%25").replace("&", "%26").replace("=", "%3D")
            .replace("+", "%2B").replace("#", "%23").replace(" ", "+"))


def _enc_segment(text):
    return _enc(text).replace("/", "%2F").replace("?", "%3F")


def reveal_base64(value):
    """The decoded text if `value` is Base64 hiding something a detector flags, else `value`."""
    v = value.strip()
    if len(v) < 12 or len(v) > MAX_VALUE or not _B64.fullmatch(v):
        return value
    padded = v + "=" * (-len(v) % 4)
    for decode in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            text = decode(padded).decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if not text or sum(ch.isprintable() or ch.isspace() for ch in text) < 0.95 * len(text):
            continue
        norm, _ = normalize_unit(text.lower())
        if any(unit_hits(norm).values()):
            return text
    return value


def _json_pairs(obj, key, out):
    """Scalar leaves as (bracket path, value): {"user": {"$ne": ""}} -> ("user[$ne]", "").

    The bracket path is how a form body carries nested fields (qs / PHP), so a JSON
    NoSQL injection reads exactly like its form-encoded twin; keeping only the leaf
    key would turn it into "$ne=" and hide the field it targets. null stays "null".
    """
    if len(out) >= MAX_PAIRS:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            _json_pairs(v, f"{key}[{k}]" if key else str(k), out)
    elif isinstance(obj, list):
        for v in obj:
            _json_pairs(v, key, out)
    else:
        out.append((key, obj if isinstance(obj, str) else json.dumps(obj)))


def _multipart_pairs(body):
    """(name, value) of each multipart/form-data part; None if `body` is not multipart."""
    first = body.split("\n", 1)[0].strip()
    if not first.startswith("--") or len(first) < 3 or "content-disposition" not in body[:2048].lower():
        return None
    pairs = []
    for part in body.split(first)[1:]:
        if part.startswith("--") or not part.strip():
            continue
        head, sep, content = part.lstrip("\r\n").partition("\r\n\r\n")
        if not sep:
            head, sep, content = part.lstrip("\n").partition("\n\n")
        m = _MULTIPART_NAME.search(head)
        name = m.group(1) if m else ""
        content = content[:-2] if content.endswith("\r\n") else content.rstrip("\n")
        if "filename=" in head.lower() and is_binary(content):
            content = ""
        pairs.append((name, content[:MAX_VALUE]))
        if len(pairs) >= MAX_PAIRS:
            break
    return pairs


def _form(pairs):
    return "&".join(f"{_enc(k)}={_enc(reveal_base64(v))}" for k, v in pairs[:MAX_PAIRS])


def canonical_query(query):
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    if not pairs:  # no "=": one opaque value
        return _enc(reveal_base64(unquote_plus(query)))
    return _form(pairs)


def canonical_body(body):
    body = str(body or "")
    stripped = body.lstrip()
    if not stripped:
        return ""
    if stripped[:1] in "{[":
        try:
            pairs = []
            _json_pairs(json.loads(stripped), "", pairs)
            return _form(pairs)
        except ValueError:
            return body
    pairs = _multipart_pairs(body)
    if pairs is not None:
        return _form(pairs)
    if "=" in body and "\n" not in stripped:
        pairs = parse_qsl(body, keep_blank_values=True)
        if pairs:
            return _form(pairs)
    return body


def canonical_path(path):
    """Path segments whose Base64 hides an attack are decoded; the rest is untouched."""
    path = str(path or "/")
    segs = path.split("/")
    out = []
    changed = False
    for s in segs:
        r = reveal_base64(s) if s else s
        if r is not s:
            changed = True
            r = _enc_segment(r)
        out.append(r)
    return "/".join(out) if changed else path


def canonical_request(path, query, body):
    """(path, query, body) in canonical form; see the module docstring."""
    return canonical_path(path), canonical_query(query or ""), canonical_body(body)


def raw_encoding_features(url, body):
    """The encoding features of the raw request, space encoding ignored."""
    src = _SPACE_ENCODING.sub("", f"{url} {body or ''}")
    return {"encoded_char_ratio": round(len(ENCODED_BYTE_PATTERN.findall(src)) / max(len(src), 1), 4),
            "double_encoded_count": len(_DOUBLE_ENCODED.findall(src)),
            "encoded_attack_token_count": len(ENCODED_ATTACK_TOKEN_PATTERN.findall(src))}


def canonical_features(method, path, query, body):
    """(structural features, canonical (path, query, body)) for one request.

    The single place both the trainer and serving compute the structural
    features: content from the canonical request, encoding from the raw one.
    """
    path = str(path or "/")
    query, body = str(query or ""), str(body or "")
    cpath, cquery, cbody = canonical_request(path, query, body)
    feats = extract_features_from_request(url=f"{cpath}?{cquery}" if cquery else cpath,
                                          method=method or "GET", body=cbody)
    feats.update(raw_encoding_features(f"{path}?{query}" if query else path, body))
    return feats, (cpath, cquery, cbody)
