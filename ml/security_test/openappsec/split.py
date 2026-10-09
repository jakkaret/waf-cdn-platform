"""Deterministic gen / eval halves of the open-appsec benchmark, for the ML rule-proposal ablation.

Rules are proposed and backtested on the "gen" half and measured on the "eval" half only, so a
rule never gets credit for the very request it was built from.

  Legitimate  by website (TestName): one site's traffic is all on one side
  Malicious   by payload group: the value of `p` fully URL-decoded and lowercased, so the same
              payload sent as GET /?p=... and as POST p=... (the tool sends both) stays together

Both sides are a stable hash, so every script (propose_rules, backtest_rules, summarize_db)
gets the same halves without sharing state.
"""

import hashlib
from urllib.parse import parse_qsl, unquote_plus, urlsplit

GEN, EVAL = "gen", "eval"
SALT = "openappsec-rule-proposal-v1"  # change only together with every result built on the old split


def payload_of(url, body):
    """The attack payload of a benchmark request (`p` from the query or the form body), decoded."""
    for source in (body or "", urlsplit(url or "").query):
        for key, value in parse_qsl(source, keep_blank_values=True):
            if key == "p":
                text = value
                break
        else:
            continue
        break
    else:
        text = f"{url}\n{body or ''}"
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return text.lower()


def group_of(dataset_type, test_name, url, body):
    """The unit that must not be split across halves."""
    if dataset_type == "Legitimate":
        return f"site:{test_name}"
    return f"payload:{test_name}:{payload_of(url, body)}"


def half_of_group(group):
    digest = hashlib.sha256(f"{SALT}\0{group}".encode("utf-8", "surrogatepass")).digest()
    return GEN if digest[0] % 2 == 0 else EVAL


def half_of(dataset_type, test_name, url, body):
    return half_of_group(group_of(dataset_type, test_name, url, body))


def add_halves(df):
    """Add `group` and `half` columns to a frame with DataSetType, TestName, url, data.

    `group` is a hash of the group text: pandas' string dtype cuts a string at a NUL byte when
    grouping, so traversal payloads such as "../etc/passwd" and "../etc/passwd\\x00index.html"
    would merge into one group. The halves come from the full text either way.
    """
    groups = [group_of(t, n, u, b) for t, n, u, b in zip(df["DataSetType"], df["TestName"], df["url"], df["data"])]
    df = df.copy()
    df["group"] = [hashlib.sha256(g.encode("utf-8", "surrogatepass")).hexdigest() for g in groups]
    df["half"] = [half_of_group(g) for g in groups]
    assert df.groupby("group")["half"].nunique().max() == 1, "a group landed on both halves"
    return df
