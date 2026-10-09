#!/usr/bin/env python3
"""
Prepare public, real-traffic datasets for Gen 3 training (Roadmap 3.1-B/D/E).

Sources (downloaded to ml/dataset/external/, provenance recorded in
ml/dataset/external/prepare_stats.json):

1. open-appsec WAF Comparison Project (Apache-2.0)
   https://downloads.openappsec.io/waf-comparison-project/legitimate.zip
   https://downloads.openappsec.io/waf-comparison-project/malicious.zip
   - legitimate: real browser sessions on 185 production websites (2024).
   - malicious: mgm WAF payload collection wrapped as GET /?p=<payload> and
     POST / p=<payload>. The wrapper is uniform, so this source is reported
     separately and never used to judge real-traffic performance.
2. SR-BH 2020 (CC0), Harvard Dataverse doi:10.7910/DVN/OGOIXX
   https://dataverse.harvard.edu/api/access/datafile/6319496
   - 12 days of real internet traffic to a WordPress honeypot, ModSecurity CRS
     labels reviewed manually by the authors, 13 CAPEC classes.

Labelling mirrors 3.1-D:
- attack only for payload-bearing classes (code/command/SQL injection, path
  traversal, response splitting); protocol/scan/verb-tampering/spoofing/
  brute-force-only rows are unknown and excluded, never auto-labelled attack.
- benign only when the source itself vouches for it (open-appsec legitimate
  browsing; SR-BH rows whose only label is "000 - Normal").

To keep memory bounded, at most MAX_ROWS_PER_GROUP rows are kept per
(near-duplicate group, label) per source, using the trainer's own group key;
the trainer weights rows 1/group-size anyway, so dropped rows carry no extra
information. Bodies are capped at BODY_CAP characters.
"""

import csv
import hashlib
import json
import os
import sys
import zipfile
from collections import Counter, defaultdict
from urllib.parse import urlsplit

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.train_gen3_full_real_benchmark import near_duplicate_group  # noqa: E402

ML_DIR = os.path.dirname(os.path.abspath(__file__))
EXT_DIR = os.path.join(ML_DIR, "dataset", "external")
MAX_ROWS_PER_GROUP = 3
BODY_CAP = 16384

OPENAPPSEC_FAMILY = {
    "cmdexe": "RCE", "log4shell": "Log4Shell", "shellshock": "RCE-Shellshock",
    "sqli": "SQLi", "traversal": "LFI", "xss": "XSS", "xxe": "XXE",
}
SRBH_PAYLOAD_CLASSES = {
    "242 - Code Injection": "Code-Injection",
    "88 - OS Command Injection": "RCE",
    "248 - Command Injection": "RCE",
    "126 - Path Traversal": "LFI",
    "66 - SQL Injection": "SQLi",
    "34 - HTTP Response Splitting": "Response-Splitting",
}
SRBH_NORMAL = "000 - Normal"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


class CappedWriter:
    """Writes rows, keeping at most MAX_ROWS_PER_GROUP per (group, label) and dropping exact duplicates."""

    def __init__(self, path):
        self.fp = open(path, "w", encoding="utf-8")
        self.group_counts = defaultdict(int)
        self.seen = set()
        self.stats = Counter()

    def add(self, uri, query, body, method, cls, source, family, **extra):
        body = (body or "")[:BODY_CAP]
        method = (method or "GET").upper()
        exact = hashlib.sha256(f"{uri}\x1f{query}\x1f{body}\x1f{method}".encode("utf-8", "replace")).digest()
        if exact in self.seen:
            self.stats["exact_duplicate"] += 1
            return
        self.seen.add(exact)
        key = (near_duplicate_group(uri, query, body), cls)
        if self.group_counts[key] >= MAX_ROWS_PER_GROUP:
            self.stats["near_duplicate_capped"] += 1
            return
        self.group_counts[key] += 1
        self.stats[f"kept_{cls}"] += 1
        self.fp.write(json.dumps({"URI": uri, "GET-Query": query, "POST-Data": body, "Method": method,
                                  "Class": cls, "Source": source, "Family": family, **extra},
                                 ensure_ascii=False) + "\n")

    def close(self):
        self.fp.close()
        self.stats["distinct_groups"] = len(self.group_counts)
        return dict(self.stats)


def _split_url(url):
    parts = urlsplit(url if url.startswith(("/", "http")) else "/" + url)
    return (parts.path or "/"), parts.query


def prepare_openappsec():
    out = {}
    src = os.path.join(EXT_DIR, "openappsec")
    for kind, cls in (("legitimate", "Valid"), ("malicious", "Anomalous")):
        zpath = os.path.join(src, f"{kind}.zip")
        w = CappedWriter(os.path.join(EXT_DIR, f"openappsec_{kind}.jsonl"))
        with zipfile.ZipFile(zpath) as z:
            for name in sorted(n for n in z.namelist() if n.endswith(".json")):
                stem = os.path.splitext(os.path.basename(name))[0]
                family = "benign" if cls == "Valid" else OPENAPPSEC_FAMILY.get(stem, stem)
                for r in json.loads(z.read(name)):
                    uri, query = _split_url(str(r.get("url", "/")))
                    data = r.get("data") or ""
                    if not isinstance(data, str):
                        data = json.dumps(data)
                    w.add(uri, query, data, r.get("method"), cls, f"OpenAppSec_{kind.capitalize()}", family, site=stem)
        out[kind] = {"input_sha256": sha256_file(zpath), **w.close()}
        print(f"[+] open-appsec {kind}: {out[kind]}")
    return out


def prepare_srbh():
    path = os.path.join(EXT_DIR, "srbh2020", "data_capec_multilabel.csv")
    w = CappedWriter(os.path.join(EXT_DIR, "srbh2020_labelled.jsonl"))
    excluded = Counter()
    csv.field_size_limit(sys.maxsize)
    with open(path, newline="", encoding="utf-8", errors="replace") as fp:
        reader = csv.DictReader(fp)
        label_cols = [c for c in reader.fieldnames if c.split(" - ")[0].strip().isdigit()]
        for r in reader:
            on = {c for c in label_cols if str(r.get(c, "0")).strip() in ("1", "1.0")}
            payload = sorted({SRBH_PAYLOAD_CLASSES[c] for c in on if c in SRBH_PAYLOAD_CLASSES})
            if payload:
                cls, family = "Anomalous", "+".join(payload)
            elif on == {SRBH_NORMAL}:
                cls, family = "Valid", "benign"
            else:
                excluded["+".join(sorted(on)) or "no_label"] += 1
                continue
            uri, query = _split_url(str(r.get("request_http_request") or "/"))
            w.add(uri, query, r.get("request_body") or "", r.get("request_http_method"), cls, "SRBH2020_Honeypot", family,
                  status=r.get("response_http_status_code", ""))
    stats = {"input_sha256": sha256_file(path), "label_columns": label_cols,
             "excluded_non_payload_label_sets": dict(excluded.most_common(15)),
             "excluded_total": sum(excluded.values()), **w.close()}
    print(f"[+] SR-BH 2020: kept/capped {stats}")
    return stats


# Exact files the 27/09/2026 candidates were built from (sha256 verified on download).
DOWNLOADS = [
    ("https://downloads.openappsec.io/waf-comparison-project/legitimate.zip",
     os.path.join("openappsec", "legitimate.zip"),
     "58faee18c54229759287a574f6f8cb1e3b951fa135e403ea9a679d2b18efd778"),
    ("https://downloads.openappsec.io/waf-comparison-project/malicious.zip",
     os.path.join("openappsec", "malicious.zip"),
     "131314e5c13b07ec686e6b16b8010008063d977b5ff8eb552819c138c00b7b2b"),
    ("https://dataverse.harvard.edu/api/access/datafile/6319496",
     os.path.join("srbh2020", "data_capec_multilabel.csv"),
     "9c73c90ce6564ae48b14f7179cd864d037a6a130ef69c68c1626ec5d7ce4a910"),
]


def download_sources():
    """Fetch the public datasets (~1.7 GB) unless already present with the expected hash."""
    import urllib.request
    # Harvard Dataverse answers 403 to urllib's default "Python-urllib/x.y" User-Agent
    opener = urllib.request.build_opener()
    opener.addheaders = [("User-Agent", "Mozilla/5.0 (compatible; waf-project-dataset-fetch)")]
    urllib.request.install_opener(opener)
    for url, rel, expected in DOWNLOADS:
        path = os.path.join(EXT_DIR, rel)
        if os.path.exists(path) and sha256_file(path) == expected:
            print(f"[=] {rel} already present (sha256 OK)")
            continue
        os.makedirs(os.path.dirname(path), exist_ok=True)
        print(f"[*] Downloading {url} -> {rel} ...", flush=True)
        urllib.request.urlretrieve(url, path + ".part")
        got = sha256_file(path + ".part")
        if got != expected:
            os.remove(path + ".part")
            raise SystemExit(f"[!] sha256 mismatch for {rel}: got {got}, expected {expected} (source changed?)")
        os.replace(path + ".part", path)
        print(f"[+] {rel} sha256 OK")


def main():
    if "--download" in sys.argv:
        download_sources()
    stats = {"max_rows_per_group": MAX_ROWS_PER_GROUP, "body_cap_chars": BODY_CAP,
             "openappsec": prepare_openappsec(), "srbh2020": prepare_srbh()}
    with open(os.path.join(EXT_DIR, "prepare_stats.json"), "w", encoding="utf-8") as f:
        json.dump(stats, f, indent=2)
    print(f"[✔] Wrote {os.path.join(EXT_DIR, 'prepare_stats.json')}")


if __name__ == "__main__":
    main()
