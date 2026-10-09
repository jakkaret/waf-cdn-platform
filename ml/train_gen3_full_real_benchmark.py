#!/usr/bin/env python3
"""
Full Real-World Training & Benchmark for WAF Gen 3 (Roadmap 3.1-D .. 3.1-G):
1. ZERO Synthetic rows, ZERO Row Multiplication. Hand-written "representative"
   URLs are NOT training data; they live only in ml/test_comprehensive.py.
2. Conservative labels with provenance (3.1-D):
   - CSIC 2010 Cleaned (checked-in benchmark labels)
   - VPS Telemetry: benign rows only. Its attack labels were derived from the
     model's own features (circular) and without the POST body that produced
     them, so they are excluded rather than trusted.
   - VPS ModSecurity: attack only when a payload rule family fired
     (930-944: LFI/RFI/RCE/PHP/XSS/SQLi/...). Protocol/generic-only events
     (920xxx + 949110, e.g. Juice Shop /socket.io/ polling hit by 920420) are
     excluded, never auto-labelled as attack. Non-GET events are excluded
     too: bodies were never captured, so their evidence is not in the row.
   - VPS Nginx 200/304 access rows (signature-filtered benign).
3. Features: EXTENDED_FEATURE_COLUMNS from ml/feature_engineering.py.
4. SHA-256 exact dedup + near-duplicate GROUPS (3.1-E.1/E.3): requests that
   differ only in method, digits or random tokens share a group. Groups never
   straddle train and holdout, and every row is weighted 1/group-size so each
   distinct request shape counts once in training, calibration and metrics.
5. Splits and CV folds are stratified on label x source. Hyperparameters and
   the decision threshold are chosen on dev out-of-fold predictions only;
   the holdout is evaluated exactly once (3.1-F.2/F.4).
6. Report: overall + per-source + per-attack-family metrics, enforcement-band
   recall, confusion matrix, single-request latency, and a dataset manifest
   with input file hashes.
"""

import os
import re
import sys
import json
import shutil
import glob
import hashlib
import inspect
import platform
import time
from collections import Counter
from datetime import datetime
from urllib.parse import parse_qsl
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold
from sklearn.metrics import roc_auc_score, confusion_matrix
import lightgbm as lgb
import joblib

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from ml.benchmark_real_holdout import load_real_csic_dataset, MIN_BENIGN_RECALL, MIN_ATTACK_RECALL, N_SPLITS, RANDOM_STATE
from ml.benchmark_gen3_real_augmented import load_real_telemetry
from ml.canonical import canonical_features
from ml.download_dataset import download_csic_dataset
from ml.feature_engineering import EXTENDED_FEATURE_COLUMNS, extract_features_from_request
from ml.hybrid_model import (
    TOKEN_SCORE_COLUMN, Gen3HybridModel, TokenModel, make_vectorizer, request_text, request_units,
)

ML_DIR = os.path.dirname(os.path.abspath(__file__))
ARCHIVE_DIR = os.path.join(ML_DIR, "models", "archive")
MODSEC_ATTACKS_PATH = os.path.join(ML_DIR, "dataset", "modsec_real_attacks.jsonl")
VPS_AUDIT_PATH = os.path.join(ML_DIR, "dataset", "vps_audit_labelled.jsonl")
VPS_AUDIT_STATS_PATH = os.path.join(ML_DIR, "dataset", "vps_audit_labelled.stats.json")
NGINX_BENIGN_PATH = os.path.join(ML_DIR, "dataset", "nginx_real_benign.jsonl")
CSIC_PATH = os.path.join(ML_DIR, "dataset", "csic_final.csv")
TELEMETRY_DIR = os.path.join(ML_DIR, "telemetry")
EXTERNAL_DIR = os.path.join(ML_DIR, "dataset", "external")
EXTERNAL_SOURCES = {
    "OpenAppSec_Legitimate": os.path.join(EXTERNAL_DIR, "openappsec_legitimate.jsonl"),
    "OpenAppSec_Malicious": os.path.join(EXTERNAL_DIR, "openappsec_malicious.jsonl"),
    "SRBH2020_Honeypot": os.path.join(EXTERNAL_DIR, "srbh2020_labelled.jsonl"),
}
# Group-level sampling rates per (source, class), for memory/compute on a 7 GB
# machine. Whole near-duplicate groups are kept or dropped together (by hash
# of the group key), so sampling is deterministic and cannot split a group.
EXTERNAL_GROUP_SAMPLE_RATE = {
    ("OpenAppSec_Legitimate", "Valid"): 0.20,   # ~425k groups -> ~85k
    ("SRBH2020_Honeypot", "Anomalous"): 0.40,
}
EXTERNAL_STATS_PATH = os.path.join(EXTERNAL_DIR, "prepare_stats.json")

# The headline promotion gate is judged on the sources the gate was defined
# on (CSIC + this VPS), so results stay comparable across candidates and a
# large, easy external source cannot inflate it. External sources train the
# model and are reported per source.
CORE_SOURCES = {
    "CSIC_2010_Cleaned",
    "VPS_Telemetry_Real",
    "VPS_Nginx_Real_200_Access",
    "ModSecurity_VPS_Audit_Payload_Rule",
    "VPS_Audit_RuleFree_2xx_Lab",
}

# OWASP CRS rule-file prefixes that indicate an actual payload attack.
# Anything else (920 protocol enforcement, 911/913 method/scanner, 949/980
# anomaly-score summaries) is protocol/generic evidence only.
PAYLOAD_RULE_FAMILIES = {
    "930": "LFI",
    "931": "RFI",
    "932": "RCE",
    "933": "PHP",
    "934": "Generic-Injection",
    "941": "XSS",
    "942": "SQLi",
    "943": "Session-Fixation",
    "944": "Java",
}

LGBM_PARAMS = dict(
    n_estimators=400,
    max_depth=10,
    num_leaves=80,
    min_child_samples=20,
    learning_rate=0.05,
    reg_alpha=0.2,
    reg_lambda=0.3,
    colsample_bytree=0.8,
    subsample=0.85,
    class_weight={0: 1.0, 1: 1.5},
    random_state=42,
    # Physical cores only: with hyperthreads (n_jobs=-1) LightGBM fits were ~8x slower under WSL.
    n_jobs=max(1, (os.cpu_count() or 2) // 2),
    verbose=-1,
)

_MIXED_TOKEN = re.compile(r"[a-z0-9_\-\.]{6,}")
_DIGITS = re.compile(r"\d+")


def _sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fp:
        for chunk in iter(lambda: fp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def modsec_attack_families(rule_ids):
    """Return the sorted payload families a ModSecurity event hit, or []."""
    return sorted({PAYLOAD_RULE_FAMILIES[r[:3]] for r in rule_ids if str(r)[:3] in PAYLOAD_RULE_FAMILIES})


def _value_shape(value):
    """Collapse values that differ only in digits or random tokens (session ids, cache busters)."""
    v = str(value).lower()
    v = _MIXED_TOKEN.sub(
        lambda m: "T" if any(c.isdigit() for c in m.group()) and any(c.isalpha() for c in m.group()) else m.group(),
        v,
    )
    return _DIGITS.sub("0", v)


def near_duplicate_group(uri, query, body):
    """Group key for 3.1-E.3: same path + param names + value shapes.

    Method is deliberately not part of the key: CSIC ships every request as
    both a GET and a POST variant, which are the same payload.
    """
    pairs = parse_qsl(query, keep_blank_values=True, max_num_fields=10000) + \
        parse_qsl(body, keep_blank_values=True, max_num_fields=10000)
    if pairs:
        payload = "&".join(f"{k}={_value_shape(v)}" for k, v in sorted(pairs))
    else:
        payload = _value_shape(query + body)
    return f"{_value_shape(uri)} {payload}"


def load_real_modsec_attacks():
    """Load ModSecurity events; keep only payload-rule hits as attacks (3.1-D.1/D.2)."""
    if not os.path.exists(MODSEC_ATTACKS_PATH):
        raise FileNotFoundError(f"ModSec attacks file not found: {MODSEC_ATTACKS_PATH}")

    rows = []
    excluded = 0
    excluded_rules = Counter()
    excluded_no_body = 0
    with open(MODSEC_ATTACKS_PATH, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rule_ids = [str(r) for r in d.get("rule_ids", [])]
            families = modsec_attack_families(rule_ids)
            if not families:
                excluded += 1
                excluded_rules.update(rule_ids)
                continue
            # The extractor never captured request bodies: for a non-GET event
            # the matched payload was most likely in the body we do not have,
            # so the training row would carry the label without its evidence.
            if str(d.get("Method", "GET")).upper() != "GET" and not d.get("POST-Data"):
                excluded_no_body += 1
                continue
            rows.append({
                "URI": d.get("URI", "/"),
                "GET-Query": d.get("GET-Query", ""),
                "POST-Data": d.get("POST-Data", ""),
                "Method": d.get("Method", "GET"),
                "Class": "Anomalous",
                "Source": "ModSecurity_VPS_Payload_Rule",
                "Family": "+".join(families),
            })

    df_modsec = pd.DataFrame(rows)
    print(f"[+] ModSecurity payload-rule attacks: {len(df_modsec)} rows kept; "
          f"{excluded} protocol/generic-only events excluded (3.1-D.2); "
          f"{excluded_no_body} non-GET events without captured body excluded")
    return df_modsec, {
        "kept_payload_rule_rows": len(df_modsec),
        "excluded_protocol_only_rows": excluded,
        "excluded_non_get_without_body_rows": excluded_no_body,
        "excluded_top_rule_ids": dict(excluded_rules.most_common(10)),
    }


def _read_json(path):
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as fp:
        return json.load(fp)


def _group_sampled(group_key, rate):
    return rate >= 1.0 or int(hashlib.sha256(group_key.encode("utf-8", "replace")).hexdigest()[:8], 16) / 0xFFFFFFFF < rate


def load_jsonl_source(path, source_name=None):
    """Stream a prepared, already-labelled JSONL source (Class/Source/Family set per row).

    For external sources, whole near-duplicate groups are sampled at
    EXTERNAL_GROUP_SAMPLE_RATE so memory stays bounded.
    """
    keep = ["URI", "GET-Query", "POST-Data", "Method", "Class", "Source", "Family"]
    rows = []
    with open(path, "r", encoding="utf-8") as fp:
        for line in fp:
            r = json.loads(line)
            rate = EXTERNAL_GROUP_SAMPLE_RATE.get((source_name, r["Class"]), 1.0)
            if rate < 1.0 and not _group_sampled(
                    near_duplicate_group(r["URI"], r["GET-Query"], r["POST-Data"]), rate):
                continue
            rows.append({k: r.get(k, "") for k in keep})
    df = pd.DataFrame(rows, columns=keep)
    print(f"[+] {os.path.basename(path)}: {len(df)} rows "
          f"(benign {int((df['Class'] == 'Valid').sum())}, attack {int((df['Class'] == 'Anomalous').sum())})")
    return df


def exclude_contradicted_benign(df):
    """Drop SR-BH "000 - Normal" rows that carry an unmistakable attack payload (3.1-D).

    The SR-BH normal class contains real attacks (e.g. shellshock `() { :;};
    /bin/sleep 15`, `;cat /etc/passwd`, `'"<script>alert(1);</script>`), about
    7-8% of it. Label and evidence contradict each other, so those rows are
    treated as unknown and excluded from training and evaluation alike; they are
    never relabelled as attacks. Evidence = any value detector hit
    (ml/value_features.py), which fires on 0.52% of real browsing traffic
    (open-appsec legitimate), so few genuine benign rows are lost.
    """
    from ml.value_features import DETECTOR_COLUMNS, extract_value_features  # needs libinjection

    def contradicted(method, uri, query, body):
        feats = extract_value_features(method or "GET", uri, query, body)
        return any(feats[c] > 0 for c in DETECTOR_COLUMNS)  # includes hits in the path itself

    benign = df["Class"] == "Valid"
    hit = pd.Series(False, index=df.index)
    hit[benign] = [contradicted(m, u, q, b)
                   for u, q, b, m in df.loc[benign, ["URI", "GET-Query", "POST-Data", "Method"]].itertuples(index=False)]
    stats = {"benign_rows": int(benign.sum()), "excluded_rows": int(hit.sum()),
             "rule": "SR-BH Valid row with any ml/value_features.py detector hit -> excluded (unknown), never relabelled"}
    print(f"[+] SR-BH benign contradicted by attack detectors: {stats['excluded_rows']} of {stats['benign_rows']} excluded")
    return df.loc[~hit].reset_index(drop=True), stats


def load_real_nginx_benign():
    """Load verified clean 200/304 requests extracted from VPS Nginx access.json."""
    if not os.path.exists(NGINX_BENIGN_PATH):
        print(f"[!] Nginx benign file not found at: {NGINX_BENIGN_PATH}")
        return pd.DataFrame()

    rows = []
    with open(NGINX_BENIGN_PATH, "r", encoding="utf-8") as fp:
        for line in fp:
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            rows.append({
                "URI": d.get("URI", "/"),
                "GET-Query": d.get("GET-Query", ""),
                "POST-Data": d.get("POST-Data", ""),
                "Method": d.get("Method", "GET"),
                "Class": "Valid",
                "Source": "VPS_Nginx_Real_200_Access"
            })

    df_nginx = pd.DataFrame(rows)
    print(f"[+] Loaded Real Nginx Clean Requests: {len(df_nginx)} rows (Provenance: VPS Nginx access.json)")
    return df_nginx


BUILD_CACHE_DIR = os.path.join(ML_DIR, "dataset", ".build_cache")


def _build_cache_key():
    """Hash of every input that can change the built dataset: data files, loader/feature code, sampling."""
    h = hashlib.sha256()
    for fn in (_build_full_real_dataset_uncached, near_duplicate_group, _value_shape, load_jsonl_source, request_text,
               exclude_contradicted_benign,
               request_units, canonical_features,
               _group_sampled, load_real_nginx_benign):
        h.update(inspect.getsource(fn).encode())
    code = [os.path.join(ML_DIR, f) for f in ("feature_engineering.py", "benchmark_real_holdout.py", "benchmark_gen3_real_augmented.py",
                                              "value_features.py", "canonical.py")]
    data = [CSIC_PATH, VPS_AUDIT_PATH, NGINX_BENIGN_PATH, *EXTERNAL_SOURCES.values()] + sorted(glob.glob(os.path.join(TELEMETRY_DIR, "*.jsonl")))
    for path in code + data:
        if os.path.exists(path):
            h.update(path.encode()); h.update(_sha256_file(path).encode())
    h.update(json.dumps(sorted((f"{a}|{b}", r) for (a, b), r in EXTERNAL_GROUP_SAMPLE_RATE.items())).encode())
    return h.hexdigest()[:24]


def build_full_real_dataset(use_cache=True):
    """Cached wrapper: rebuilding (dedup + grouping + feature extraction) takes minutes."""
    # CSIC is auto-downloaded on first use; fetch it before hashing inputs, or the key
    # of a fresh runtime (no CSIC yet) differs from every later run in the same runtime.
    download_csic_dataset()
    key = _build_cache_key()
    path = os.path.join(BUILD_CACHE_DIR, f"{key}.joblib")
    if use_cache and os.path.exists(path):
        print(f"[+] Loaded built dataset from cache {os.path.relpath(path, ML_DIR)}")
        return joblib.load(path)
    built = _build_full_real_dataset_uncached()
    os.makedirs(BUILD_CACHE_DIR, exist_ok=True)
    for old in glob.glob(os.path.join(BUILD_CACHE_DIR, "*.joblib")):
        os.remove(old)
    joblib.dump(built, path)
    return built


def _build_full_real_dataset_uncached():
    """Build the deduplicated, conservatively labelled dataset.

    Returns (X, y, hashes, integrity, meta) where meta is a DataFrame aligned
    with X holding Source, Family and the near-duplicate Group of every row.
    """
    print("\n" + "="*60)
    print(" 📦 BUILDING 100% REAL-WORLD GEN 3 DATASET (ZERO SYNTHETIC)")
    print("="*60)

    # 1. CSIC 2010 Cleaned (Real historical benchmark)
    df_csic = load_real_csic_dataset()
    df_csic["Source"] = "CSIC_2010_Cleaned"
    df_csic["Family"] = "CSIC_unlabelled_family"
    print(f"[+] CSIC Cleaned: {len(df_csic)} rows")

    # 2. VPS Live Telemetry: benign only. The loader's attack labels come from
    #    this model's own features on a body we no longer have (circular).
    df_telem_all = load_real_telemetry()
    telem_attack_dropped = int((df_telem_all["Class"] == "Anomalous").sum())
    df_telem = df_telem_all[df_telem_all["Class"] == "Valid"].copy()
    print(f"[+] Telemetry benign kept: {len(df_telem)}; feature-derived attack labels dropped: {telem_attack_dropped}")

    # 3. VPS ModSecurity, all audit logs incl. rotated .gz (scripts/extract_vps_audit_dataset.py):
    #    payload-rule GET attacks + rule-free 2xx/3xx GET benign on lab hosts
    #    Private (never in git): absent on a public-data-only run such as a fresh Colab runtime.
    if os.path.exists(VPS_AUDIT_PATH):
        df_audit = load_jsonl_source(VPS_AUDIT_PATH)
    else:
        print(f"[!] VPS audit dataset not found at {VPS_AUDIT_PATH}; training without VPS audit rows")
        df_audit = pd.DataFrame()
    modsec_stats = _read_json(VPS_AUDIT_STATS_PATH)

    # 4. VPS Live Nginx Real Clean Requests (Real 200/304 verified traffic from VPS)
    df_nginx = load_real_nginx_benign()

    # (The former step 5, 69 hand-written "representative" URLs, was removed:
    #  they are synthetic and overlapped the scenarios in test_comprehensive.py.)

    # 5. Public real-traffic datasets (ml/prepare_external_datasets.py)
    external = {name: load_jsonl_source(path, name) for name, path in EXTERNAL_SOURCES.items() if os.path.exists(path)}
    srbh_contradicted = {}
    if "SRBH2020_Honeypot" in external:
        external["SRBH2020_Honeypot"], srbh_contradicted = exclude_contradicted_benign(external["SRBH2020_Honeypot"])

    raw_counts = {
        "CSIC_2010_Cleaned": len(df_csic),
        "VPS_Telemetry_Real_benign": len(df_telem),
        "VPS_ModSecurity_Audit_labelled": len(df_audit),
        "VPS_Nginx_Real_200_Access": len(df_nginx),
    } | {name: len(df) for name, df in external.items()}

    combined = pd.concat([df_csic, df_telem, df_audit, df_nginx, *external.values()], ignore_index=True)
    combined["Family"] = combined["Family"].fillna("benign")
    combined.loc[combined["Class"].astype(str).str.strip().str.lower() != "anomalous", "Family"] = "benign"
    rows_before = len(combined)

    # Enforce 100% SHA-256 Deduplication
    request_cols = ["URI", "GET-Query", "POST-Data", "Method"]
    combined[request_cols] = combined[request_cols].fillna("").astype(str)
    canonical = combined[request_cols].agg("\x1f".join, axis=1)
    hashes = canonical.map(lambda v: hashlib.sha256(v.encode("utf-8")).hexdigest())

    labels = combined["Class"].astype(str).str.strip().str.lower().map(lambda v: 1 if v == "anomalous" else 0)

    # Verify no conflicting labels on identical requests
    conflicts = pd.DataFrame({"hash": hashes, "label": labels}).groupby("hash")["label"].nunique()
    conflicting_hashes = int((conflicts > 1).sum())
    if conflicting_hashes:
        print(f"[!] Warning: {conflicting_hashes} conflicting hashes detected; dropping conflicts...")
        valid_hashes = set(conflicts[conflicts == 1].index)
        mask_valid = hashes.isin(valid_hashes)
        combined = combined.loc[mask_valid].reset_index(drop=True)
        hashes = hashes.loc[mask_valid].reset_index(drop=True)
        labels = labels.loc[mask_valid].reset_index(drop=True)

    keep = ~hashes.duplicated(keep="first")
    df_clean = combined.loc[keep].reset_index(drop=True)
    hashes_clean = hashes.loc[keep].reset_index(drop=True)
    labels_clean = labels.loc[keep].reset_index(drop=True)

    groups = df_clean.apply(
        lambda r: near_duplicate_group(r["URI"], r["GET-Query"], r["POST-Data"]), axis=1
    )
    # Near-duplicate weighting (3.1-E.1): every distinct request shape counts
    # once. A shape seen 8,887 times (e.g. GET /?_wd=<token>) gets weight
    # 1/8887 per row instead of dominating training and every metric.
    group_label = groups + "|" + labels_clean.astype(str)
    weights = 1.0 / group_label.map(group_label.value_counts()).astype(float)

    print(f"\n[✔] Data Cleaning & SHA-256 Deduplication Complete:")
    print(f"    - Total Unique Real Rows: {len(df_clean)} (Cleaned from {rows_before})")
    print(f"    - Near-duplicate groups:  {groups.nunique()} (effective distinct shapes: {weights.sum():.0f})")
    print(f"    - Genuine Benign Samples: {sum(labels_clean == 0)} rows / {weights[labels_clean == 0].sum():.0f} shapes")
    print(f"    - Genuine Attack Samples: {sum(labels_clean == 1)} rows / {weights[labels_clean == 1].sum():.0f} shapes")
    print(f"    - Synthetic Payloads:     0 (ZERO Synthetic Data)")

    print(f"\n[*] Extracting {len(EXTENDED_FEATURE_COLUMNS)} features for all {len(df_clean)} real samples...")
    features_list = []
    t0 = time.time()
    # Features (structural and per-unit) come from the canonical request, exactly as
    # in serving (ml/gen3_model.request_features); dedup and grouping above use raw.
    canon = []
    for _, r in df_clean.iterrows():
        feats, c = canonical_features(r["Method"] or "GET", r["URI"], r["GET-Query"], r["POST-Data"])
        features_list.append(feats)
        canon.append(c)

    print(f"[+] Feature Extraction completed in {time.time() - t0:.2f}s")
    X = pd.DataFrame(features_list)[EXTENDED_FEATURE_COLUMNS]
    y = labels_clean
    meta = pd.DataFrame({
        "Source": df_clean["Source"],
        "Family": df_clean["Family"],
        "URI": [c[0] for c in canon],
        "Group": groups,
        "Weight": weights,
        # Folds are stratified on label x source so every fold (and the
        # holdout) carries the same source mix.
        "Strat": labels_clean.astype(str) + "|" + df_clean["Source"],
        # Normalised request text for content (token) models; not a model feature here.
        "Text": [request_text(r["Method"], r["URI"], r["GET-Query"], r["POST-Data"]) for _, r in df_clean.iterrows()],
        # Context-free units (path segments, param names/values, JSON leaves) for per-unit max-pooling models
        "Units": [request_units(m, u, q, b) for (u, q, b), m in zip(canon, df_clean["Method"])],
    })

    per_source = pd.crosstab(meta["Source"], y).rename(columns={0: "benign", 1: "attack"})
    shapes_by_source = meta.groupby(["Source", y])["Weight"].sum().round(1)
    integrity = {
        "dataset": "CSIC_2010 + VPS_Telemetry_Benign + VPS_ModSecurity_Audit (payload-rule attacks, rule-free benign) + VPS_Nginx_Benign + OpenAppSec + SR-BH 2020",
        "core_sources_for_gate": sorted(CORE_SOURCES),
        "synthetic_rows": 0,
        "raw_rows_by_source": raw_counts,
        "exclusions": {
            "telemetry_feature_derived_attack_labels": telem_attack_dropped,
            "vps_audit_extraction": modsec_stats,
            "external_preparation": _read_json(EXTERNAL_STATS_PATH),
            "hand_written_representative_urls": "removed from training (synthetic)",
            "conflicting_label_hashes": conflicting_hashes,
            "exact_duplicates": int(rows_before - len(df_clean)),
            "external_group_sample_rate": {f"{s}|{c}": r for (s, c), r in EXTERNAL_GROUP_SAMPLE_RATE.items()},
            "srbh_benign_contradicted_by_detectors": srbh_contradicted,
        },
        "total_unique_samples": len(X),
        "near_duplicate_groups": int(groups.nunique()),
        "effective_distinct_shapes": round(float(weights.sum()), 1),
        "benign_count": int(sum(y == 0)),
        "attack_count": int(sum(y == 1)),
        "unique_rows_by_source": {s: {k: int(v) for k, v in r.items()} for s, r in per_source.iterrows()},
        "distinct_shapes_by_source_label": {f"{s}|{'attack' if l else 'benign'}": float(v)
                                            for (s, l), v in shapes_by_source.items()},
        "attack_family_counts": {k: int(v) for k, v in meta.loc[y == 1, "Family"].value_counts().items()},
        "feature_count": len(EXTENDED_FEATURE_COLUMNS),
        "feature_columns": EXTENDED_FEATURE_COLUMNS,
    }
    return X, y, hashes_clean.tolist(), integrity, meta


def group_folds(meta, n_splits=N_SPLITS):
    """Group-level stratified folds: yields (train_idx, val_idx) row indices.

    Folds are drawn over near-duplicate groups (one entry per group,
    stratified on label x source), so they balance distinct request shapes
    rather than rows. Row-balanced StratifiedGroupKFold instead parks a whole
    8,887-row group in one fold, leaving that fold with ~2 VPS benign shapes.
    """
    gtab = meta.groupby("Group", sort=True)["Strat"].first()
    skf = StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    group_col = meta["Group"]
    for g_fit, g_val in skf.split(np.zeros(len(gtab)), gtab.to_numpy()):
        # pandas hash-based isin: np.isin on object strings took ~3 min per call at 418k rows
        val_mask = group_col.isin(set(gtab.index[g_val])).to_numpy()
        yield np.flatnonzero(~val_mask), np.flatnonzero(val_mask)


def split_dev_holdout(meta):
    """Group-aware ~20% holdout: first group-level fold, stratified on label x source."""
    return next(group_folds(meta))


def weighted_recalls(y_true, y_pred, w):
    """Benign/attack recall where each row counts by its near-duplicate weight."""
    y_true, y_pred, w = np.asarray(y_true), np.asarray(y_pred), np.asarray(w, dtype=float)
    out = {}
    for name, cls, hit in (("benign", 0, 0), ("attack", 1, 1)):
        m = y_true == cls
        out[f"{name}_rows"] = int(m.sum())
        out[f"{name}_shapes"] = round(float(w[m].sum()), 1)
        out[f"{name}_recall"] = round(float(w[m & (y_pred == hit)].sum() / w[m].sum()), 4) if m.any() else None
        out[f"{name}_recall_rows"] = round(float((y_pred[m] == hit).mean()), 4) if m.any() else None
    return out


def choose_threshold_weighted(y_true, probs, w, benign_target=MIN_BENIGN_RECALL):
    """Highest weighted attack recall subject to weighted benign recall >= benign_target (attack = probs >= t).

    Exact on the scores. The previous 0.0005 grid broke when more than 1 - target
    of the benign weight scored above 0.9995 (LightGBM saturates on unseen data):
    the only admissible grid point was 1.0 and attack recall read 0 at AUC 0.94.
    Among thresholds with the same attack recall the highest is returned, which
    maximises benign recall (the grid's tie-break).
    """
    y_true, probs, w = np.asarray(y_true), np.asarray(probs, dtype=float), np.asarray(w, dtype=float)
    ben, att = y_true == 0, y_true == 1
    wb, wa = w[ben].sum(), w[att].sum()
    if wb <= 0 or wa <= 0:
        return {"threshold": 1.0, "attack_recall": 0.0, "benign_recall": 1.0, "status": "single_class"}
    order = np.argsort(-probs[ben], kind="stable")
    pb = probs[ben][order]
    above = np.cumsum(w[ben][order]) / wb  # benign weight scoring >= pb[i]
    k = int(np.searchsorted(above, (1.0 - benign_target) + 1e-12, side="right"))
    if k >= len(pb):
        t = 0.0  # the whole benign weight fits in the allowance
    else:
        # every benign score >= pb[k] must stay below t; raising t up to the next
        # attack score keeps attack recall and only adds benign recall
        pa = probs[att]
        higher = pa[pa > pb[k]]
        # (no attack above it: recall is 0 anyway, so pass every benign request)
        t = float(higher.min()) if higher.size else float(np.nextafter(probs.max(), np.inf))
    b_rec = float(w[ben & (probs < t)].sum() / wb)
    a_rec = float(w[att & (probs >= t)].sum() / wa)
    status = "passed_both_gates" if a_rec >= MIN_ATTACK_RECALL else "failed_attack_gate"
    return {"threshold": t, "attack_recall": a_rec, "benign_recall": b_rec, "status": status}


def oof_predict(X, y, meta, params, n_splits=N_SPLITS):
    """Out-of-fold probabilities from group-aware, label x source stratified CV."""
    oof = np.zeros(len(X))
    fold_of = np.zeros(len(X), dtype=int)
    for fold, (fit_idx, val_idx) in enumerate(group_folds(meta, n_splits), 1):
        m = lgb.LGBMClassifier(**params)
        m.fit(X.iloc[fit_idx], y.iloc[fit_idx], sample_weight=meta["Weight"].iloc[fit_idx].to_numpy())
        oof[val_idx] = m.predict_proba(X.iloc[val_idx])[:, 1]
        fold_of[val_idx] = fold
    return oof, fold_of


def select_hyperparameters(X_dev, y_dev, meta_dev):
    """Pick regularisation on dev OOF only (the holdout is never consulted).

    The grid spans tree capacity and leaf size (attack class weight made no
    consistent difference in the 27/09 12-config grid, so it is fixed at 1:1).
    The objective is the promotion gate itself on the CORE sources: weighted
    attack recall at weighted benign recall >= 98.5%.
    """
    grid = []
    for num_leaves in (31, 80, 255):
        for min_child_samples in (20, 100):
            grid.append(LGBM_PARAMS | {
                "num_leaves": num_leaves,
                "min_child_samples": min_child_samples,
                "max_depth": -1 if num_leaves > 80 else LGBM_PARAMS["max_depth"],
                "class_weight": {0: 1.0, 1: 1.0},
            })
    results = []
    core = meta_dev["Source"].isin(CORE_SOURCES).to_numpy()
    w = meta_dev["Weight"].to_numpy()
    for i, params in enumerate(grid, 1):
        t0 = time.time()
        oof, _ = oof_predict(X_dev, y_dev, meta_dev, params)
        cal = choose_threshold_weighted(y_dev[core], oof[core], w[core])
        auc = float(roc_auc_score(y_dev[core], oof[core], sample_weight=w[core]))
        results.append({"params": {k: params[k] for k in ("num_leaves", "min_child_samples")} |
                        {"attack_weight": params["class_weight"][1]},
                        "oof_threshold": round(cal["threshold"], 4),
                        "oof_attack_recall": round(cal["attack_recall"], 4),
                        "oof_benign_recall": round(cal["benign_recall"], 4),
                        "oof_weighted_auc": round(auc, 4)})
        print(f"  [{i:2d}/{len(grid)}] {results[-1]['params']} -> CORE OOF attack {cal['attack_recall']*100:.2f}% "
              f"@ benign {cal['benign_recall']*100:.2f}% (thr {cal['threshold']:.4f}, wAUC {auc:.4f}) [{time.time()-t0:.0f}s]",
              flush=True)
    best_i = max(range(len(grid)), key=lambda i: (results[i]["oof_attack_recall"], results[i]["oof_weighted_auc"]))
    return grid[best_i], results, best_i


def select_token_alpha(H_dev, y_dev, meta_dev, alphas=(1e-7, 3e-7, 1e-6, 3e-6)):
    """Pick the token model's L2 strength on CORE dev OOF (same objective as the tree grid)."""
    core = meta_dev["Source"].isin(CORE_SOURCES).to_numpy()
    w = meta_dev["Weight"].to_numpy()
    results, best = [], None
    for alpha in alphas:
        t0 = time.time()
        oof = np.zeros(len(y_dev))
        for fit_idx, val_idx in group_folds(meta_dev):
            oof[val_idx] = TokenModel(alpha).fit(H_dev[fit_idx], y_dev[fit_idx], w[fit_idx]).predict_proba(H_dev[val_idx])
        cal = choose_threshold_weighted(y_dev[core], oof[core], w[core])
        auc = float(roc_auc_score(y_dev[core], oof[core], sample_weight=w[core]))
        results.append({"alpha": alpha, "oof_attack_recall": round(cal["attack_recall"], 4),
                        "oof_benign_recall": round(cal["benign_recall"], 4), "oof_weighted_auc": round(auc, 4)})
        print(f"  token alpha={alpha:g} -> CORE OOF attack {cal['attack_recall']*100:.2f}% @ benign "
              f"{cal['benign_recall']*100:.2f}% (wAUC {auc:.4f}) [{time.time()-t0:.0f}s]", flush=True)
        if best is None or (cal["attack_recall"], auc) > best[0]:
            best = ((cal["attack_recall"], auc), alpha, oof)
    print(f"[*] Selected token alpha={best[1]:g}")
    return best[1], results, best[2]


def _single_request_latency_us(hybrid, X_sample, texts):
    """Latency of one request through the hybrid (token model + LightGBM), one row at a time."""
    cols = hybrid.feature_columns[:-1]
    records = X_sample[cols].to_dict("records")
    hybrid.predict_proba_frame(pd.DataFrame([records[0]]), [texts[0]])  # warm-up
    timings = []
    for rec, text in zip(records, texts):
        t = time.perf_counter()
        hybrid.predict_proba_frame(pd.DataFrame([rec]), [text])
        timings.append((time.perf_counter() - t) * 1e6)
    return {
        "p50_us": round(float(np.percentile(timings, 50)), 1),
        "p95_us": round(float(np.percentile(timings, 95)), 1),
        "n": len(timings),
    }


def main():
    X, y, hashes, integrity, meta = build_full_real_dataset()
    groups = meta["Group"].to_numpy()

    # Group-aware split stratified on label x source: no exact or near-duplicate leakage
    dev_idx, holdout_idx = split_dev_holdout(meta)

    hash_overlap = {hashes[i] for i in dev_idx} & {hashes[i] for i in holdout_idx}
    group_overlap = set(groups[dev_idx]) & set(groups[holdout_idx])
    assert not hash_overlap, f"Critical leakage! {len(hash_overlap)} hashes overlapped."
    assert not group_overlap, f"Near-duplicate leakage! {len(group_overlap)} groups overlapped."

    print(f"\n[+] Verified Zero SHA-256 and Near-Duplicate Group Overlap between "
          f"Development ({len(dev_idx)}) and Holdout ({len(holdout_idx)})")

    X_dev = X.iloc[dev_idx].reset_index(drop=True)
    X_holdout = X.iloc[holdout_idx].reset_index(drop=True)
    y_dev = y.iloc[dev_idx].reset_index(drop=True)
    y_holdout = y.iloc[holdout_idx].reset_index(drop=True)
    meta_dev = meta.iloc[dev_idx].reset_index(drop=True)
    meta_holdout = meta.iloc[holdout_idx].reset_index(drop=True)
    w_dev = meta_dev["Weight"].to_numpy()
    w_holdout = meta_holdout["Weight"].to_numpy()

    print("\n" + "="*60)
    print(" 🔧 HYPERPARAMETER SELECTION ON DEV OUT-OF-FOLD (HOLDOUT UNTOUCHED)")
    print("="*60)
    params, search_results, best_i = select_hyperparameters(X_dev, y_dev, meta_dev)
    print(f"[*] Selected: {search_results[best_i]['params']}")
    core_dev = meta_dev["Source"].isin(CORE_SOURCES).to_numpy()

    # Reference: the 36-feature LightGBM alone (same protocol), for comparison in the report
    ref_oof, _ = oof_predict(X_dev, y_dev, meta_dev, params)
    ref_cal = choose_threshold_weighted(y_dev[core_dev], ref_oof[core_dev], w_dev[core_dev])
    ref_model = lgb.LGBMClassifier(**params).fit(X_dev, y_dev, sample_weight=w_dev)

    print("\n" + "="*60)
    print(" 🔤 TOKEN (CONTENT) MODEL + STACKING, SELECTED ON DEV OUT-OF-FOLD")
    print("="*60)
    H_dev = make_vectorizer().transform(meta_dev["Text"].tolist()).tocsr()   # hashing is stateless
    H_holdout = make_vectorizer().transform(meta_holdout["Text"].tolist()).tocsr()
    token_alpha, token_search, token_oof = select_token_alpha(H_dev, y_dev.to_numpy(), meta_dev)
    token_final = TokenModel(token_alpha).fit(H_dev, y_dev.to_numpy(), w_dev)
    # Stacking: the tree model trains on OUT-OF-FOLD token scores; holdout gets the dev-fitted token model's score
    X_dev = X_dev.assign(**{TOKEN_SCORE_COLUMN: token_oof})
    X_holdout = X_holdout.assign(**{TOKEN_SCORE_COLUMN: token_final.predict_proba(H_holdout)})
    feature_columns = list(X_dev.columns)

    # Threshold: calibrated once on the stacked model's pooled OOF probabilities (CORE sources)
    oof_probs, fold_of = oof_predict(X_dev, y_dev, meta_dev, params)
    calib = choose_threshold_weighted(y_dev[core_dev], oof_probs[core_dev], w_dev[core_dev])
    threshold = calib["threshold"]
    oof_preds = (oof_probs >= threshold).astype(int)
    oof_all = weighted_recalls(y_dev, oof_preds, w_dev)
    cv_folds = []
    for fold in range(1, N_SPLITS + 1):
        sel = (fold_of == fold) & core_dev
        r = weighted_recalls(y_dev.to_numpy()[sel], oof_preds[sel], w_dev[sel])
        cv_folds.append({"fold": fold, **r})
        print(f"  Fold {fold} @ OOF threshold: Benign {r['benign_recall']*100:.2f}% ({r['benign_shapes']:.0f} shapes) | "
              f"Attack {r['attack_recall']*100:.2f}% ({r['attack_shapes']:.0f} shapes)")
    cv_attack = [f["attack_recall"] for f in cv_folds]
    cv_benign = [f["benign_recall"] for f in cv_folds]
    print(f"\n[*] OOF Calibrated Threshold: {threshold:.4f} ({calib['status']})")
    print(f"    - OOF Benign Recall: {calib['benign_recall']*100:.2f}% (Safety Gate >= 98.5%) ± {np.std(cv_benign)*100:.2f}% across folds")
    print(f"    - OOF Attack Recall: {calib['attack_recall']*100:.2f}% (Target >= 85%) ± {np.std(cv_attack)*100:.2f}% across folds")
    print(f"    - (all sources at this threshold: benign {oof_all['benign_recall']*100:.2f}%, attack {oof_all['attack_recall']*100:.2f}%)")

    # Fit final model on entire Development set
    print("\n" + "="*60)
    print(" 🎯 FINAL MODEL EVALUATION ON UNSEEN HOLDOUT SET (EVALUATED ONCE)")
    print("="*60)

    final_model = lgb.LGBMClassifier(**params)
    t0 = time.time()
    final_model.fit(X_dev, y_dev, sample_weight=w_dev)
    fit_time = time.time() - t0

    hybrid = Gen3HybridModel(token_final, final_model, feature_columns, threshold)
    t1 = time.time()
    holdout_probs = final_model.predict_proba(X_holdout)[:, 1]
    batch_us = (time.time() - t1) / len(X_holdout) * 1e6
    lat_idx = np.random.default_rng(RANDOM_STATE).choice(len(X_holdout), size=min(500, len(X_holdout)), replace=False)
    single = _single_request_latency_us(hybrid, X_holdout.iloc[lat_idx], meta_holdout["Text"].iloc[lat_idx].tolist())
    ref_probs = ref_model.predict_proba(X_holdout[EXTENDED_FEATURE_COLUMNS])[:, 1]

    holdout_preds = (holdout_probs >= threshold).astype(int)
    # Headline gate on CORE sources; all-source numbers are reported alongside
    core_h = meta_holdout["Source"].isin(CORE_SOURCES).to_numpy()
    yh, ph, wh, prh = y_holdout.to_numpy(), holdout_probs, w_holdout, holdout_preds
    overall = weighted_recalls(yh[core_h], prh[core_h], wh[core_h])
    overall_all = weighted_recalls(yh, prh, wh)
    tn, fp, fn, tp = confusion_matrix(yh[core_h], prh[core_h]).ravel()
    auc = float(roc_auc_score(yh[core_h], ph[core_h], sample_weight=wh[core_h]))
    auc_all = float(roc_auc_score(yh, ph, sample_weight=wh))
    acc = float(np.sum(wh[core_h] * (prh[core_h] == yh[core_h])) / wh[core_h].sum())
    b_rec, a_rec = overall["benign_recall"], overall["attack_recall"]

    per_source = {s: weighted_recalls(y_holdout.to_numpy()[idx], holdout_preds[idx], w_holdout[idx])
                  for s, idx in meta_holdout.groupby("Source").indices.items()}
    attack_mask = (y_holdout == 1).to_numpy()
    per_family = {}
    for fam, idx in meta_holdout[attack_mask].groupby("Family").indices.items():
        rows = np.flatnonzero(attack_mask)[idx]
        per_family[fam] = {"rows": len(rows), "attack_recall_rows": round(float(holdout_preds[rows].mean()), 4)}
    # Enforcement bands from ML_ENFORCEMENT_PLAN.md (challenge >= 0.70, block >= 0.95)
    bands = {}
    for name, t in (("challenge_0.70", 0.70), ("block_0.95", 0.95)):
        r = weighted_recalls(yh[core_h], (ph[core_h] >= t).astype(int), wh[core_h])
        bands[name] = {"benign_recall": r["benign_recall"], "attack_recall": r["attack_recall"]}

    passed = bool(b_rec >= MIN_BENIGN_RECALL and a_rec >= MIN_ATTACK_RECALL)
    verdict = "PASSED ALL SAFETY & ACCURACY GATES" if passed else "BELOW GATE (experiment only, do not promote)"

    print(f" Headline = CORE sources ({', '.join(sorted(CORE_SOURCES))}).")
    print(f" Metrics are near-duplicate weighted (each distinct request shape counts once); raw row recall in brackets.")
    print(f" ⭐ ACCURACY SCORE:    {acc*100:.2f}%")
    print(f" ⭐ ROC-AUC SCORE:     {auc:.4f} (all sources {auc_all:.4f})")
    print(f" All sources @ same threshold: benign {overall_all['benign_recall']*100:.2f}% / attack {overall_all['attack_recall']*100:.2f}%")
    print(f" ⭐ LATENCY:           single-request p50 {single['p50_us']:.0f} µs / p95 {single['p95_us']:.0f} µs "
          f"(batch-amortised {batch_us:.2f} µs)")
    print(f" Benign Recall:       {b_rec*100:.2f}% [rows {overall['benign_recall_rows']*100:.2f}%] (Requirement >= 98.5% -> {'PASSED' if b_rec>=MIN_BENIGN_RECALL else 'FAILED'})")
    print(f" Attack Recall:       {a_rec*100:.2f}% [rows {overall['attack_recall_rows']*100:.2f}%] (Target >= 85% -> {'PASSED' if a_rec>=MIN_ATTACK_RECALL else 'BELOW TARGET'})")
    print(f" Confusion Matrix:    TN={tn}, FP={fp}, FN={fn}, TP={tp} (rows)")
    print(f" Enforcement bands:   {bands}")
    print(" Per-source:")
    for s, v in per_source.items():
        print(f"   {s:32s} benign {v['benign_recall']} ({v['benign_shapes']} shapes) | attack {v['attack_recall']} ({v['attack_shapes']} shapes)")
    print(" Per-attack-family recall (rows):")
    for f_, v in sorted(per_family.items(), key=lambda kv: -kv[1]["rows"]):
        print(f"   {f_:32s} {v}")
    print(f" Final Status:        {verdict}")
    print("="*60 + "\n")

    # Feature Importance
    importances = final_model.feature_importances_
    feat_imp = {col: int(imp) for col, imp in sorted(zip(feature_columns, importances), key=lambda x: x[1], reverse=True)}
    ref_pred = (ref_probs >= ref_cal["threshold"]).astype(int)
    reference_36 = {
        "note": "same LightGBM params on the 36 structural features only, own CORE OOF threshold",
        "oof_core": {"threshold": round(ref_cal["threshold"], 4), "attack_recall": round(ref_cal["attack_recall"], 4),
                     "benign_recall": round(ref_cal["benign_recall"], 4)},
        "holdout_core": weighted_recalls(yh[core_h], ref_pred[core_h], wh[core_h]),
        "holdout_core_auc": round(float(roc_auc_score(yh[core_h], ref_probs[core_h], sample_weight=wh[core_h])), 4),
    }
    print(f" Reference (36 features, no token model): holdout CORE benign {reference_36['holdout_core']['benign_recall']*100:.2f}% / "
          f"attack {reference_36['holdout_core']['attack_recall']*100:.2f}%")

    # Save scientific experiment archive
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    candidate_dir = os.path.join(ARCHIVE_DIR, f"task3-1-real-augmented-candidate-{timestamp}")
    os.makedirs(candidate_dir, exist_ok=True)

    model_path = os.path.join(candidate_dir, "hybrid_waf_model.joblib")
    report_path = os.path.join(candidate_dir, "experiment_report.json")
    manifest_path = os.path.join(candidate_dir, "dataset_manifest.json")

    joblib.dump(hybrid, model_path)
    shutil.copy2(os.path.abspath(__file__), os.path.join(candidate_dir, "train_script_snapshot.py"))

    input_files = [CSIC_PATH, VPS_AUDIT_PATH, NGINX_BENIGN_PATH, *EXTERNAL_SOURCES.values()] + sorted(
        glob.glob(os.path.join(TELEMETRY_DIR, "*.jsonl"))
    )
    manifest = {
        "dataset_version": f"gen3-conservative-{timestamp}",
        "input_files": {os.path.relpath(p, ML_DIR): {"sha256": _sha256_file(p), "bytes": os.path.getsize(p)}
                        for p in input_files if os.path.exists(p)},
        "data_integrity": integrity,
        "split_rule": {
            "method": "group-level StratifiedKFold over near-duplicate groups (stratified on label x source), first fold as holdout (~20% of distinct shapes)",
            "group_key": "path + sorted param names + value shape (digits -> 0, mixed alnum tokens >= 6 chars -> T); method excluded",
            "weighting": "1 / size of (group, label): each distinct request shape counts once",
            "random_state": RANDOM_STATE,
            "dev_rows": int(len(dev_idx)),
            "holdout_rows": int(len(holdout_idx)),
            "sha256_overlap": 0,
            "group_overlap": 0,
        },
        "train_script_sha256": _sha256_file(os.path.abspath(__file__)),
        "feature_engineering_sha256": _sha256_file(os.path.join(ML_DIR, "feature_engineering.py")),
        "environment": {"python": platform.python_version(), "lightgbm": lgb.__version__},
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    report_data = {
        "experiment": "Task 3.1 & 2.3 Real-World Training (conservative labels, near-duplicate weighted group split)",
        "timestamp": timestamp,
        "data_integrity": integrity,
        "metric_definition": "near-duplicate weighted recall: each distinct request shape counts once; *_rows fields are raw per-row recall",
        "hyperparameter_search": {
            "method": "grid on dev pooled OOF, objective = weighted attack recall at weighted benign recall >= 98.5%",
            "results": search_results,
            "selected_index": best_i,
        },
        "cv": {
            "method": "5-fold group-level StratifiedKFold (label x source) on dev set; threshold from pooled out-of-fold probabilities of CORE sources",
            "threshold": round(threshold, 4),
            "calibration_status": calib["status"],
            "oof_benign_recall": round(calib["benign_recall"], 4),
            "oof_attack_recall": round(calib["attack_recall"], 4),
            "oof_all_sources_at_threshold": oof_all,
            "folds_at_oof_threshold": cv_folds,
            "std_attack_recall_across_folds": round(float(np.std(cv_attack)), 4),
            "std_benign_recall_across_folds": round(float(np.std(cv_benign)), 4),
        },
        "holdout_evaluation": {
            "threshold": round(threshold, 4),
            "threshold_source": "pooled out-of-fold calibration on CORE dev sources; holdout never used for tuning",
            "headline_population": sorted(CORE_SOURCES),
            "all_sources_at_threshold": overall_all,
            "roc_auc_all_sources": round(auc_all, 4),
            "accuracy": round(acc, 4),
            "roc_auc": round(auc, 4),
            "benign_recall": b_rec,
            "attack_recall": a_rec,
            "benign_recall_rows": overall["benign_recall_rows"],
            "attack_recall_rows": overall["attack_recall_rows"],
            "confusion_matrix_rows": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "enforcement_bands": bands,
            "per_source": per_source,
            "per_attack_family": per_family,
            "latency": {"single_request": single, "batch_amortised_us": round(batch_us, 2)},
            "fit_time_s": round(fit_time, 2),
            "passed_safety_gate": passed,
            "verdict": verdict,
        },
        "model_type": "Gen3HybridModel (ml/hybrid_model.py): token model stacked under LightGBM",
        "token_model": {"alpha": token_alpha, "search": token_search, "token_pattern": "see ml/hybrid_model.py TOKEN_PATTERN",
                        "ngram_range": [1, 2], "hash_features": 2 ** 20},
        "reference_lightgbm_36": reference_36,
        "feature_columns": feature_columns,
        "feature_importances": feat_imp,
        "hyperparameters": {k: v for k, v in params.items() if k != "class_weight"} |
                           {"class_weight": {str(k): v for k, v in params["class_weight"].items()}},
        "candidate_model_path": os.path.relpath(model_path, ML_DIR),
        "dataset_manifest": os.path.relpath(manifest_path, ML_DIR),
    }

    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)

    print(f"\n[✔] Candidate Model Saved to: {model_path}")
    print(f"[✔] Full Evaluation Report Saved to: {report_path}")
    print(f"[✔] Dataset Manifest Saved to: {manifest_path}\n")


if __name__ == "__main__":
    main()
