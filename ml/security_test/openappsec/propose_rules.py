#!/usr/bin/env python3
"""Propose ModSecurity rules from the "gen" half of the open-appsec benchmark, the way each generator would.

Part 2.2 of the rule-proposal plan. Two generators:

  RF-rules    what production does today: the RandomForest flags a request (attack probability
              > 0.5, ml_api.py /predict), then ml/auto_rule_generator.generate_pending_rule() turns
              it into a SecRule (7 fixed regexes, else a literal of the first 40 characters).
  Gen3-rules  Gen3 (no-OpenAppSec model, card threshold) flags a request, and the value-level
              detector that fired on one of its units (ml/value_features.unit_hits) becomes the
              rule: @detectSQLi / @detectXSS, or the detector's own regex, on ARGS|ARGS_NAMES|
              REQUEST_FILENAME with decoding transforms. Never scoped to a parameter name: every
              malicious request of this dataset sits in `p` on `/`, so a name-scoped rule would
              score well here and mean nothing elsewhere.

What the ML sees (--view): production's log analyzer reads the nginx access log, which holds the
request line (method + path + query) and no body (nginx.conf.template `json_combined`; the edge
`cdn_json` log has $uri only, not even the query). "url" (default) reproduces that; "url+body"
shows what logging the body would add.

Output (<out>/):
  rf-rules-all.conf, gen3-rules-all.conf   every proposed rule after de-duplication, deny mode,
                                           ids 1000500+ (RF) / 1100000+ (Gen3)
  rf-rules.json, gen3-rules.json           per rule: id, rule text, how many gen-half requests
                                           proposed it (legitimate / malicious), examples
  proposal_summary.json

    .venv/bin/python ml/security_test/openappsec/propose_rules.py --requests-db ~/waf-bench/results/offline/requests.duckdb
"""

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from urllib.parse import urlsplit

import duckdb
import numpy as np
import pandas as pd

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, REPO)

from ml.auto_rule_generator import assert_secrule_safe, generate_pending_rule  # noqa: E402
from ml.canonical import canonical_request  # noqa: E402
from ml.feature_engineering import (  # noqa: E402
    RESTRICTED_FILE_PATTERN, extract_features_from_request, feature_columns_for_model,
)
from ml.hybrid_model import request_units  # noqa: E402
from ml.security_test.openappsec.score_offline import RF_BODY_CAP  # noqa: E402
from ml.security_test.openappsec.split import GEN, half_of  # noqa: E402
from ml.value_features import DETECTORS, normalize_unit, unit_hits  # noqa: E402

RF_PATH = os.path.join(REPO, "ml", "models", "random_forest_waf.joblib")
GEN3_PATH = os.path.join(REPO, "ml", "models", "gen3", "gen3_f_noopenappsec.onnx")
RF_THRESHOLD = 0.5
RF_FIRST_ID, GEN3_FIRST_ID = 1000500, 1100000

GEN3_VARIABLES = "ARGS|ARGS_NAMES|REQUEST_FILENAME"
# Mirrors ml/value_features.normalize_unit: URL decoding (ModSecurity already decoded ARGS once),
# HTML entities, \xHH / \uXXXX escapes, lowercase, null bytes dropped.
GEN3_TRANSFORMS = "t:none,t:urlDecodeUni,t:htmlEntityDecode,t:jsDecode,t:lowercase,t:removeNulls"
GEN3_OPERATORS = {
    "v_sqli_libinjection": "@detectSQLi",
    "v_xss_libinjection": "@detectXSS",
    **{name: f"@rx {pattern.pattern}" for name, pattern in DETECTORS.items()},
    "v_restricted_file": f"@rx {RESTRICTED_FILE_PATTERN.pattern}",
}


def gen3_rule_text(rule_id, detector):
    operator = GEN3_OPERATORS[detector]
    assert_secrule_safe(operator)
    return (f'SecRule {GEN3_VARIABLES} "{operator}" \\\n'
            f'    "id:{rule_id},phase:2,deny,status:403,log,severity:CRITICAL,\\\n'
            f'    {GEN3_TRANSFORMS},\\\n'
            f"    msg:'ML proposed rule (Gen3-rules): {detector}'\"")


def detectors_fired(method, url, body):
    """Detector names that fired on any unit of the request, as Gen3 computes its value features."""
    parts = urlsplit(url)
    path, query, body = canonical_request(parts.path or "/", parts.query, body)
    texts = [normalize_unit(str(path).lower())[0]]
    texts += [normalize_unit(u)[0] for u in request_units(method, path, query, body)]
    fired = set()
    for text in texts:
        fired.update(name for name, hit in unit_hits(text).items() if hit)
    return fired


def load_gen_half(requests_db, view):
    """Gen-half requests with the body the ML would see under `view` (no legitimate body is loaded for "url")."""
    con = duckdb.connect(requests_db, read_only=True)
    body_sql = "data" if view == "url+body" else "CASE WHEN \"DataSetType\" = 'Malicious' THEN data ELSE '' END"
    df = con.execute(f'''SELECT rid, "DataSetType", "TestName", coalesce(method, 'GET') AS method,
                                coalesce(url, '/') AS dataset_url, wire_url AS url, coalesce({body_sql}, '') AS data
                         FROM requests ORDER BY rid''').df()
    con.close()
    # the split uses the dataset URL (as summarize_db.py does) and the malicious body (payload
    # grouping); legitimate requests split by site. Everything else uses the URL as sent (wire_url).
    df["half"] = [half_of(t, n, u, b) for t, n, u, b in zip(df.DataSetType, df.TestName, df.dataset_url, df.data)]
    df = df[df.half == GEN].reset_index(drop=True)
    df["seen_body"] = df["data"] if view == "url+body" else ""
    return df


def score_view(df, gen3_path):
    import joblib

    from ml.gen3_onnx import Gen3OnnxModel

    rf = joblib.load(RF_PATH)  # pickle committed to the repo, the same artifact ml_api.py loads
    cols = feature_columns_for_model(rf)
    gen3 = Gen3OnnxModel(gen3_path)
    rows = list(zip(df.method, df.url, df.seen_body))
    # same body cap as score_offline.py (RF extraction is superlinear in body size)
    feats = [extract_features_from_request(url=u, method=m, body=b[:RF_BODY_CAP]) for m, u, b in rows]
    rf_score = rf.predict_proba(pd.DataFrame(feats)[cols])[:, 1]
    gen3_score = np.array([gen3.score_request(m, u, b) for m, u, b in rows])
    return rf_score, gen3_score, gen3.threshold


class Proposals:
    """Proposed rules keyed by their de-duplication key, with the gen-half requests behind each."""

    def __init__(self):
        self.by_key = {}
        self.stats = defaultdict(lambda: {"legitimate": 0, "malicious": 0, "examples": []})

    def add(self, key, text_fn, row):
        if key not in self.by_key:
            self.by_key[key] = text_fn
        s = self.stats[key]
        s["legitimate" if row.DataSetType == "Legitimate" else "malicious"] += 1
        if len(s["examples"]) < 3:
            s["examples"].append({"rid": int(row.rid), "label": row.DataSetType, "method": row.method,
                                  "url": row.url[:200], "body": row.seen_body[:200]})

    def write(self, out_dir, name, first_id):
        rules, conf = [], [f"# {name}: rules proposed from the gen half (deny mode). Generated by propose_rules.py\n"]
        for n, key in enumerate(sorted(self.by_key, key=lambda k: -sum(self.stats[k][x] for x in ("legitimate", "malicious")))):
            rule_id = first_id + n
            text = self.by_key[key](rule_id)
            conf.append(text + "\n")
            rules.append({"id": rule_id, "key": key, "rule": text, "proposed_by": dict(self.stats[key])})
        with open(os.path.join(out_dir, f"{name}-all.conf"), "w", encoding="utf-8") as f:
            f.write("\n".join(conf))
        with open(os.path.join(out_dir, f"{name}.json"), "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=1, ensure_ascii=False)
        return rules


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--requests-db", default=os.path.expanduser("~/waf-bench/results/offline/requests.duckdb"))
    ap.add_argument("--out", default=os.path.expanduser("~/waf-bench/results/rules"))
    ap.add_argument("--view", choices=["url", "url+body"], default="url")
    ap.add_argument("--gen3", default=GEN3_PATH)
    args = ap.parse_args()
    out = os.path.join(args.out, args.view.replace("+", "_"))
    os.makedirs(out, exist_ok=True)

    t0 = time.time()
    df = load_gen_half(args.requests_db, args.view)
    print(f"[*] gen half: {len(df):,} requests ({(df.DataSetType == 'Legitimate').sum():,} legitimate / "
          f"{(df.DataSetType == 'Malicious').sum():,} malicious), view={args.view}")
    df["rf_score"], df["gen3_score"], gen3_thr = score_view(df, args.gen3)
    print(f"[*] scored [{time.time() - t0:.0f}s]")

    rf_rules, gen3_rules = Proposals(), Proposals()
    rf_flagged = df[df.rf_score > RF_THRESHOLD]
    unsafe = 0
    for row in rf_flagged.itertuples():
        try:
            rule = generate_pending_rule(row.url, row.method, row.seen_body, attack_type="Anomaly Pattern")
        except ValueError:
            unsafe += 1  # ml_api.py /generate-rule now refuses these (422)
            continue
        rf_rules.add(rule["pattern"], lambda rid, t=rule["secrule_template"]: t.replace("{RULE_ID}", str(rid)), row)

    gen3_flagged = df[df.gen3_score >= gen3_thr]
    no_detector = 0
    for row in gen3_flagged.itertuples():
        fired = detectors_fired(row.method, row.url, row.seen_body)
        if not fired:
            no_detector += 1  # flagged by the model's structural features alone: nothing to turn into a rule
        for detector in sorted(fired):
            gen3_rules.add(detector, lambda rid, d=detector: gen3_rule_text(rid, d), row)

    summary = {"view": args.view, "requests_db": args.requests_db, "gen3_threshold": gen3_thr, "rf_threshold": RF_THRESHOLD,
               "gen_half": {"legitimate": int((df.DataSetType == "Legitimate").sum()),
                            "malicious": int((df.DataSetType == "Malicious").sum())}}
    for name, flagged, props, first_id, extra in [
        ("rf-rules", rf_flagged, rf_rules, RF_FIRST_ID, {"refused_unsafe_pattern": unsafe}),
        ("gen3-rules", gen3_flagged, gen3_rules, GEN3_FIRST_ID, {"flagged_without_detector": no_detector}),
    ]:
        rules = props.write(out, name, first_id)
        summary[name] = {
            "flagged_requests": {"legitimate": int((flagged.DataSetType == "Legitimate").sum()),
                                 "malicious": int((flagged.DataSetType == "Malicious").sum())},
            # production creates one pending rule per flagged request (dashboard/backend/api/ml.py)
            "pending_rules_before_dedup": int(len(flagged)) - extra.get("refused_unsafe_pattern", 0),
            "rules_after_dedup": len(rules),
            "rules_proposed_only_by_legitimate": sum(1 for r in rules if r["proposed_by"]["malicious"] == 0),
            **extra,
        }
    with open(os.path.join(out, "proposal_summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)
    print(json.dumps({k: summary[k] for k in ("rf-rules", "gen3-rules")}, indent=2))
    print(f"[✔] {out} [{time.time() - t0:.0f}s]")


if __name__ == "__main__":
    main()
