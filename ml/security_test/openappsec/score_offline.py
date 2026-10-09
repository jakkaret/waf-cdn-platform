#!/usr/bin/env python3
"""Score every open-appsec benchmark request offline with RF and Gen3, and measure both models.

Part 1 of the rule-proposal plan (ml/security_test/BENCHMARK_PLAN_OPENAPPSEC.md, "ML rule proposal"):
how good are the two models on this dataset before any WAF is involved?

  RF    ml/models/random_forest_waf.joblib, scored as ml_api.py /predict does
  Gen3  ml/models/gen3/gen3_f_noopenappsec.onnx (no OpenAppSec in its training data)

Input is the tool's DuckDB, so the request set is exactly the one the tool sent (same --fast
sample). Outputs (keys DataSetType, TestName, TestId join later runs of the same sample):

  <out>/requests.duckdb  table `requests` (rid, labels, method, url, wire_url, data, headers): the request
                         set, kept because the tool wipes its DB on every --fresh-run; table
                         `scores` (rid, labels, rf_score, gen3_score)
  <out>/scores.parquet   the `scores` table
  <out>/offline_metrics.json + a printed table

If the DuckDB holds a Gen3-only system (D_ML-only@card / Gen3@...), its 403 decisions are
compared with the offline Gen3 scores at the same threshold: they must agree on every request
the tool did not drop (status 0), or the offline scoring is not what the harness served.

    .venv/bin/python ml/security_test/openappsec/score_offline.py \
        --db ~/waf-bench/results/db/waf_comparison.duckdb --out ~/waf-bench/results/offline
"""

import argparse
import json
import os
import sys
import time
from multiprocessing import Pool

import duckdb
import numpy as np
import pandas as pd
from sklearn.metrics import roc_auc_score, roc_curve

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
sys.path.insert(0, REPO)

RF_PATH = os.path.join(REPO, "ml", "models", "random_forest_waf.joblib")
GEN3_PATH = os.path.join(REPO, "ml", "models", "gen3", "gen3_f_noopenappsec.onnx")
RF_THRESHOLD = 0.5  # ml_api.py: is_anomaly = rf_pred == 1 or attack_prob > 0.5
# RF feature extraction is superlinear in body size (10 KB 0.006 s, 100 KB 0.25 s; the sample has
# bodies up to 53 MB, hours each). Production RF never sees a body (the nginx access log has none),
# so RF scores the first RF_BODY_CAP characters; the count is in offline_metrics.json. Gen3 caps its
# units itself and scores the full body.
RF_BODY_CAP = 65536
KEY = ["DataSetType", "TestName", "TestId"]

_rf = _gen3 = None


def _init_worker(gen3_path):
    global _rf, _gen3
    import joblib
    import onnxruntime as ort

    import ml.gen3_onnx
    from ml.gen3_onnx import Gen3OnnxModel

    def single_thread_session(onnx_bytes):  # ml.gen3_onnx._session with one intra-op thread per worker
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = opts.inter_op_num_threads = 1
        return ort.InferenceSession(onnx_bytes, opts, providers=["CPUExecutionProvider"])

    ml.gen3_onnx._session = single_thread_session

    # joblib.load executes a pickle: this is the artifact committed to the repo, same as ml_api.py loads
    _rf = joblib.load(RF_PATH)
    if hasattr(_rf, "n_jobs"):
        _rf.n_jobs = 1  # parallelism comes from the worker processes; nested threads oversubscribe the CPU
    _gen3 = Gen3OnnxModel(gen3_path)


def _score_rows(rows):
    """[(method, url, body)] -> [(rf_score, gen3_score)]; a scoring error yields NaN, never a crash."""
    from ml.feature_engineering import extract_features_from_request, feature_columns_for_model

    cols = feature_columns_for_model(_rf)
    feats, rf = [], np.full(len(rows), np.nan)
    ok = []
    for i, (m, u, b) in enumerate(rows):
        try:
            feats.append(extract_features_from_request(url=u, method=m, body=b[:RF_BODY_CAP]))
            ok.append(i)
        except Exception:
            pass
    if feats:
        rf[ok] = _rf.predict_proba(pd.DataFrame(feats)[cols])[:, 1]
    gen3 = np.full(len(rows), np.nan)
    for i, (m, u, b) in enumerate(rows):
        try:
            gen3[i] = _gen3.score_request(method=m, url=u, body=b)
        except Exception:
            pass
    return list(zip(rf.tolist(), gen3.tolist()))


def wire_url(method, url):
    """The request target the tool actually sends for a dataset URL.

    The tool sends with requests.request() (waf-comparison-project helper.py), which requotes the
    URL: a dataset URL with an invalid escape such as %u2216 or %bg goes out with every % as %25
    (/?p=%3F%u2216 -> /?p=%253F%25u2216). Every WAF saw this form, so scoring, rule proposal and
    replay must use it, not the URL stored in the DB.
    """
    import requests

    try:
        return requests.Request(method or "GET", "http://wire" + (url or "/")).prepare().path_url
    except Exception:
        return url or "/"


def snapshot_requests(db_path, requests_db):
    """Copy the run's distinct request set (every WAF in the DB was sent the same set) to its own DuckDB.

    The tool wipes its DB on every --fresh-run, and the request bodies (~1 GB of text for a --fast
    sample) must not be loaded into one pandas frame: workers read their own slice from this file.
    Later steps (propose_rules, backtest_rules) read requests from here too.
    """
    if os.path.exists(requests_db):
        os.remove(requests_db)
    con = duckdb.connect(requests_db)
    con.execute(f"ATTACH '{db_path}' AS tool (READ_ONLY)")
    first = con.execute('SELECT min("WAF_Name") FROM tool.waf_comparison').fetchone()[0]
    con.execute('''
        CREATE TABLE requests AS
        SELECT row_number() OVER (ORDER BY "DataSetType", "TestName", "TestId") - 1 AS rid,
               "DataSetType", "TestName", "TestId", "Category", method, url, data, headers
        FROM tool.waf_comparison WHERE "WAF_Name" = ?''', [first])
    n = con.execute("SELECT count(*) FROM requests").fetchone()[0]
    con.execute("DETACH tool")
    urls = con.execute("SELECT rid, method, url FROM requests ORDER BY rid").fetchall()
    wire = pd.DataFrame({"rid": [r[0] for r in urls], "wire_url": [wire_url(m, u) for _, m, u in urls]})
    con.register("wire", wire)
    con.execute("ALTER TABLE requests ADD COLUMN wire_url VARCHAR")
    con.execute("UPDATE requests SET wire_url = wire.wire_url FROM wire WHERE requests.rid = wire.rid")
    changed = con.execute("SELECT count(*) FROM requests WHERE wire_url IS DISTINCT FROM url").fetchone()[0]
    print(f"[*] {changed:,} requests go out with a different URL than the dataset's (requests' requoting)")
    con.close()
    return n


def _score_slice(args):
    requests_db, lo, hi = args
    con = duckdb.connect(requests_db, read_only=True)
    rows = con.execute("SELECT coalesce(method, 'GET'), wire_url, coalesce(data, '') FROM requests "
                       "WHERE rid >= ? AND rid < ? ORDER BY rid", [lo, hi]).fetchall()
    con.close()
    return lo, _score_rows(rows)


def score(requests_db, n, gen3_path, workers, chunk=1000):
    """rid -> (rf_score, gen3_score) for every request, scored in worker processes."""
    slices = [(requests_db, lo, min(lo + chunk, n)) for lo in range(0, n, chunk)]
    rf, gen3 = np.full(n, np.nan), np.full(n, np.nan)
    t0 = time.time()
    with Pool(workers, initializer=_init_worker, initargs=(gen3_path,), maxtasksperchild=50) as pool:
        for done, (lo, res) in enumerate(pool.imap_unordered(_score_slice, slices), 1):
            rf[lo:lo + len(res)], gen3[lo:lo + len(res)] = zip(*res) if res else ((), ())
            if done % 10 == 0 or done == len(slices):
                print(f"  scored {done}/{len(slices)} slices [{time.time() - t0:.0f}s]", flush=True)
    return rf, gen3


def rates(y, s, thr):
    pred = s >= thr
    return {"tpr": float(pred[y == 1].mean()), "fpr": float(pred[y == 0].mean())}


def model_metrics(df, col, thr):
    d = df[df[col].notna()]
    y, s = (d["DataSetType"] == "Malicious").to_numpy().astype(int), d[col].to_numpy()
    fpr, tpr, cut = roc_curve(y, s)
    out = {
        "scored": int(len(d)), "unscored_errors": int(df[col].isna().sum()),
        "roc_auc": float(roc_auc_score(y, s)),
        # best TPR whose FPR stays within the budget; lowest FPR that reaches the TPR
        "tpr_at_fpr_1pct": float(tpr[fpr <= 0.01].max()),
        "tpr_at_fpr_5pct": float(tpr[fpr <= 0.05].max()),
        "fpr_at_tpr_90pct": float(fpr[tpr >= 0.90].min()),
        "threshold": thr, "at_threshold": rates(y, s, thr),
        "tpr_by_attack": {}, "tnr_by_site_category": {},
    }
    out["at_threshold"]["balanced"] = (out["at_threshold"]["tpr"] + 1 - out["at_threshold"]["fpr"]) / 2
    for cat, g in d[d["DataSetType"] == "Malicious"].groupby("TestName"):
        out["tpr_by_attack"][cat] = float((g[col] >= thr).mean())
    for cat, g in d[d["DataSetType"] == "Legitimate"].groupby("Category"):
        out["tnr_by_site_category"][cat] = float((g[col] < thr).mean())
    return out


def harness_agreement(con, df, thr):
    """Offline Gen3 decision vs the Gen3-only harness's 403 on the same requests (status 0 excluded)."""
    names = [r[0] for r in con.execute('SELECT DISTINCT "WAF_Name" FROM waf_comparison').fetchall()]
    ml_only = [n for n in names if n.startswith("D_ML-only") or n.startswith("Gen3@")]
    if not ml_only:
        return None
    served = con.execute('''SELECT "DataSetType", "TestName", "TestId", "isBlocked" FROM waf_comparison
                            WHERE "WAF_Name" = ? AND response_status_code != 0''', [ml_only[0]]).df()
    m = served.merge(df[KEY + ["gen3_score"]], on=KEY)
    offline = m["gen3_score"] >= thr
    disagree = m[offline != m["isBlocked"].astype(bool)]
    return {"waf_name": ml_only[0], "compared": int(len(m)), "disagree": int(len(disagree)),
            "disagree_examples": disagree.head(5)[KEY + ["gen3_score", "isBlocked"]].astype(str).to_dict("records")}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--db", default=os.path.expanduser("~/waf-bench/results/db/waf_comparison.duckdb"))
    ap.add_argument("--out", default=os.path.expanduser("~/waf-bench/results/offline"))
    ap.add_argument("--gen3", default=GEN3_PATH, help="Gen3 ONNX (must be trained without OpenAppSec)")
    ap.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)

    from ml.gen3_onnx import Gen3OnnxModel
    gen3_thr = Gen3OnnxModel(args.gen3).threshold

    requests_db = os.path.join(args.out, "requests.duckdb")
    n = snapshot_requests(args.db, requests_db)
    con = duckdb.connect(requests_db)
    df = con.execute('SELECT rid, "DataSetType", "TestName", "TestId", "Category" FROM requests ORDER BY rid').df()
    print(f"[*] {n:,} requests from {args.db} -> {requests_db} "
          f"({(df.DataSetType == 'Legitimate').sum():,} legitimate / {(df.DataSetType == 'Malicious').sum():,} malicious)")
    con.close()
    df["rf_score"], df["gen3_score"] = score(requests_db, n, args.gen3, args.workers)

    path = os.path.join(args.out, "scores.parquet")
    con = duckdb.connect(requests_db)
    con.register("scores_df", df)
    con.execute("CREATE OR REPLACE TABLE scores AS SELECT * FROM scores_df")  # joinable on rid
    con.execute(f"COPY scores TO '{path}' (FORMAT PARQUET)")
    con.close()
    con = duckdb.connect(args.db, read_only=True)

    with duckdb.connect(requests_db, read_only=True) as rcon:
        capped = rcon.execute("SELECT count(*) FROM requests WHERE length(data) > ?", [RF_BODY_CAP]).fetchone()[0]
    metrics = {
        "db": args.db, "gen3_model": os.path.relpath(args.gen3, REPO), "requests": int(len(df)),
        "rf_body_cap_chars": RF_BODY_CAP, "rf_body_truncated_requests": int(capped),
        "RF": model_metrics(df, "rf_score", RF_THRESHOLD),
        "Gen3": model_metrics(df, "gen3_score", gen3_thr),
        "gen3_vs_harness": harness_agreement(con, df, gen3_thr),
    }
    with open(os.path.join(args.out, "offline_metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)

    print(f"\n{'model':6s} {'AUC':>7s} {'TPR@FPR1%':>10s} {'TPR@FPR5%':>10s} {'FPR@TPR90%':>11s} "
          f"{'thr':>7s} {'TPR':>7s} {'FPR':>7s} {'Bal':>7s}")
    for name in ("RF", "Gen3"):
        r = metrics[name]
        a = r["at_threshold"]
        print(f"{name:6s} {r['roc_auc']:7.4f} {r['tpr_at_fpr_1pct']:10.2%} {r['tpr_at_fpr_5pct']:10.2%} "
              f"{r['fpr_at_tpr_90pct']:11.2%} {r['threshold']:7.4f} {a['tpr']:7.2%} {a['fpr']:7.2%} {a['balanced']:7.2%}")
        print("       TPR by attack: " + ", ".join(f"{k} {v:.1%}" for k, v in r["tpr_by_attack"].items()))
        if r["unscored_errors"]:
            print(f"       [!] {r['unscored_errors']} requests could not be scored (excluded)")
    h = metrics["gen3_vs_harness"]
    if h:
        print(f"\n[*] Gen3 offline vs harness ({h['waf_name']}): {h['disagree']} disagreements "
              f"of {h['compared']:,} served requests")
    print(f"\n[✔] {path}\n[✔] {os.path.join(args.out, 'offline_metrics.json')}")


if __name__ == "__main__":
    main()
