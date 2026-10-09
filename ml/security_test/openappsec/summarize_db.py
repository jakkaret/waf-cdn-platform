"""Rates per WAF from the open-appsec tool's DuckDB, the way its report computes them.

The tool drops requests with status 0 (timeouts / connection errors) from both
rates (report/data_loader.py: WHERE response_status_code != 0), so this also
prints how many were dropped: a large count means the run is not trustworthy.

    python summarize_db.py <results>/db/waf_comparison.duckdb

Rule-proposal ablation (needs numpy and ml/security_test/openappsec/split.py; run from the repo venv):

    python summarize_db.py <db> --half eval --baseline CRS-3.3.8 [--json out.json]

  --half eval      count only the eval half (rules were proposed and backtested on the gen half)
  --baseline NAME  per WAF: TPR / FPR change against NAME on the requests both answered (status != 0),
                   with a 95% bootstrap CI that resamples websites (legitimate) and payload groups
                   (malicious), paired; plus TPR per attack type
"""
import argparse
import json
import os
import sys

import duckdb


def plain_rates(con):
    rows = con.execute('''
        SELECT "WAF_Name", "DataSetType",
               COUNT(*)                                                         AS sent,
               SUM(CASE WHEN response_status_code = 0 THEN 1 ELSE 0 END)        AS dropped_status0,
               SUM(CASE WHEN response_status_code != 0 AND "isBlocked" = 1 THEN 1 ELSE 0 END) AS blocked,
               SUM(CASE WHEN response_status_code != 0 THEN 1 ELSE 0 END)       AS counted
        FROM waf_comparison GROUP BY 1, 2 ORDER BY 1, 2''').fetchall()

    per = {}
    for waf, kind, sent, dropped, blocked, counted in rows:
        rate = blocked / counted * 100 if counted else float("nan")
        per.setdefault(waf, {})[kind] = rate
        print(f"{waf:28s} {kind:10s} sent {sent:8d}  dropped(status 0) {dropped:6d}  blocked {blocked:8d}/{counted:<8d} {rate:7.3f}%")

    print()
    print(f"{'WAF':28s} {'TPR':>8s} {'FPR':>8s} {'Balanced':>9s}")
    for waf, r in per.items():
        tpr, fpr = r.get("Malicious", float("nan")), r.get("Legitimate", float("nan"))
        print(f"{waf:28s} {tpr:7.3f}% {fpr:7.3f}% {(tpr + 100 - fpr) / 2:8.3f}%")


def ablation(con, half, baseline, n_boot=2000, seed=42):
    import numpy as np

    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
    from ml.security_test.openappsec.split import add_halves

    # bodies only where the split needs them (malicious payload groups), from one WAF's rows:
    # the request set is the same for every WAF, and legitimate bodies run to GBs over 5 WAFs
    first = con.execute('SELECT min("WAF_Name") FROM waf_comparison').fetchone()[0]
    keys = con.execute('''SELECT "DataSetType", "TestName", "TestId", url,
                                 CASE WHEN "DataSetType" = 'Malicious' THEN data ELSE '' END AS data
                          FROM waf_comparison WHERE "WAF_Name" = ?''', [first]).df()
    keys = add_halves(keys)[["DataSetType", "TestName", "TestId", "group", "half"]]
    df = con.execute('''SELECT "WAF_Name", "DataSetType", "TestName", "TestId",
                               response_status_code != 0 AS answered, coalesce("isBlocked", false) AS blocked
                        FROM waf_comparison''').df().merge(keys, on=["DataSetType", "TestName", "TestId"])
    if half:
        df = df[df.half == half]
    wafs = sorted(df.WAF_Name.unique())
    if baseline not in wafs:
        raise SystemExit(f"baseline {baseline!r} not in this DB: {wafs}")
    base = df[df.WAF_Name == baseline].set_index(["DataSetType", "TestName", "TestId"])
    rng = np.random.default_rng(seed)
    report = {"half": half or "all", "baseline": baseline, "wafs": {}}

    print(f"\n== {half or 'all'} half, baseline {baseline} (paired on requests both answered; 95% bootstrap CI)")
    print(f"{'WAF':40s} {'TPR':>7s} {'FPR':>7s} {'Bal':>7s} {'dTPR [95% CI]':>24s} {'dFPR [95% CI]':>24s} {'status0':>8s}")
    for waf in wafs:
        w = df[df.WAF_Name == waf]
        r = {"status0": int((~w.answered).sum())}
        for kind in ("Malicious", "Legitimate"):
            a = w[(w.DataSetType == kind) & w.answered]
            r["tpr" if kind == "Malicious" else "fpr"] = float(a.blocked.mean())
        r["balanced"] = (r["tpr"] + 1 - r["fpr"]) / 2
        j = w.set_index(["DataSetType", "TestName", "TestId"]).join(base[["answered", "blocked"]], rsuffix="_base")
        j = j[j.answered & j.answered_base].reset_index()
        for kind, name in (("Malicious", "d_tpr"), ("Legitimate", "d_fpr")):
            g = j[j.DataSetType == kind].groupby("group").agg(n=("blocked", "size"), b=("blocked", "sum"),
                                                               b0=("blocked_base", "sum"))
            n, d = g.n.to_numpy(float), (g.b - g.b0).to_numpy(float)
            idx = rng.integers(0, len(g), size=(n_boot, len(g)))
            boot = d[idx].sum(1) / n[idx].sum(1)
            r[name] = {"value": float(d.sum() / n.sum()), "ci95": [float(np.percentile(boot, 2.5)), float(np.percentile(boot, 97.5))],
                       "paired_requests": int(n.sum()), "groups": int(len(g))}
        mal = w[(w.DataSetType == "Malicious") & w.answered]
        r["tpr_by_attack"] = {k: float(v) for k, v in mal.groupby("TestName").blocked.mean().items()}
        report["wafs"][waf] = r
        ci = lambda x: f"{x['value'] * 100:+6.2f} [{x['ci95'][0] * 100:+6.2f},{x['ci95'][1] * 100:+6.2f}]"  # noqa: E731
        print(f"{waf:40s} {r['tpr']:7.2%} {r['fpr']:7.2%} {r['balanced']:7.2%} {ci(r['d_tpr']):>24s} {ci(r['d_fpr']):>24s} {r['status0']:8d}")

    attacks = sorted({a for r in report["wafs"].values() for a in r["tpr_by_attack"]})
    print(f"\nTPR by attack type\n{'WAF':40s} " + " ".join(f"{a:>10s}" for a in attacks))
    for waf, r in report["wafs"].items():
        print(f"{waf:40s} " + " ".join(f"{r['tpr_by_attack'].get(a, float('nan')):10.2%}" for a in attacks))
    return report


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("db")
    ap.add_argument("--half", choices=["gen", "eval"])
    ap.add_argument("--baseline", help="WAF name to compare every other WAF against")
    ap.add_argument("--json", help="write the --baseline report here")
    args = ap.parse_args()
    con = duckdb.connect(args.db, read_only=True)
    plain_rates(con)
    if args.baseline:
        report = ablation(con, args.half, args.baseline)
        if args.json:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)


if __name__ == "__main__":
    main()
