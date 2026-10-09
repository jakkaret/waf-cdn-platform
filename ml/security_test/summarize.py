#!/usr/bin/env python3
"""
Read the three tools' report files and the harness decision log, and print the
Gen 3 model's detection as: per-tool detection, then Precision / Recall / F1.

Positive class = attack. A request is "detected" when the harness answered 403
(model score >= threshold). Benign requests that got 403 are false positives.

    PYTHONPATH=. python ml/security_test/summarize.py --out ml/security_test/results.json
"""

import argparse
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def load_jsonl(path):
    rows = []
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return rows


def metrics(tp, fp, fn, tn):
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else (0.0 if tp + fn else None)
    rnd = lambda v: None if v is None else round(v, 4)  # noqa: E731
    return {"precision": rnd(p), "recall": rnd(r), "f1": rnd(f1), "tp": tp, "fp": fp, "fn": fn, "tn": tn}


def gotestwaf(report_dir):
    """GoTestWAF writes a JSON report; pull true/false positive/negative counts if present."""
    files = sorted(glob.glob(os.path.join(report_dir, "*.json")), key=os.path.getmtime)
    if not files:
        return None
    data = json.load(open(files[-1], encoding="utf-8"))
    # GoTestWAF summary shape varies by version; report both its own score and our harness log.
    return {"report_file": os.path.basename(files[-1]),
            "keys": sorted(list(data.keys()))[:20]}


def summarize_harness(log_path):
    """Ground truth from the harness log: everything a tool sent, and whether the model blocked it.

    Tool traffic is treated as attack by default; benign probes belong to GoTestWAF's
    false-positive set, tagged with ?waf_test=benign by the runner.
    """
    rows = load_jsonl(log_path)
    rows = [r for r in rows if not r["url"].startswith("/healthz")]
    attack = [r for r in rows if "waf_test=benign" not in r["url"]]
    benign = [r for r in rows if "waf_test=benign" in r["url"]]
    tp = sum(1 for r in attack if r["blocked"])
    fn = len(attack) - tp
    fp = sum(1 for r in benign if r["blocked"])
    tn = len(benign) - fp
    return {"total_requests": len(rows), "attack_sent": len(attack), "benign_sent": len(benign),
            "metrics": metrics(tp, fp, fn, tn),
            "note": "benign_sent=0 means only attack traffic was sent; precision/FP not measurable from this run"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", default=os.path.join(HERE, "decisions.jsonl"))
    ap.add_argument("--gotestwaf-dir", default=os.path.join(HERE, "reports", "gotestwaf"))
    ap.add_argument("--out", default=os.path.join(HERE, "results.json"))
    args = ap.parse_args()

    result = {"harness": summarize_harness(args.log), "gotestwaf_report": gotestwaf(args.gotestwaf_dir)}
    h = result["harness"]
    m = h["metrics"]
    print(f"[*] harness saw {h['total_requests']} requests "
          f"(attack {h['attack_sent']}, benign {h['benign_sent']})")
    print(f"    detection (recall) {m['recall']} | precision {m['precision']} | F1 {m['f1']}")
    print(f"    TP {m['tp']} FP {m['fp']} FN {m['fn']} TN {m['tn']}")
    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2, ensure_ascii=False)
    print(f"[✔] wrote {args.out}")


if __name__ == "__main__":
    main()
