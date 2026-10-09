#!/usr/bin/env python3
"""
Promotion gate 3.1-G.0 (WAF_GEN3_ROADMAP.md), approved by the project owner on
28/09/2026 before the final candidate was evaluated. Every dataset counts the
same (macro average), so the result does not depend on how much of each public
dataset we happened to sample, and CSIC 2010 is one dataset among the others.

  G1  benign recall >= 98.5% on every dataset (holdout)             normal traffic passes
  G2  mean attack recall over datasets >= 85% (holdout)              known sites are protected
  G3  mean attack recall at 98.5% benign over datasets never seen
      in training >= 70% (leave-one-dataset-out)                     new sites are protected
  G4  no dataset below 40% attack recall in G2 or G3                 no blind spot
  G5  normal scenarios 37/37, attack scenarios >= 23/26 and
      context-transfer stress detection >= 60%                       sanity checks

Holdout numbers are the mean over the holdout folds of one report. A report
can hold folds, leave-one-dataset-out results or both; `evaluate_reports`
takes the newest usable part of each kind among reports over the same sources.

Usage: python ml/promotion_gate.py REPORT.json [REPORT.json ...] [--config NAME ...]
"""

import argparse
import json
import os
from collections import defaultdict

import numpy as np

GATE = {
    "benign_min": 0.985,
    "known_attack_mean": 0.85,
    "unseen_attack_mean": 0.70,
    "per_dataset_attack_min": 0.40,
    "scenario_normal": 37,
    "scenario_attack_min": 23,
    "stress_detect_min": 0.60,
}
# Marker of reports whose "attack at 98.5% benign" uses the exact threshold
# (the earlier 0.0005 grid read 0.0 when benign scores saturated).
EXACT_LOFO_KEY = "attack_recall_at_benign_99_9"


def dataset_of(source):
    """Dataset a source belongs to: open-appsec ships benign and attack traffic as two sources."""
    if source.startswith("OpenAppSec_"):
        return "OpenAppSec"
    if "VPS" in source:
        return "VPS"
    return source


def holdout_by_dataset(folds):
    """Per dataset: benign and attack recall on the holdout, mean over folds.

    Sources of one dataset are combined by their near-duplicate weight
    ("shapes"), exactly as if the dataset were one source.
    """
    per = defaultdict(lambda: {"benign": [], "attack": []})
    for fold in folds:
        agg = defaultdict(lambda: np.zeros(4))  # benign hits, benign shapes, attack hits, attack shapes
        for source, r in fold["holdout"]["per_source"].items():
            a = agg[dataset_of(source)]
            if r.get("benign_recall") is not None and r.get("benign_shapes"):
                a += [r["benign_recall"] * r["benign_shapes"], r["benign_shapes"], 0, 0]
            if r.get("attack_recall") is not None and r.get("attack_shapes"):
                a += [0, 0, r["attack_recall"] * r["attack_shapes"], r["attack_shapes"]]
        for d, (bh, bs, ah, ash) in agg.items():
            if bs > 0:
                per[d]["benign"].append(bh / bs)
            if ash > 0:
                per[d]["attack"].append(ah / ash)
    return {d: {k: (round(float(np.mean(v)), 4) if v else None) for k, v in m.items()} for d, m in per.items()}


def _criterion(value, target, passed, detail=None):
    return {"value": value, "target": target, "passed": passed, "detail": detail or {}}


def evaluate(folds, lofo):
    """Gate for one configuration from its holdout folds and leave-one-dataset-out results (either may be empty)."""
    g = {}
    by_ds = holdout_by_dataset(folds) if folds else {}
    benign = {d: v["benign"] for d, v in by_ds.items() if v["benign"] is not None}
    known = {d: v["attack"] for d, v in by_ds.items() if v["attack"] is not None}
    unseen = {d: r["attack_recall_at_benign_98_5"] for d, r in (lofo or {}).items()
              if EXACT_LOFO_KEY in r and r.get("attack_recall_at_benign_98_5") is not None}

    g["G1_benign_every_dataset"] = (
        _criterion(min(benign.values()), f">= {GATE['benign_min']}", min(benign.values()) >= GATE["benign_min"], benign)
        if benign else _criterion(None, f">= {GATE['benign_min']}", None))
    g["G2_known_attack_mean"] = (
        _criterion(round(float(np.mean(list(known.values()))), 4), f">= {GATE['known_attack_mean']}",
                   float(np.mean(list(known.values()))) >= GATE["known_attack_mean"], known)
        if known else _criterion(None, f">= {GATE['known_attack_mean']}", None))
    g["G3_unseen_attack_mean"] = (
        _criterion(round(float(np.mean(list(unseen.values()))), 4), f">= {GATE['unseen_attack_mean']}",
                   float(np.mean(list(unseen.values()))) >= GATE["unseen_attack_mean"], unseen)
        if unseen else _criterion(None, f">= {GATE['unseen_attack_mean']}", None))
    both = {**{f"known:{d}": v for d, v in known.items()}, **{f"unseen:{d}": v for d, v in unseen.items()}}
    g["G4_no_dataset_below"] = (
        _criterion(min(both.values()), f">= {GATE['per_dataset_attack_min']}",
                   min(both.values()) >= GATE["per_dataset_attack_min"] if known and unseen else None,
                   {min(both, key=both.get): min(both.values())})
        if both else _criterion(None, f">= {GATE['per_dataset_attack_min']}", None))
    if folds:
        normal = min(int(f["scenarios"]["normal_allowed"].split("/")[0]) for f in folds)
        attack = float(np.mean([int(f["scenarios"]["attack_blocked"].split("/")[0]) for f in folds]))
        stress = [f["stress_context_transfer"].get("detection_rate") for f in folds]
        stress = float(np.mean(stress)) if all(s is not None for s in stress) else None
        fp = [f["stress_context_transfer"].get("control_false_positive_rate") for f in folds]
        ok = (normal >= GATE["scenario_normal"] and attack >= GATE["scenario_attack_min"]
              and stress is not None and stress >= GATE["stress_detect_min"])
        g["G5_sanity"] = _criterion(
            {"scenario_normal_min": normal, "scenario_attack_mean": round(attack, 2),
             "stress_detect_mean": None if stress is None else round(stress, 4)},
            f"normal {GATE['scenario_normal']}/37, attack >= {GATE['scenario_attack_min']}/26, "
            f"stress >= {GATE['stress_detect_min']}", ok,
            {"stress_control_fp_mean": None if None in fp else round(float(np.mean(fp)), 4)})
    else:
        g["G5_sanity"] = _criterion(None, "scenarios + stress", None)

    measured = [c["passed"] for c in g.values()]
    return {"criteria": g, "complete": all(p is not None for p in measured),
            "passed": all(p is True for p in measured), "holdout_folds": len(folds or [])}


def _load(path):
    """A report in the current layout (holdout folds and/or leave-one-dataset-out), else None.

    Reports of the first 28/09 runs kept one holdout directly under each
    configuration and cannot be scored; they must not become the reference.
    """
    try:
        with open(path, encoding="utf-8") as f:
            rep = json.load(f)
    except (OSError, ValueError):
        return None
    configs = rep.get("configs")
    if not isinstance(configs, dict):
        return None
    usable = any(c.get("folds") or c.get("leave_one_dataset_out") for c in configs.values() if isinstance(c, dict))
    return rep if usable else None


def evaluate_reports(paths, configs=None):
    """Gate per configuration from one or more experiment_value_features reports.

    Only reports over the same sources and the same feature extraction as the
    newest one are combined (a report without "feature_extraction" predates the
    canonical request form); for each configuration the newest report with
    holdout folds supplies G1/G2/G5 and the newest with exact
    leave-one-dataset-out results supplies G3/G4.
    """
    reps = [(p, r) for p in sorted(paths, key=os.path.getmtime) if (r := _load(p)) is not None]
    if not reps:
        return {}
    sources, extraction = reps[-1][1].get("sources"), reps[-1][1].get("feature_extraction")
    reps = [(p, r) for p, r in reps if r.get("sources") == sources and r.get("feature_extraction") == extraction]
    names = configs or sorted({n for _, r in reps for n in r["configs"]})
    out = {}
    for name in names:
        folds_src = next(((p, r["configs"][name]["folds"]) for p, r in reversed(reps)
                          if name in r["configs"] and r["configs"][name].get("folds")), (None, []))
        lofo_src = next(((p, r["configs"][name]["leave_one_dataset_out"]) for p, r in reversed(reps)
                         if name in r["configs"] and any(EXACT_LOFO_KEY in v for v in
                                                         r["configs"][name].get("leave_one_dataset_out", {}).values())),
                        (None, {}))
        if folds_src[0] is None and lofo_src[0] is None:
            continue
        gate = evaluate(folds_src[1], lofo_src[1])
        gate["sources"] = sources
        gate["feature_extraction"] = extraction
        gate["from_reports"] = {"holdout_folds": folds_src[0], "leave_one_dataset_out": lofo_src[0]}
        out[name] = gate
    return out


def format_gate(name, gate):
    mark = {True: "PASS", False: "FAIL", None: " n/a"}
    lines = [f"== {name}: {'PASSED' if gate['passed'] else ('FAILED' if gate['complete'] else 'INCOMPLETE')} "
             f"({gate['holdout_folds']} holdout folds)"]
    for cid, c in gate["criteria"].items():
        detail = ", ".join(f"{k}={v}" for k, v in c["detail"].items())
        lines.append(f"  [{mark[c['passed']]}] {cid:26s} {str(c['value']):>40s}  target {c['target']}"
                     + (f"  | {detail}" if detail else ""))
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Evaluate promotion gate 3.1-G.0 from experiment reports")
    ap.add_argument("reports", nargs="+")
    ap.add_argument("--config", action="append", help="configuration name (repeatable); default all")
    ap.add_argument("--json", help="write the gate results to this file")
    args = ap.parse_args()
    results = evaluate_reports(args.reports, args.config)
    if not results:
        raise SystemExit("no usable report (need experiment_value_features.py reports with folds or leave-one-dataset-out)")
    for name, gate in results.items():
        print(format_gate(name, gate))
        print(f"     from: {gate['from_reports']}")
    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)


if __name__ == "__main__":
    main()
