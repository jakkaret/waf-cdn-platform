#!/usr/bin/env python3
"""Measure WAF inference paths without changing production state.

Run from the repository root:
    python3 ml/benchmark_latency.py --samples 30
"""

from __future__ import annotations

import argparse
import json
import statistics
import sys
import time
from pathlib import Path
from typing import Callable

import joblib
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.attribution import build_attribution_response
from ml.feature_engineering import FEATURE_COLUMNS, extract_features_from_request


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, round((len(ordered) - 1) * fraction)))
    return ordered[index]


def measure(fn: Callable[[], object], warmup: int, samples: int) -> dict[str, float | int]:
    for _ in range(warmup):
        fn()

    timings: list[float] = []
    for _ in range(samples):
        started = time.perf_counter()
        fn()
        timings.append((time.perf_counter() - started) * 1000.0)

    return {
        "samples": samples,
        "avg_ms": round(statistics.fmean(timings), 3),
        "p50_ms": round(percentile(timings, 0.50), 3),
        "p95_ms": round(percentile(timings, 0.95), 3),
        "max_ms": round(max(timings), 3),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--url", default="/login?id=1")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body", default="")
    parser.add_argument("--models-dir", type=Path, default=REPO_ROOT / "ml" / "models")
    args = parser.parse_args()

    if args.samples < 1 or args.warmup < 0:
        parser.error("--samples must be >= 1 and --warmup must be >= 0")

    models_dir = args.models_dir
    rf_model = joblib.load(models_dir / "random_forest_waf.joblib")
    iso_model = joblib.load(models_dir / "isolation_forest_waf.joblib")

    def make_features() -> pd.DataFrame:
        features = extract_features_from_request(args.url, args.method, args.body)
        return pd.DataFrame([features])[FEATURE_COLUMNS]

    feature_frame = make_features()

    def model_only() -> None:
        rf_model.predict_proba(feature_frame)
        iso_model.decision_function(feature_frame)

    def sklearn_fast_path() -> None:
        frame = make_features()
        rf_model.predict_proba(frame)
        iso_model.decision_function(frame)

    def sklearn_full_path() -> None:
        frame = make_features()
        rf_model.predict_proba(frame)
        iso_model.decision_function(frame)
        build_attribution_response(rf_model, frame)

    result: dict[str, object] = {
        "target_ms": 10.0,
        "request": {"url": args.url, "method": args.method},
        "models": {
            "random_forest_estimators": getattr(rf_model, "n_estimators", None),
            "random_forest_max_depth": getattr(rf_model, "max_depth", None),
            "isolation_forest_estimators": getattr(iso_model, "n_estimators", None),
        },
        "sklearn_model_only": measure(model_only, args.warmup, args.samples),
        "sklearn_fast_path": measure(sklearn_fast_path, args.warmup, args.samples),
        "sklearn_full_path_with_attribution": measure(
            sklearn_full_path, args.warmup, args.samples
        ),
    }

    try:
        from ml.onnx_inference import OnnxWafInference

        onnx_engine = OnnxWafInference(models_dir)
        result["onnx_fast_path"] = measure(
            lambda: onnx_engine.predict(args.url, args.method, args.body),
            args.warmup,
            args.samples,
        )
    except Exception as exc:
        result["onnx_fast_path"] = {"available": False, "reason": str(exc)}

    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
