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


def form_body(size: int) -> str:
    """A benign-looking urlencoded form body of about `size` bytes (field names and prose values)."""
    words = "customer+requested+delivery+before+noon+please+call+on+arrival"
    fields, n = [], 0
    while n < size:
        field = f"field{len(fields)}={words}"
        fields.append(field)
        n += len(field) + 1
    return "&".join(fields)[:size]


def by_body_size(rf_model, args) -> dict:
    """RF (features + predict_proba) and Gen3 ONNX per request, single thread, by POST body size.

    RF feature extraction is superlinear in body size; Gen3 caps its units. Production RF only
    scores the URL from the access log, so its body column is what logging bodies would cost.
    """
    from ml.feature_engineering import feature_columns_for_model

    cols = feature_columns_for_model(rf_model)
    try:
        from ml.gen3_onnx import Gen3OnnxModel

        gen3 = Gen3OnnxModel(str(args.gen3_onnx))
    except Exception as exc:
        gen3, gen3_error = None, f"{type(exc).__name__}: {exc}"
    out = {}
    for size in [int(s) for s in args.body_sizes.split(",") if s.strip()]:
        body = form_body(size)
        samples = max(3, min(args.samples, 30 if size >= 100_000 else args.samples))
        row = {"rf_features_predict": measure(
            lambda: rf_model.predict_proba(pd.DataFrame([extract_features_from_request(args.url, "POST", body)])[cols]),
            1, samples)}
        row["gen3_onnx"] = measure(lambda: gen3.score_request("POST", args.url, body), 1, samples) if gen3 \
            else {"available": False, "reason": gen3_error}
        out[str(size)] = row
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--samples", type=int, default=30)
    parser.add_argument("--warmup", type=int, default=5)
    parser.add_argument("--url", default="/login?id=1")
    parser.add_argument("--method", default="GET")
    parser.add_argument("--body", default="")
    parser.add_argument("--models-dir", type=Path, default=REPO_ROOT / "ml" / "models")
    parser.add_argument("--body-sizes", default="",
                        help="comma-separated POST form body sizes in bytes (e.g. 0,1000,10000,100000): "
                             "per-request time of RF (features + predict) and Gen3 (ONNX) at each size")
    parser.add_argument("--gen3-onnx", type=Path,
                        default=REPO_ROOT / "ml" / "models" / "gen3" / "gen3_f_noopenappsec.onnx")
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

    if args.body_sizes:
        result["by_body_size"] = by_body_size(rf_model, args)

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
