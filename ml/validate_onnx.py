#!/usr/bin/env python3
"""Validate RF ONNX parity against the checked-in sklearn model.

This checks numerical parity and labels only. It is not an accuracy evaluation
or evidence of zero-day detection capability.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import joblib
import pandas as pd

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from ml.feature_engineering import FEATURE_COLUMNS, extract_features_from_request
from ml.onnx_inference import OnnxWafInference

CASES = [
    ("benign_home", "/", "GET", ""),
    ("benign_login", "/login?id=1", "GET", ""),
    ("benign_static", "/assets/app.js", "GET", ""),
    ("sqli", "/login?id=1%27%20OR%201%3D1--", "GET", ""),
    ("xss", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E", "GET", ""),
    ("traversal", "/download?file=../../etc/passwd", "GET", ""),
    ("ssrf", "/fetch?url=http://169.254.169.254/latest/meta-data/", "GET", ""),
    ("command_injection", "/run?cmd=cat%20/etc/passwd%3B%20id", "GET", ""),
    ("post_json", "/api/profile", "POST", '{"name":"<script>alert(1)</script>"}'),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--models-dir", type=Path, default=REPO_ROOT / "ml" / "models")
    parser.add_argument("--tolerance", type=float, default=1e-3)
    args = parser.parse_args()

    rf_model = joblib.load(args.models_dir / "random_forest_waf.joblib")
    onnx_engine = OnnxWafInference(args.models_dir)
    rows = []
    max_probability_diff = 0.0
    label_mismatches = 0

    for name, url, method, body in CASES:
        features = extract_features_from_request(url=url, method=method, body=body)
        frame = pd.DataFrame([features])[FEATURE_COLUMNS]
        sklearn_probability = float(rf_model.predict_proba(frame)[0, -1])
        sklearn_label = int(rf_model.predict(frame)[0])
        onnx_result = onnx_engine.predict(url, method, body)
        onnx_probability = float(onnx_result["attack_probability"])
        onnx_label = int(bool(onnx_result["is_anomaly"]))
        difference = abs(sklearn_probability - onnx_probability)
        max_probability_diff = max(max_probability_diff, difference)
        label_mismatches += int(sklearn_label != onnx_label)
        rows.append({
            "name": name,
            "sklearn_probability": round(sklearn_probability, 6),
            "onnx_probability": round(onnx_probability, 6),
            "absolute_difference": round(difference, 6),
            "sklearn_label": sklearn_label,
            "onnx_label": onnx_label,
        })

    status = "PASS" if max_probability_diff <= args.tolerance and label_mismatches == 0 else "FAIL"
    result = {
        "status": status,
        "comparison": "random_forest_sklearn_vs_onnx",
        "cases": len(CASES),
        "tolerance": args.tolerance,
        "max_probability_diff": round(max_probability_diff, 6),
        "label_mismatches": label_mismatches,
        "results": rows,
        "scope_note": "Parity only; not an accuracy or zero-day detection claim.",
    }
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
