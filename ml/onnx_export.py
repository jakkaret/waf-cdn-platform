#!/usr/bin/env python3
"""Export the checked-in sklearn WAF models to ONNX without overwriting them."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType

from ml.feature_engineering import FEATURE_COLUMNS


def export_model(model, output_path: Path) -> dict[str, object]:
    initial_types = [("features", FloatTensorType([None, len(FEATURE_COLUMNS)]))]
    options = {id(model): {"zipmap": False}} if hasattr(model, "predict_proba") else None
    onnx_model = convert_sklearn(
        model,
        initial_types=initial_types,
        options=options,
        target_opset={"ai.onnx.ml": 3},
    )
    output_path.write_bytes(onnx_model.SerializeToString())
    return {
        "path": str(output_path),
        "bytes": output_path.stat().st_size,
        "input": onnx_model.graph.input[0].name,
        "outputs": [output.name for output in onnx_model.graph.output],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--models-dir",
        type=Path,
        default=Path(__file__).resolve().parent / "models",
    )
    args = parser.parse_args()

    args.models_dir.mkdir(parents=True, exist_ok=True)
    rf = joblib.load(args.models_dir / "random_forest_waf.joblib")

    manifest = {
        "feature_columns": FEATURE_COLUMNS,
        "random_forest": export_model(rf, args.models_dir / "random_forest_waf.onnx"),
        "isolation_forest": {
            "status": "async_only",
            "artifact": "isolation_forest_waf.joblib",
        },
    }
    (args.models_dir / "onnx_manifest.json").write_text(
        json.dumps(manifest, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
