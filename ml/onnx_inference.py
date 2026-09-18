"""Low-overhead ONNX inference for the WAF decision path.

This module intentionally excludes feature attribution. Attribution remains on
the existing explainable /predict path and must not be placed on an inline
request path whose budget is below 10 ms.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np

from ml.feature_engineering import FEATURE_COLUMNS, extract_features_from_request


class OnnxWafInference:
    def __init__(self, models_dir: Path | str):
        models_dir = Path(models_dir)
        import onnxruntime as ort

        self._rf = ort.InferenceSession(
            str(models_dir / "random_forest_waf.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self._rf_input = self._rf.get_inputs()[0].name

    @staticmethod
    def _first_output(session, values: list[Any], preferred: str) -> Any:
        names = [output.name for output in session.get_outputs()]
        if preferred in names:
            return values[names.index(preferred)]
        return values[0]

    def predict(self, url: str = "", method: str = "GET", body: str = "") -> dict[str, Any]:
        features = extract_features_from_request(url=url, method=method, body=body)
        matrix = np.asarray(
            [[float(features[column]) for column in FEATURE_COLUMNS]],
            dtype=np.float32,
        )

        rf_values = self._rf.run(None, {self._rf_input: matrix})
        rf_probability = self._first_output(self._rf, rf_values, "probabilities")
        probability_array = np.asarray(rf_probability)
        if probability_array.ndim == 2:
            attack_probability = float(probability_array[0, -1])
        else:
            attack_probability = float(np.asarray(probability_array).reshape(-1)[-1])

        rf_label = self._first_output(self._rf, rf_values, "label")
        label_value = int(np.asarray(rf_label).reshape(-1)[0])


        is_anomaly = bool(label_value == 1 or attack_probability > 0.5)
        return {
            "is_anomaly": is_anomaly,
            "attack_probability": round(attack_probability, 4),
            "anomaly_score": None,
            "detector": "random_forest_inline",
            "status": "ANOMALY_DETECTED" if is_anomaly else "PASS",
            "features": features,
        }
