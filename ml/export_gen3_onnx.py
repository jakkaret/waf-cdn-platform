#!/usr/bin/env python3
"""
Convert an existing gen3_f_model.joblib (ml/train_final_gen3.py) to gen3_f_model.onnx.

For models trained before train_final_gen3.py exported ONNX itself. Without the
training data, parity is checked on the 63 scenario requests (ml/test_comprehensive.py)
plus 5,000 rows placed exactly on / next to every split threshold; the .onnx is
written only if ONNX and LightGBM agree within 1e-5. The joblib is a pickle:
convert only models produced by this repository.

    PYTHONPATH=. python ml/export_gen3_onnx.py ml/models/archive/gen3-final-f-<ts>/gen3_f_model.joblib
"""

import argparse
import json
import os
import sys

import joblib

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.gen3_onnx import export_onnx  # noqa: E402
from ml.test_comprehensive import TESTS  # noqa: E402


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("joblib_path")
    ap.add_argument("--out", help="default: gen3_f_model.onnx next to the joblib")
    args = ap.parse_args()

    wrapper = joblib.load(args.joblib_path)
    rows = wrapper.matrix([(m, u, b) for _, m, u, b, _ in TESTS])
    data, report = export_onnx(wrapper, rows)
    print(json.dumps(report, indent=2))
    if not report["parity_passed"]:
        sys.exit("[!] parity check failed; nothing written")
    out = args.out or os.path.join(os.path.dirname(os.path.abspath(args.joblib_path)), "gen3_f_model.onnx")
    with open(out, "wb") as f:
        f.write(data)
    print(f"[✔] {out} ({len(data)} bytes)")


if __name__ == "__main__":
    main()
