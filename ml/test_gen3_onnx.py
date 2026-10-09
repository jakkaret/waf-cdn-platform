import os
import shutil
import sys
import tempfile
import unittest

import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    import onnx
    import onnxmltools  # noqa: F401
    import onnxruntime  # noqa: F401
except ImportError:  # the serving venv has onnxruntime only; export needs the training venv
    onnx = None

from ml.gen3_model import FEATURE_SET_F, FEATURE_SETS, Gen3FModel, feature_set_version, request_features
from ml.test_comprehensive import TESTS

REQUESTS = [(m, u, b) for _, m, u, b, _ in TESTS]


def _model(columns=FEATURE_SET_F):
    """LightGBM on the 63 scenarios plus jittered copies: enough splits to exercise the export."""
    import lightgbm as lgb
    rng = np.random.default_rng(1)
    X0 = np.array([[request_features(m, u, b)[c] for c in columns] for m, u, b in REQUESTS], dtype=np.float32)
    y0 = np.array([exp == "BLOCK" for exp, *_ in TESTS], dtype=int)
    X = np.vstack([X0] + [X0 * rng.uniform(0.7, 1.3, X0.shape).astype(np.float32) for _ in range(30)])
    y = np.tile(y0, 31)
    return lgb.LGBMClassifier(n_estimators=60, num_leaves=15, min_child_samples=5, verbose=-1).fit(X, y)


@unittest.skipIf(onnx is None, "onnx / onnxmltools / onnxruntime not installed")
class Gen3OnnxTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from ml.gen3_onnx import export_onnx
        cls.wrapper = Gen3FModel(_model(), threshold=0.42, card={"feature_set": "test"})
        cls.data, cls.report = export_onnx(cls.wrapper, cls.wrapper.matrix(REQUESTS))
        cls.tmp = tempfile.mkdtemp()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_parity_passes_on_real_and_threshold_boundary_rows(self):
        r = self.report
        self.assertTrue(r["parity_passed"], r)
        self.assertLess(r["parity_max_abs_diff_real_rows"], 1e-5)
        self.assertLess(r["parity_max_abs_diff_boundary_rows"], 1e-5)
        self.assertEqual(r["thresholds_ambiguous"], 0)

    def test_onnx_model_matches_lightgbm_request_by_request(self):
        from ml.gen3_onnx import Gen3OnnxModel
        served = Gen3OnnxModel(self.data)
        self.assertEqual(served.runtime, "onnx")
        self.assertAlmostEqual(served.threshold, 0.42)
        self.assertEqual(served.card["feature_set"], "test")
        self.assertTrue(served.card["onnx"]["parity_passed"])
        for req in REQUESTS:
            self.assertAlmostEqual(served.score_request(*req), self.wrapper.score_request(*req), delta=1e-5)
            self.assertEqual(served.predict(*req), self.wrapper.predict(*req))

    def _tampered(self, key, value):
        model = onnx.load_from_string(self.data)
        for p in model.metadata_props:
            if p.key == key:
                p.value = value
        return model.SerializeToString()

    def test_refuses_other_columns_or_failed_parity(self):
        from ml.gen3_onnx import Gen3OnnxModel
        with self.assertRaises(ValueError):
            Gen3OnnxModel(self._tampered("feature_columns", '["a"]'))
        with self.assertRaises(ValueError):
            Gen3OnnxModel(self._tampered("parity_passed", "false"))

    def test_api_prefers_onnx_and_falls_back_to_joblib(self):
        import joblib
        import ml.ml_api as api
        onnx_path, joblib_path = os.path.join(self.tmp, "m.onnx"), os.path.join(self.tmp, "m.joblib")
        joblib.dump(self.wrapper, joblib_path)
        with open(onnx_path, "wb") as f:
            f.write(self.data)
        model, err = api.load_gen3_model(joblib_path, onnx_path)
        self.assertEqual((model.runtime, err), ("onnx", None))

        with open(onnx_path, "wb") as f:
            f.write(b"not an onnx model")
        model, err = api.load_gen3_model(joblib_path, onnx_path)
        self.assertEqual(model.runtime, "joblib")
        self.assertIn("onnx:", err)

        model, err = api.load_gen3_model(os.path.join(self.tmp, "none.joblib"), onnx_path)
        self.assertIsNone(model)
        self.assertIn("onnx:", err)

    def test_fast_engine_gen3_serves_predict_fast(self):
        from fastapi.testclient import TestClient
        import ml.ml_api as api
        from ml.gen3_onnx import Gen3OnnxModel
        client = TestClient(api.app)
        old = api.gen3_model, api.FAST_ENGINE
        try:
            api.gen3_model, api.FAST_ENGINE = Gen3OnnxModel(self.data), "gen3"
            r = client.post("/predict-fast", json={"url": "/search?q=<script>alert(1)</script>"})
            self.assertEqual(r.status_code, 200)
            body = r.json()
            self.assertEqual(body["detector"], "gen3_f_onnx")
            self.assertEqual(set(body) >= {"is_anomaly", "attack_probability", "status"}, True)
            d = client.get("/predict-fast/decision", headers={"X-Original-URI": "/?id=1'+or+1=1--"})
            self.assertEqual(d.status_code, 204)
            self.assertIn(d.headers["X-WAF-ML-Decision"], {"pass", "anomaly"})
            api.gen3_model = None
            self.assertEqual(client.post("/predict-fast", json={"url": "/"}).status_code, 503)
        finally:
            api.gen3_model, api.FAST_ENGINE = old


@unittest.skipIf(onnx is None, "onnx / onnxmltools / onnxruntime not installed")
class FeatureSetTests(unittest.TestCase):
    def test_noenc_model_exports_loads_and_reports_its_version(self):
        from ml.gen3_onnx import Gen3OnnxModel, export_onnx
        cols = FEATURE_SETS["F-noenc"]
        self.assertNotIn("encoded_char_ratio", cols)
        self.assertEqual(len(cols), len(FEATURE_SET_F) - 1)
        wrapper = Gen3FModel(_model(cols), threshold=0.5, feature_set="F-noenc")
        data, report = export_onnx(wrapper, wrapper.matrix(REQUESTS))
        self.assertTrue(report["parity_passed"], report)
        served = Gen3OnnxModel(data)
        self.assertEqual((served.feature_set, served.version), ("F-noenc", feature_set_version("F-noenc")))
        for req in REQUESTS[:10]:
            self.assertAlmostEqual(served.score_request(*req), wrapper.score_request(*req), delta=1e-5)
        self.assertEqual(served.predict("GET", "/")["feature_set"], feature_set_version("F-noenc"))

    def test_columns_must_match_the_named_set(self):
        with self.assertRaises(ValueError):
            Gen3FModel(object(), 0.5, columns=FEATURE_SET_F, feature_set="F-noenc")
        with self.assertRaises(ValueError):
            Gen3FModel(object(), 0.5, feature_set="G")
        self.assertEqual(Gen3FModel(object(), 0.5).version, feature_set_version("F"))


class ApiTokenTests(unittest.TestCase):
    def test_token_required_only_when_configured(self):
        from fastapi.testclient import TestClient
        import ml.ml_api as api
        client = TestClient(api.app)
        old = api.API_TOKEN
        try:
            api.API_TOKEN = ""
            self.assertEqual(client.get("/health").status_code, 200)
            api.API_TOKEN = "s3cret-token"
            self.assertEqual(client.get("/health").status_code, 401)
            self.assertEqual(client.get("/health", headers={"X-WAF-ML-Token": "wrong"}).status_code, 401)
            self.assertEqual(client.post("/predict-gen3", json={"url": "/"}).status_code, 401)
            self.assertEqual(client.get("/health", headers={"X-WAF-ML-Token": "s3cret-token"}).status_code, 200)
        finally:
            api.API_TOKEN = old


if __name__ == "__main__":
    unittest.main()
