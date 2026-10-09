"""
Gen 3 model (feature set F) as ONNX: export on the training side, inference on
the serving side (e.g. a separate ML host running only onnxruntime).

Only the trees go into ONNX; feature extraction stays in Python
(ml/gen3_model.request_features), identical to the joblib model, so both
runtimes see the same float32 feature row.

Exactness. onnxmltools stores LightGBM split thresholds as float32 rounded to
nearest, while LightGBM compares double(x) <= t. For float32 inputs,
x <= t  <=>  x <= (largest float32 <= t), so export rewrites every threshold to
that rounded-down value. LightGBM's predictor also treats |x| <= 1e-35 as 0,
which `lightgbm_input` reproduces. With both, ONNX and booster.predict agree to
float rounding (~1e-7) even on rows placed exactly on split thresholds; export
refuses to mark a model valid unless that parity check passes (< 1e-5).

Unlike joblib (a pickle that runs code on load), an .onnx file is plain data:
the threshold, column contract and model card travel in its metadata_props.
"""

import json

import numpy as np

from ml.gen3_model import FEATURE_SETS, VERSION_TO_SET, request_features

ONNX_INPUT = "features"
ONNX_OUTPUT = "probabilities"
ONNX_TARGET_OPSET = 15            # highest the LightGBM converter of onnxmltools 1.16 supports
PARITY_TOLERANCE = 1e-5
LGBM_ZERO_THRESHOLD = 1e-35       # LightGBM kZeroThreshold


def lightgbm_input(matrix):
    """float32 matrix as LightGBM's predictor sees it (|x| <= 1e-35 becomes 0)."""
    m = np.asarray(matrix, dtype=np.float32).copy()
    m[np.abs(m) <= LGBM_ZERO_THRESHOLD] = 0.0
    return m


def _split_thresholds(booster):
    """{(tree_index, feature_index): {exact double thresholds}} from the booster."""
    out = {}

    def walk(node, tree):
        if "split_feature" in node:
            out.setdefault((tree, node["split_feature"]), set()).add(node["threshold"])
            walk(node["left_child"], tree)
            walk(node["right_child"], tree)

    for t in booster.dump_model()["tree_info"]:
        walk(t["tree_structure"], t["tree_index"])
    return out


def _round_down_float32(t):
    f = np.float32(t)
    return float(f) if float(f) <= t else float(np.nextafter(f, np.float32(-np.inf)))


def exact_float32_thresholds(onnx_model, booster):
    """Rewrite TreeEnsemble thresholds in place to the largest float32 <= LightGBM's double threshold.

    Returns (changed, ambiguous): ambiguous nodes (two thresholds of one tree and
    feature that round to the same float32 but down to different values) are
    left as converted; the parity check then decides.
    """
    tree_op = next(n for n in onnx_model.graph.node if n.op_type.startswith("TreeEnsemble"))
    attr = {a.name: a for a in tree_op.attribute}
    exact = _split_thresholds(booster)
    values = list(attr["nodes_values"].floats)
    changed = ambiguous = 0
    for i, (tree, feat, v, mode) in enumerate(zip(attr["nodes_treeids"].ints, attr["nodes_featureids"].ints,
                                                  values, attr["nodes_modes"].strings)):
        if mode != b"BRANCH_LEQ":
            continue
        downs = {_round_down_float32(t) for t in exact.get((tree, feat), ()) if np.float32(t) == np.float32(v)}
        if len(downs) != 1:
            ambiguous += 1
            continue
        d = downs.pop()
        changed += d != float(np.float32(v))
        values[i] = d
    del attr["nodes_values"].floats[:]
    attr["nodes_values"].floats.extend(values)
    return changed, ambiguous


def boundary_matrix(booster, n_columns, rows=5000, seed=0):
    """Adversarial parity rows: every value sits on a split threshold or one float32 step from it."""
    rng = np.random.default_rng(seed)
    by_feature = {}
    for (_, feat), ts in _split_thresholds(booster).items():
        by_feature.setdefault(feat, set()).update(ts)
    m = np.zeros((rows, n_columns), dtype=np.float32)
    for j in range(n_columns):
        ts = np.array(sorted(by_feature.get(j, {0.0})), dtype=np.float64)
        pick = rng.choice(ts, rows).astype(np.float32)
        step = np.nextafter(pick, np.where(rng.random(rows) < 0.5, -np.inf, np.inf).astype(np.float32))
        m[:, j] = np.where(rng.random(rows) < 1 / 3, pick, step)
    return m


def _session(onnx_bytes):
    """WAF_ORT_THREADS (optional) caps onnxruntime's intra-op threads. The default pool has one
    thread per CPU the process can see (all host CPUs inside a cpuset-limited container) and they
    spin between calls; one request at a time gains nothing from them."""
    import os

    import onnxruntime as ort
    opts = ort.SessionOptions()
    threads = os.environ.get("WAF_ORT_THREADS")
    if threads:
        opts.intra_op_num_threads = opts.inter_op_num_threads = int(threads)
    return ort.InferenceSession(onnx_bytes, opts, providers=["CPUExecutionProvider"])


def _onnx_scores(session, matrix):
    return session.run([ONNX_OUTPUT], {ONNX_INPUT: lightgbm_input(matrix)})[0][:, 1]


def parity(booster, session, matrix):
    """Max |ONNX - LightGBM| attack probability over the rows of `matrix`."""
    m = np.asarray(matrix, dtype=np.float32)
    return float(np.max(np.abs(_onnx_scores(session, m) - booster.predict(m)))) if len(m) else 0.0


def export_onnx(wrapper, parity_rows, card=None):
    """Convert a Gen3FModel to ONNX bytes and verify it.

    parity_rows: float32 matrix of real feature rows (FEATURE_SET_F order).
    Returns (onnx_bytes, report); report["parity_passed"] says whether the
    model may be served. The card (threshold, columns, parity) is embedded.
    """
    import onnx
    import onnxmltools
    import onnxruntime
    from onnxmltools.convert.common.data_types import FloatTensorType

    booster = wrapper.model.booster_
    n = len(wrapper.columns)
    model = onnxmltools.convert_lightgbm(wrapper.model, initial_types=[(ONNX_INPUT, FloatTensorType([None, n]))],
                                         zipmap=False, target_opset=ONNX_TARGET_OPSET)
    for out in model.graph.output:            # batch dimension is dynamic (converter declares 1)
        dims = out.type.tensor_type.shape.dim
        if dims:
            dims[0].ClearField("dim_value")
            dims[0].dim_param = "N"
    changed, ambiguous = exact_float32_thresholds(model, booster)

    session = _session(model.SerializeToString())
    real = parity(booster, session, parity_rows)
    boundary = parity(booster, session, boundary_matrix(booster, n))
    report = {
        "format": "onnx", "opset": ONNX_TARGET_OPSET, "input": ONNX_INPUT, "output": f"{ONNX_OUTPUT}[:, 1]",
        "thresholds_rounded_down": int(changed), "thresholds_ambiguous": int(ambiguous),
        "parity_rows": int(len(parity_rows)), "parity_max_abs_diff_real_rows": real,
        "parity_max_abs_diff_boundary_rows": boundary, "parity_tolerance": PARITY_TOLERANCE,
        "parity_passed": bool(max(real, boundary) < PARITY_TOLERANCE),
        "versions": {"onnx": onnx.__version__, "onnxmltools": onnxmltools.__version__,
                     "onnxruntime": onnxruntime.__version__},
    }
    meta = {"feature_set": wrapper.version, "feature_columns": json.dumps(list(wrapper.columns)),
            "threshold": repr(float(wrapper.threshold)), "parity_passed": str(report["parity_passed"]).lower(),
            "model_card": json.dumps({**(card if card is not None else wrapper.card), "onnx": report}, default=float)}
    for k, v in meta.items():
        entry = model.metadata_props.add()
        entry.key, entry.value = k, v
    model.producer_name = "waf_project ml/gen3_onnx.py"
    return model.SerializeToString(), report


class Gen3OnnxModel:
    """Gen 3 model served by onnxruntime; same interface as Gen3FModel (no LightGBM needed)."""

    runtime = "onnx"

    def __init__(self, path_or_bytes):
        self.session = _session(path_or_bytes)
        meta = self.session.get_modelmeta().custom_metadata_map
        self.columns = json.loads(meta.get("feature_columns", "[]"))
        self.version = meta.get("feature_set", "")
        self.feature_set = VERSION_TO_SET.get(self.version)
        if self.feature_set is None or self.columns != FEATURE_SETS[self.feature_set]:
            raise ValueError(f"ONNX model feature set {self.version!r} does not match this code "
                             f"(known: {sorted(VERSION_TO_SET)}); re-export with this code version")
        if meta.get("parity_passed") != "true":
            raise ValueError("ONNX model did not pass the LightGBM parity check at export")
        self.threshold = float(meta["threshold"])
        self.card = json.loads(meta.get("model_card", "{}"))

    def matrix(self, requests):
        """(method, url, body) tuples -> float32 matrix in model column order."""
        rows = []
        for m, u, b in requests:
            feats = request_features(m, u, b)
            rows.append([feats[c] for c in self.columns])
        return np.array(rows, dtype=np.float32)

    def score_request(self, method="GET", url="/", body=""):
        return float(_onnx_scores(self.session, self.matrix([(method, url, body)]))[0])

    def predict(self, method="GET", url="/", body=""):
        p = self.score_request(method, url, body)
        return {"attack_probability": round(p, 4), "is_attack": p >= self.threshold,
                "threshold": round(self.threshold, 4), "feature_set": self.version}
