"""Pickle-free serving of the /predict forests (audit H52).

ml_api.py used to unpickle (joblib) the RandomForest and IsolationForest, which runs
a pickle. Here both forests live as plain numpy arrays in .npz files, loaded
with allow_pickle=False, and evaluated by a small tree walker that reproduces
scikit-learn exactly:

- sklearn casts X to float32 and goes left when x[feature] <= threshold
  (threshold float64); walk() does the same.
- RandomForestClassifier.predict_proba is the mean of the trees' leaf
  probabilities; the per-node P(class=1) is stored, so the treeinterpreter
  attribution (ml/attribution.py) walks the same path with no sklearn object.
- IsolationForest.decision_function is
  -2 ** (-sum(depth_at_leaf) / (n_trees * c(max_samples))) - offset_,
  where depth_at_leaf = decision_path_length + average_path_length - 1 is
  precomputed per node at export.

export_*() need the fitted sklearn objects and run only offline
(ml/export_plain_models.py); the serving side needs numpy alone.
"""
from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np

FORMAT_VERSION = 1


def _concat_trees(trees) -> Dict[str, np.ndarray]:
    """Concatenate tree_ arrays; child indexes become global, leaves stay -1."""
    left, right, feature, threshold, offsets = [], [], [], [], [0]
    base = 0
    for t in trees:
        cl = t.children_left.astype(np.int64)
        cr = t.children_right.astype(np.int64)
        left.append(np.where(cl >= 0, cl + base, -1))
        right.append(np.where(cr >= 0, cr + base, -1))
        feature.append(t.feature.astype(np.int64))
        threshold.append(t.threshold.astype(np.float64))
        base += t.node_count
        offsets.append(base)
    return {
        "left": np.concatenate(left),
        "right": np.concatenate(right),
        "feature": np.concatenate(feature),
        "threshold": np.concatenate(threshold),
        "roots": np.asarray(offsets[:-1], dtype=np.int64),
    }


def _node_prob_class1(value_row, class1_idx: int) -> float:
    # Same normalisation as ml/attribution.py (counts in old sklearn, proportions in new).
    total = float(value_row.sum())
    if total == 0.0:
        return 0.0
    if abs(total - 1.0) < 1e-9:
        return float(value_row[class1_idx])
    return float(value_row[class1_idx]) / total


def export_random_forest(rf, path) -> None:
    trees = [e.tree_ for e in rf.estimators_]
    arrays = _concat_trees(trees)
    probs = []
    for est in rf.estimators_:
        c1 = list(est.classes_).index(1)
        probs.extend(_node_prob_class1(row[0], c1) for row in est.tree_.value)
    arrays["p1"] = np.asarray(probs, dtype=np.float64)
    arrays["feature_names"] = np.asarray([str(n) for n in rf.feature_names_in_])
    arrays["classes"] = np.asarray(rf.classes_, dtype=np.int64)
    arrays["format_version"] = np.asarray(FORMAT_VERSION)
    np.savez_compressed(path, **arrays)


def export_isolation_forest(iso, path) -> None:
    trees = [e.tree_ for e in iso.estimators_]
    arrays = _concat_trees(trees)
    depth = [
        (dpl + apl - 1.0)
        for dpl_t, apl_t in zip(iso._decision_path_lengths, iso._average_path_length_per_tree)
        for dpl, apl in zip(dpl_t, apl_t)
    ]
    arrays["leaf_depth"] = np.asarray(depth, dtype=np.float64)
    arrays["tree_features"] = np.asarray(iso.estimators_features_, dtype=np.int64)
    arrays["subsample_features"] = np.asarray(iso._max_features != iso.n_features_in_)
    from sklearn.ensemble._iforest import _average_path_length
    arrays["denominator"] = np.asarray(len(iso.estimators_) * float(_average_path_length([iso._max_samples])[0]))
    arrays["offset"] = np.asarray(float(iso.offset_))
    arrays["feature_names"] = np.asarray([str(n) for n in iso.feature_names_in_])
    arrays["format_version"] = np.asarray(FORMAT_VERSION)
    np.savez_compressed(path, **arrays)


class _Forest:
    def __init__(self, path):
        with np.load(path, allow_pickle=False) as z:
            self._z = {k: z[k] for k in z.files}
        if int(self._z["format_version"]) != FORMAT_VERSION:
            raise ValueError(f"{path}: unsupported format_version {self._z['format_version']}")
        self.left = self._z["left"]
        self.right = self._z["right"]
        self.feature = self._z["feature"]
        self.threshold = self._z["threshold"]
        self.roots = self._z["roots"]
        self.feature_names: List[str] = [str(n) for n in self._z["feature_names"]]
        self.n_trees = len(self.roots)

    def walk(self, root: int, x: np.ndarray) -> List[int]:
        """Node ids root -> leaf for one float32 row (sklearn's comparison)."""
        path = [root]
        node = root
        while self.left[node] != -1:
            node = self.left[node] if x[self.feature[node]] <= self.threshold[node] else self.right[node]
            path.append(int(node))
        return path

    def row(self, values) -> np.ndarray:
        return np.asarray(values, dtype=np.float32)


class PlainRandomForest(_Forest):
    def __init__(self, path):
        super().__init__(path)
        self.p1 = self._z["p1"]
        self.classes = [int(c) for c in self._z["classes"]]

    def explain(self, values) -> Tuple[float, float, Dict[str, float]]:
        """(P(class=1), bias, contributions) for one row in feature_names order.
        bias + sum(contributions) == P(class=1), as in ml/attribution.py."""
        x = self.row(values)
        total_p = 0.0
        total_bias = 0.0
        contrib = {f: 0.0 for f in self.feature_names}
        for root in self.roots:
            path = self.walk(int(root), x)
            total_bias += self.p1[path[0]]
            for parent, child in zip(path, path[1:]):
                contrib[self.feature_names[self.feature[parent]]] += self.p1[child] - self.p1[parent]
            total_p += self.p1[path[-1]]
        n = self.n_trees
        return total_p / n, total_bias / n, {f: v / n for f, v in contrib.items()}

    def predict_proba1(self, values) -> float:
        x = self.row(values)
        return float(sum(self.p1[self.walk(int(r), x)[-1]] for r in self.roots) / self.n_trees)

    def predict(self, values) -> int:
        # predict_proba has two columns (classes 0 and 1); argmax, ties to the first class.
        p1 = self.predict_proba1(values)
        i1 = self.classes.index(1)
        probs = [0.0, 0.0]
        probs[i1], probs[1 - i1] = p1, 1.0 - p1
        return self.classes[int(np.argmax(probs))]


class PlainIsolationForest(_Forest):
    def __init__(self, path):
        super().__init__(path)
        self.leaf_depth = self._z["leaf_depth"]
        self.tree_features = self._z["tree_features"]
        self.subsample = bool(self._z["subsample_features"])
        self.denominator = float(self._z["denominator"])
        self.offset = float(self._z["offset"])

    def decision_function(self, values) -> float:
        x = self.row(values)
        depth = 0.0
        for i, root in enumerate(self.roots):
            xs = x[self.tree_features[i]] if self.subsample else x
            depth += self.leaf_depth[self.walk(int(root), xs)[-1]]
        score = 2 ** (-(depth / self.denominator)) if self.denominator != 0 else 1.0
        return float(-score - self.offset)
