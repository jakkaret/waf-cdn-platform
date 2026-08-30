"""Per-prediction feature attribution for the WAF RandomForest model.

Ruling R1 (task-9-brief.md): no `shap`. Attribution is computed directly
from the RandomForest's own tree paths (the treeinterpreter decomposition),
not from an external library.

The decomposition, for one tree and one sample
------------------------------------------------
Walking the tree root -> leaf for the sample, every step crosses exactly one
split, on exactly one feature. The prediction (P(class=1) at the leaf) is
decomposed as:

    bias                = P(class=1) at the root node
    contribution[f]    += P(class=1) at child - P(class=1) at parent,
                          for the feature f the parent split on

so that, by construction (a telescoping sum along the path):

    bias + sum(contribution[f] for f in features) == P(class=1) at the leaf

`RandomForestClassifier.predict_proba` is the mean of its trees'
probabilities, so averaging `bias` and each `contribution[f]` across all
trees preserves the identity at forest level:

    mean_bias + sum(mean_contribution[f]) == rf.predict_proba(X)[0][1]

This module only builds that decomposition. It never rounds internally --
rounding is a display concern for the API layer (see `build_attribution_response`).
"""

import warnings
from typing import Any, Dict, List, Tuple

import pandas as pd

# sklearn.tree._tree.TREE_UNDEFINED -- the feature index leaves carry.
# Leaves are never used as a "parent" in the walk below, so this constant
# is documentation more than a load-bearing check, but it is what makes
# clear why leaves are excluded from the loop.
TREE_LEAF_FEATURE = -2


def _class1_index(estimator) -> int:
    """Column index of class 1 in `tree_.value` / `predict_proba` output.

    Do not assume class 1 sits at index 1 -- map it via `classes_`.
    """
    classes = list(estimator.classes_)
    return classes.index(1)


def _node_prob_class1(value_row, class1_idx: int) -> float:
    """P(class=1) for one node's `tree_.value[node_id][0]` row.

    Normalises defensively: sklearn has represented this row as raw
    weighted sample counts in older releases and as already-normalised
    proportions in newer ones (production runs a version that already
    normalises; do not assume that everywhere else does).
    """
    total = float(value_row.sum())
    if total == 0.0:
        return 0.0
    if abs(total - 1.0) < 1e-9:
        return float(value_row[class1_idx])
    return float(value_row[class1_idx]) / total


def explain_tree(estimator, X: pd.DataFrame) -> Tuple[float, Dict[str, float]]:
    """Decompose one tree's prediction for row 0 of `X` into a bias and
    per-feature contributions.

    Returns `(bias, contributions)` where `contributions` has one entry per
    feature that appears on the sample's root->leaf path (features never
    split on for this sample are simply absent -- the caller fills zeros).

    Exactly, by construction:
        bias + sum(contributions.values()) == that tree's P(class=1) for X
    """
    class1_idx = _class1_index(estimator)
    tree = estimator.tree_
    feature_names = list(X.columns)

    # Individual tree estimators inside the forest (unlike the forest
    # wrapper itself) were never fitted with recorded feature names, so
    # sklearn emits a cosmetic UserWarning every call when given a
    # DataFrame. The brief's own note (and R6) still calls for passing the
    # DataFrame here rather than `.values`; the warning is expected and
    # silenced rather than worked around by dropping column names.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        indicator = estimator.decision_path(X)
    node_ids = indicator.indices[indicator.indptr[0]:indicator.indptr[1]]

    contributions: Dict[str, float] = {}
    bias = None
    prev_node_id = None
    prev_prob = None

    for node_id in node_ids:
        prob = _node_prob_class1(tree.value[node_id][0], class1_idx)
        if bias is None:
            # Root node: this is the bias, not a step.
            bias = prob
        else:
            # The step from prev_node_id -> node_id crossed the split that
            # prev_node_id (the parent) made, on this feature.
            split_feature_idx = tree.feature[prev_node_id]
            feature_name = feature_names[split_feature_idx]
            delta = prob - prev_prob
            contributions[feature_name] = contributions.get(feature_name, 0.0) + delta
        prev_node_id = node_id
        prev_prob = prob

    return bias, contributions


def compute_forest_attribution(rf_model, X: pd.DataFrame) -> Tuple[float, Dict[str, float]]:
    """The reusable attribution function: given a fitted forest and one
    feature row, return the bias and per-feature contributions, averaged
    across every tree in the forest.

    `X` must be a single-row DataFrame whose columns are the feature names
    (the model was fit with feature names; pass a DataFrame, not `.values`,
    to avoid the sklearn "does not have valid feature names" warning and to
    keep contributions keyed by name).

    Every column of `X` is present in the returned `contributions` dict,
    including columns no tree in the forest ever split on for this sample
    (contribution 0.0), so a caller can always account for every feature.

    Unrounded. Exactly, up to floating-point error:
        bias + sum(contributions.values()) == rf_model.predict_proba(X)[0][1]
    """
    feature_names = list(X.columns)
    estimators = rf_model.estimators_
    n_trees = len(estimators)

    total_bias = 0.0
    total_contrib = {f: 0.0 for f in feature_names}

    for estimator in estimators:
        tree_bias, tree_contrib = explain_tree(estimator, X)
        total_bias += tree_bias
        for feature_name, value in tree_contrib.items():
            total_contrib[feature_name] += value

    mean_bias = total_bias / n_trees
    mean_contrib = {f: v / n_trees for f, v in total_contrib.items()}
    return mean_bias, mean_contrib


def build_attribution_response(rf_model, df_feat: pd.DataFrame) -> Dict[str, Any]:
    """Build the `/predict` API shape for attribution.

    Returns:
        {
          "attribution": [
            {"feature": ..., "value": ..., "contribution": ...},
            ...
          ],
          "attribution_baseline": <bias>,
        }

    - `attribution` has exactly one entry per column of `df_feat`, sorted by
      `|contribution|` descending.
    - `value` is that feature's actual value for this request (from row 0
      of `df_feat`).
    - Rounding happens here, for display only, after the additive identity
      has already been computed on the unrounded numbers.
    """
    bias, contributions = compute_forest_attribution(rf_model, df_feat)
    row = df_feat.iloc[0]

    entries: List[Dict[str, Any]] = [
        {
            "feature": feature_name,
            "value": float(row[feature_name]),
            "contribution": contributions[feature_name],
        }
        for feature_name in df_feat.columns
    ]
    entries.sort(key=lambda e: abs(e["contribution"]), reverse=True)

    for entry in entries:
        entry["value"] = round(entry["value"], 4)
        entry["contribution"] = round(entry["contribution"], 4)

    return {
        "attribution": entries,
        "attribution_baseline": round(bias, 4),
    }
