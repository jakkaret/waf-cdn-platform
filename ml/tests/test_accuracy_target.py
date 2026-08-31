"""
Scenario: T13 -- /health's "accuracy_target_passed" must reflect the real
evaluated accuracy, not a hardcoded True.

ml_api.py's /health handler used to return `"accuracy_target_passed": True`
unconditionally, alongside `eval_accuracy` read from the real
eval_results.json. On the currently-deployed model that produced the
self-contradicting pair `accuracy_target_passed: true, eval_accuracy: 0.8047`
-- true accuracy (80.47%) is below the project's stated 85% target
(Docs/12-Development-Guide.md T13), but the field claimed it passed anyway.
Verified live on Main, 2026-09-01: `curl localhost:5000/health` returned
exactly that pair.

This locks in a pure, directly-testable decision function
(accuracy_meets_target) instead of testing it only through the FastAPI app,
which needs the model artifacts loaded to construct.
"""
from ml.ml_api import accuracy_meets_target, ACCURACY_TARGET


def test_below_target_accuracy_does_not_pass():
    # The real, currently-measured production numbers (ml/models/eval_results.json)
    real_eval_results = {"metrics": {"accuracy": 0.8047}}
    assert accuracy_meets_target(real_eval_results) is False


def test_above_target_accuracy_passes():
    eval_results = {"metrics": {"accuracy": 0.90}}
    assert accuracy_meets_target(eval_results) is True


def test_exactly_at_target_passes():
    eval_results = {"metrics": {"accuracy": ACCURACY_TARGET}}
    assert accuracy_meets_target(eval_results) is True


def test_missing_eval_results_fails_closed_not_passed():
    """No evaluation data is not evidence of passing -- claiming "passed"
    with nothing measured would repeat exactly the bug this fixes."""
    assert accuracy_meets_target({}) is False
