"""train_final_gen3 --params-from: a published model card must give back its exact hyperparameters,
or ml/training/<model>/reproduce.sh trains a different model on a clone without ml/models/archive/."""
import json

import pytest

pytest.importorskip("lightgbm", reason="training dependencies not installed")

from ml.train_final_gen3 import hyperparameters_from  # noqa: E402

CARD = "ml/models/gen3/gen3_f_noopenappsec_model_card.json"


def test_params_from_model_card_match_the_card():
    with open(CARD, encoding="utf-8") as f:
        card_hp = json.load(f)["hyperparameters"]
    params, source = hyperparameters_from(CARD)
    assert source == card_hp["from"]
    assert params["class_weight"] == {int(k): v for k, v in card_hp["class_weight"].items()}
    for key, value in card_hp.items():
        if key not in ("from", "class_weight"):
            assert params[key] == value, key
