import json
import os
import sys
import tempfile
import time
import unittest

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ml.promotion_gate import dataset_of, evaluate, evaluate_reports, holdout_by_dataset


def _src(benign=None, attack=None, bs=100.0, ash=100.0):
    return {"benign_recall": benign, "benign_shapes": bs if benign is not None else 0.0,
            "attack_recall": attack, "attack_shapes": ash if attack is not None else 0.0}


def _fold(per_source, normal=37, attack=24, stress=0.65):
    return {"holdout": {"per_source": per_source},
            "scenarios": {"normal_allowed": f"{normal}/37", "attack_blocked": f"{attack}/26"},
            "stress_context_transfer": {"detection_rate": stress, "control_false_positive_rate": 0.001}}


GOOD_SOURCES = {
    "CSIC_2010_Cleaned": _src(0.99, 0.80),
    "OpenAppSec_Legitimate": _src(0.999, None),
    "OpenAppSec_Malicious": _src(None, 0.95),
    "SRBH2020_Honeypot": _src(0.995, 0.90),
}
GOOD_LOFO = {d: {"attack_recall_at_benign_98_5": v, "attack_recall_at_benign_99_9": v / 2}
             for d, v in (("CSIC_2010_Cleaned", 0.55), ("OpenAppSec", 0.85), ("SRBH2020_Honeypot", 0.75))}


class PromotionGateTests(unittest.TestCase):
    def test_dataset_grouping(self):
        self.assertEqual(dataset_of("OpenAppSec_Legitimate"), "OpenAppSec")
        self.assertEqual(dataset_of("ModSecurity_VPS_Audit_Payload_Rule"), "VPS")
        self.assertEqual(dataset_of("CSIC_2010_Cleaned"), "CSIC_2010_Cleaned")

    def test_sources_of_one_dataset_are_combined_by_weight(self):
        by = holdout_by_dataset([_fold({"VPS_Nginx_Real_200_Access": _src(1.0, None, bs=10),
                                        "VPS_Audit_RuleFree_2xx_Lab": _src(0.9, None, bs=90)})])
        self.assertAlmostEqual(by["VPS"]["benign"], 0.91)

    def test_passing_candidate(self):
        g = evaluate([_fold(GOOD_SOURCES)] * 3, GOOD_LOFO)
        self.assertTrue(g["complete"])
        self.assertTrue(g["passed"], g["criteria"])
        # every dataset weighs the same: (0.80 + 0.95 + 0.90) / 3
        self.assertAlmostEqual(g["criteria"]["G2_known_attack_mean"]["value"], 0.8833, places=4)
        self.assertAlmostEqual(g["criteria"]["G3_unseen_attack_mean"]["value"], 0.7167, places=4)

    def test_each_criterion_can_fail(self):
        bad_benign = dict(GOOD_SOURCES, OpenAppSec_Legitimate=_src(0.97, None))
        self.assertFalse(evaluate([_fold(bad_benign)], GOOD_LOFO)["criteria"]["G1_benign_every_dataset"]["passed"])
        blind = dict(GOOD_LOFO, CSIC_2010_Cleaned={"attack_recall_at_benign_98_5": 0.3, "attack_recall_at_benign_99_9": 0.1})
        g = evaluate([_fold(GOOD_SOURCES)], blind)
        self.assertFalse(g["criteria"]["G4_no_dataset_below"]["passed"])
        self.assertFalse(g["passed"])
        self.assertFalse(evaluate([_fold(GOOD_SOURCES, normal=36)], GOOD_LOFO)["criteria"]["G5_sanity"]["passed"])

    def test_grid_era_lofo_is_not_used(self):
        old = {d: {"attack_recall_at_benign_98_5": 0.0} for d in GOOD_LOFO}  # no exact-metric marker
        g = evaluate([_fold(GOOD_SOURCES)], old)
        self.assertIsNone(g["criteria"]["G3_unseen_attack_mean"]["passed"])
        self.assertFalse(g["complete"])
        self.assertFalse(g["passed"])

    def test_reports_are_combined_and_old_layouts_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            srcs = ["CSIC_2010_Cleaned", "OpenAppSec_Legitimate", "OpenAppSec_Malicious", "SRBH2020_Honeypot"]

            def write(name, report):
                path = os.path.join(d, name)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(report, f)
                time.sleep(0.02)  # distinct mtimes: newest wins
                return path

            folds = write("folds.json", {"sources": srcs, "configs": {"F": {"folds": [_fold(GOOD_SOURCES)] * 3,
                                                                              "leave_one_dataset_out": {}}}})
            lofo = write("lofo.json", {"sources": srcs, "configs": {"F": {"folds": [],
                                                                            "leave_one_dataset_out": GOOD_LOFO}}})
            other = write("other.json", {"sources": ["CSIC_2010_Cleaned"], "configs": {"F": {"folds": [], "leave_one_dataset_out": {}}}})
            old = write("old.json", {"sources": srcs, "configs": {"F": {"holdout": {}}}})
            broken = os.path.join(d, "broken.json")
            with open(broken, "w") as f:
                f.write("{")
            res = evaluate_reports([folds, lofo, other, old, broken])
            self.assertIn("F", res)
            self.assertEqual(res["F"]["from_reports"], {"holdout_folds": folds, "leave_one_dataset_out": lofo})
            self.assertTrue(res["F"]["passed"])

            # A newer usable report over different sources (e.g. VPS data added) becomes the
            # reference and is never mixed with reports over the old sources.
            newer = write("newer.json", {"sources": srcs + ["VPS_Audit_RuleFree_2xx_Lab"],
                                         "configs": {"F": {"folds": [], "leave_one_dataset_out": GOOD_LOFO}}})
            res = evaluate_reports([folds, lofo, other, old, broken, newer])
            self.assertEqual(res["F"]["from_reports"], {"holdout_folds": None, "leave_one_dataset_out": newer})
            self.assertFalse(res["F"]["complete"])

    def test_reports_from_another_feature_extraction_are_not_mixed(self):
        with tempfile.TemporaryDirectory() as d:
            srcs = ["CSIC_2010_Cleaned", "OpenAppSec_Legitimate", "OpenAppSec_Malicious", "SRBH2020_Honeypot"]

            def write(name, report):
                path = os.path.join(d, name)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(report, f)
                time.sleep(0.02)
                return path

            # raw-era report (no feature_extraction key) with complete holdout folds ...
            raw = write("raw.json", {"sources": srcs, "configs": {"F": {"folds": [_fold(GOOD_SOURCES)] * 3,
                                                                          "leave_one_dataset_out": GOOD_LOFO}}})
            # ... must not complete a newer canonical report that only has LOFO
            canon = write("canon.json", {"sources": srcs, "feature_extraction": "gen3-F-2026-09-29-canon",
                                         "configs": {"F": {"folds": [], "leave_one_dataset_out": GOOD_LOFO}}})
            res = evaluate_reports([raw, canon])
            self.assertEqual(res["F"]["from_reports"], {"holdout_folds": None, "leave_one_dataset_out": canon})
            self.assertEqual(res["F"]["feature_extraction"], "gen3-F-2026-09-29-canon")
            self.assertFalse(res["F"]["complete"])


if __name__ == "__main__":
    unittest.main()
