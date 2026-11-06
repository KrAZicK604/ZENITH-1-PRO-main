"""Metrics must reveal wrong decisions and retain undecided violations."""
import unittest
from unittest.mock import patch

from pilot_evaluation import _record, evaluate


class PilotEvaluationTest(unittest.TestCase):
    def test_metrics_distinguish_every_outcome(self):
        counts = dict.fromkeys(("true_alert", "false_alert", "missed_violation",
                                "true_within", "abstain_outside", "abstain_within"), 0)
        for decision in ("WITHIN_TOLERANCE", "OUTSIDE_TOLERANCE", "ABSTAIN"):
            for actual in (False, True):
                _record(counts, decision, actual)
        self.assertEqual(set(counts.values()), {1})
        with self.assertRaises(ValueError):
            _record(counts, "UNKNOWN", False)

    def test_fixed_evaluation_is_reproducible_and_has_negative_controls(self):
        report = evaluate()
        self.assertEqual(report, evaluate())
        self.assertEqual(report["status"], "PASS")
        self.assertEqual(len(report["results"]), 4)
        for result in report["results"]:
            counts = result["counts"]
            self.assertEqual(sum(counts.values()), 144)
            self.assertEqual(counts["false_alert"], 0)
            self.assertEqual(counts["missed_violation"], 0)
        tiny_native = report["results"][2]["counts"]
        self.assertGreater(tiny_native["true_alert"], 0)
        self.assertGreater(tiny_native["true_within"], 0)
        self.assertGreater(report["results"][3]["counts"]["abstain_outside"], 0)

    def test_always_alert_classifier_is_exposed(self):
        with patch("pilot_evaluation._classify", return_value=("OUTSIDE_TOLERANCE", None, None)):
            report = evaluate()
        self.assertGreater(report["results"][0]["counts"]["false_alert"], 0)

    def test_always_accept_classifier_is_exposed(self):
        with patch("pilot_evaluation._classify", return_value=("WITHIN_TOLERANCE", None, None)):
            report = evaluate()
        self.assertGreater(report["results"][2]["counts"]["missed_violation"], 0)

    def test_arithmetic_abstain_does_not_publish_partial_scores(self):
        with patch("rational_oracle.binary64_assumptions_hold", return_value=False):
            report = evaluate()
        self.assertEqual(report["status"], "ABSTAIN")
        self.assertEqual(report["results"], [])
