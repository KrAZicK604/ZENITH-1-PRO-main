"""Decision boundaries, proof obligations and negative pilot controls."""
from fractions import Fraction as Q
import unittest
from unittest.mock import patch

from interval_oracle import ideal_orbit_intervals
from prediction_pilot import _classify, assess_prediction, demonstration


class PredictionPilotTest(unittest.TestCase):
    def test_upper_bound_alone_cannot_prove_outside(self):
        self.assertEqual(_classify(Q(1, 2), Q(0), Q(1), Q(1, 10))[0], "ABSTAIN")

    def test_exact_tolerance_is_within(self):
        self.assertEqual(_classify(Q(0), Q(1, 4), Q(1, 4), Q(1, 4))[0],
                         "WITHIN_TOLERANCE")
        self.assertEqual(_classify(Q(0), Q(1, 4), Q(1, 2), Q(1, 4))[0], "ABSTAIN")

    def test_outside_requires_strict_positive_separation(self):
        decision, low, high = _classify(Q(0), Q(1, 2), Q(3, 4), Q(1, 4))
        self.assertEqual((decision, low, high), ("OUTSIDE_TOLERANCE", Q(1, 2), Q(3, 4)))

    def test_partition_samples_support_each_reported_decision(self):
        for a in range(5):
            for b in range(a, 5):
                for z in range(5):
                    decision, low, high = _classify(Q(z, 4), Q(a, 4), Q(b, 4), Q(1, 4))
                    for k in range(a*2, b*2+1):
                        error = abs(Q(z, 4)-Q(k, 8))
                        self.assertLessEqual(low, error)
                        self.assertLessEqual(error, high)
                        if decision == "WITHIN_TOLERANCE":
                            self.assertLessEqual(error, Q(1, 4))
                        elif decision == "OUTSIDE_TOLERANCE":
                            self.assertGreater(error, Q(1, 4))

    def test_demo_is_reproducible_and_separates_control(self):
        report = demonstration()
        self.assertEqual(report, demonstration())
        drift, control = [x["assessment"] for x in report["cases"]]
        self.assertEqual(drift["final"]["decision"], "OUTSIDE_TOLERANCE")
        self.assertGreater(Q(drift["final"]["absolute_error_lower"]), Q(1, 2))
        self.assertEqual(control["counts"]["WITHIN_TOLERANCE"], 1001)
        self.assertIsNone(control["first_outside_step"])
        for assessment in (drift, control):
            self.assertEqual(sum(assessment["counts"].values()), assessment["state_count"])
            self.assertEqual(assessment["productionAuthority"], "NONE")

    def test_malformed_tolerances_and_orbits_fail(self):
        orbit = [0.75.hex()]*2
        for tolerance in (None, True, "nan", "1e-6", "1/0", "0/1", "2/1", "1/"+"9"*1000):
            self.assertEqual(assess_prediction(4.0, 0.75, orbit, tolerance)["status"], "FAIL")
        self.assertEqual(assess_prediction(4.0, 0.75, ["nan"]*2)["status"], "FAIL")

    def test_unsupported_arithmetic_abstains_without_decision(self):
        with patch("rational_oracle.binary64_assumptions_hold", return_value=False):
            report = assess_prediction(4.0, 0.75, [0.75.hex()]*2)
        self.assertEqual(report["status"], "ABSTAIN")
        self.assertNotIn("final", report)

    def test_caller_mutation_does_not_change_report(self):
        orbit = [0.75.hex()]*2

        def validate_then_edit(*args):
            result = ideal_orbit_intervals(*args)
            orbit[:] = ["nan"]*2002
            return result

        with patch("prediction_pilot.ideal_orbit_intervals", side_effect=validate_then_edit):
            report = assess_prediction(4.0, 0.75, orbit)
        self.assertEqual(report["state_count"], 2)
        self.assertEqual(report["counts"]["WITHIN_TOLERANCE"], 2)
