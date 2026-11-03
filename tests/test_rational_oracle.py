"""Adversarial and seeded tests for the independent rational recurrence oracle."""
import math
import random
import unittest
from unittest.mock import patch

from evidence_v1 import make_evidence, verify_evidence
from logistic_map import logistic_orbit
from rational_oracle import verify_recurrence


class RationalOracleTest(unittest.TestCase):
    @staticmethod
    def encoded(rate, initial, steps):
        return [state.hex() for state in logistic_orbit(rate, initial, steps)]

    def test_forty_seeded_full_budget_orbits(self):
        rng = random.Random(20261102)
        for case in range(40):
            rate = rng.uniform(0.05, 4.0)
            initial = rng.uniform(0.000001, 0.999999)
            with self.subTest(case=case):
                result = verify_recurrence(rate, initial, self.encoded(rate, initial, 1000))
                self.assertEqual(result[0], "PASS", result[1])

    def test_zero_rate_and_underflow(self):
        for rate, initial in ((0.0, 0.2), (0.05, 0.01), (4.0, 0.25)):
            with self.subTest(rate=rate):
                self.assertEqual(
                    verify_recurrence(rate, initial, self.encoded(rate, initial, 1000))[0],
                    "PASS",
                )

    def test_detects_modified_middle_step(self):
        orbit = self.encoded(3.9, 0.2, 20)
        orbit[5] = 0.2345.hex()
        result = verify_recurrence(3.9, 0.2, orbit)
        self.assertEqual(result[0], "FAIL")
        self.assertIn("step", result[1])

    def test_rejects_wrong_initial_condition(self):
        orbit = self.encoded(3.9, 0.2, 5)
        self.assertEqual(verify_recurrence(3.9, 0.3, orbit)[0], "FAIL")

    def test_rejects_noncanonical_hex(self):
        orbit = self.encoded(3.9, 0.2, 5)
        orbit[1] = orbit[1].upper()
        self.assertEqual(verify_recurrence(3.9, 0.2, orbit)[0], "FAIL")

    def test_rejects_nan_and_infinity(self):
        for value in ("nan", "inf", "-inf"):
            with self.subTest(value=value):
                orbit = self.encoded(3.9, 0.2, 5)
                orbit[2] = value
                self.assertEqual(verify_recurrence(3.9, 0.2, orbit)[0], "FAIL")

    def test_rejects_out_of_interval_state(self):
        orbit = self.encoded(3.9, 0.2, 5)
        orbit[2] = (1.5).hex()
        self.assertEqual(verify_recurrence(3.9, 0.2, orbit)[0], "FAIL")

    def test_rejects_oversized_hex_input(self):
        orbit = self.encoded(3.9, 0.2, 5)
        orbit[2] = "0x" + "0" * 100000
        self.assertEqual(verify_recurrence(3.9, 0.2, orbit)[0], "FAIL")

    def test_rejects_oversized_work(self):
        orbit = [0.2.hex()] * 1002
        self.assertEqual(verify_recurrence(3.9, 0.2, orbit)[0], "FAIL")

    def test_rejects_boolean_parameters(self):
        orbit = self.encoded(3.9, 0.2, 5)
        self.assertEqual(verify_recurrence(True, 0.2, orbit)[0], "FAIL")
        self.assertEqual(verify_recurrence(3.9, False, orbit)[0], "FAIL")

    def test_rejects_nonfinite_parameters(self):
        orbit = self.encoded(3.9, 0.2, 5)
        self.assertEqual(verify_recurrence(math.inf, 0.2, orbit)[0], "FAIL")
        self.assertEqual(verify_recurrence(3.9, math.nan, orbit)[0], "FAIL")

    def test_even_forged_local_replay_cannot_pass_oracle(self):
        # Both make_evidence and its original replay use the patched simulator.
        # The independent Fraction-based recurrence must still reject the data.
        fake = [0.2] + [0.6] * 5
        with patch("evidence_v1.logistic_orbit", return_value=fake):
            record = make_evidence(3.9, 0.2, 5)
            status, reason = verify_evidence(record)
        self.assertEqual(status, "FAIL")
        self.assertIn("mathematical recurrence", reason)

    def test_genuine_record_passes_both_verifiers(self):
        record = make_evidence(3.9, 0.2, 100)
        status, reason = verify_evidence(record)
        self.assertEqual(status, "PASS", reason)


if __name__ == "__main__":
    unittest.main()
