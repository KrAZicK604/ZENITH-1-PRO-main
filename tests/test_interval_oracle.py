"""Exact-orbit, critical-point, rounding and hostile-input controls."""
from fractions import Fraction as Q
import unittest
from unittest.mock import patch

from interval_oracle import GRID, _image, ideal_orbit_intervals
from logistic_map import logistic_orbit
from rational_oracle import verify_recurrence
from trajectory_bound import trajectory_error_bounds


class IntervalOracleTest(unittest.TestCase):
    def test_critical_point_is_included(self):
        self.assertEqual(_image(Q(4), Q(1, 4), Q(3, 4)), (Q(3, 4), Q(1)))
        self.assertEqual(_image(Q(4), Q(0), Q(1)), (Q(0), Q(1)))

    def test_small_dyadic_partition_contains_every_sample_image(self):
        for r in (Q(0), Q(1, 2), Q(3), Q(4)):
            for a in range(8):
                for b in range(a + 1, 9):
                    lo, hi = _image(r, Q(a, 8), Q(b, 8))
                    for k in range(a * 2, b * 2 + 1):
                        x = Q(k, 16)
                        self.assertLessEqual(lo, r*x*(1-x))
                        self.assertLessEqual(r*x*(1-x), hi)

    def test_encloses_independently_iterated_exact_orbits(self):
        for rate, initial in ((3.9, 0.2), (0.5, 0.3), (4.0, 0.25), (0.0, 0.2)):
            orbit = [x.hex() for x in logistic_orbit(rate, initial, 10)]
            status, _, intervals = ideal_orbit_intervals(rate, initial, orbit)
            self.assertEqual(status, "PASS")
            x, r = Q.from_float(initial), Q.from_float(rate)
            for lo, hi in intervals:
                self.assertLessEqual(lo, x)
                self.assertLessEqual(x, hi)
                self.assertLessEqual(lo.denominator, GRID)
                self.assertLessEqual(hi.denominator, GRID)
                x = r*x*(1-x)

    def test_rounding_is_outward_at_subnormal_scale(self):
        tiny = Q(1, GRID)
        self.assertEqual(_image(Q(1, 2), tiny, tiny), (Q(0), tiny))

    def test_full_budget_exact_fixed_point(self):
        status, _, intervals = ideal_orbit_intervals(4.0, 0.75, [0.75.hex()]*1001)
        self.assertEqual(status, "PASS")
        self.assertEqual(intervals, ((Q(3, 4), Q(3, 4)),)*1001)

    def test_narrow_ideal_interval_can_exclude_float_trajectory(self):
        states = logistic_orbit(3.9, 0.2, 1000)
        orbit = [x.hex() for x in states]
        status, _, intervals = ideal_orbit_intervals(3.9, 0.2, orbit)
        self.assertEqual(status, "PASS")
        lo, hi = intervals[-1]
        self.assertLess(hi-lo, Q(1, 10**100))
        self.assertGreater(Q.from_float(states[-1])-hi, Q(1, 2))
        global_bounds = trajectory_error_bounds(3.9, 0.2, orbit)[2]
        errors = [max(abs(Q.from_float(z)-a), abs(Q.from_float(z)-b))
                  for z, (a, b) in zip(states, intervals)]
        threshold = Q(1, 10**6)
        first = lambda values: next(i for i, value in enumerate(values) if value > threshold)
        self.assertGreater(first(errors), first(global_bounds))

    def test_validation_snapshot_survives_caller_edit(self):
        orbit = [0.75.hex()]*2

        def validate_then_edit(*args):
            result = verify_recurrence(*args)
            orbit[:] = ["nan"]*2002
            return result

        with patch("interval_oracle.verify_recurrence", side_effect=validate_then_edit):
            self.assertEqual(ideal_orbit_intervals(4.0, 0.75, orbit)[2],
                             ((Q(3, 4), Q(3, 4)),)*2)

    def test_invalid_inputs_and_arithmetic_abstain(self):
        for orbit in (None, (), [], [0.75.hex()]*1002, ["nan"]*2,
                      [0.75.hex(), 0.25.hex()]):
            self.assertEqual(ideal_orbit_intervals(4.0, 0.75, orbit)[::2], ("FAIL", ()))
        with patch("rational_oracle.binary64_assumptions_hold", return_value=False):
            self.assertEqual(ideal_orbit_intervals(4.0, 0.75, [0.75.hex()]*2)[::2],
                             ("ABSTAIN", ()))
