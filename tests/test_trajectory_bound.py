"""Exact ideal-orbit checks and uncertainty controls for global bounds."""
from fractions import Fraction
import unittest
from unittest.mock import patch

from logistic_map import logistic_orbit
from trajectory_bound import GRID, trajectory_error_bounds


class TrajectoryBoundTest(unittest.TestCase):
    def test_encloses_exact_real_orbits(self):
        # Short exact iterates have exponentially growing denominators; this
        # oracle is independent of the linear Lipschitz propagation formula.
        for rate, initial in ((3.9, 0.2), (0.5, 0.3), (4.0, 0.25), (0.0, 0.2)):
            states = logistic_orbit(rate, initial, 10)
            status, _, bounds = trajectory_error_bounds(rate, initial, [x.hex() for x in states])
            self.assertEqual(status, "PASS")
            exact, r = Fraction.from_float(initial), Fraction.from_float(rate)
            for state, bound in zip(states, bounds):
                self.assertLessEqual(abs(Fraction.from_float(state) - exact), bound)
                self.assertLessEqual(bound, 1)
                self.assertEqual((bound * GRID).denominator, 1)
                exact = r * exact * (1 - exact)

    def test_exact_fixed_orbit_has_zero_error(self):
        self.assertEqual(trajectory_error_bounds(4.0, 0.75, [0.75.hex()] * 1001)[2],
                         (Fraction(0),) * 1001)

    def test_chaotic_local_pass_can_have_unit_global_bound(self):
        states = logistic_orbit(3.9, 0.2, 1000)
        status, _, bounds = trajectory_error_bounds(3.9, 0.2, [x.hex() for x in states])
        self.assertEqual(status, "PASS")
        self.assertEqual(bounds[-1], 1)
        self.assertEqual(len(bounds), 1001)

    def test_subnormal_and_contraction_full_budget(self):
        states = logistic_orbit(0.5, 0.2, 1000)
        status, _, bounds = trajectory_error_bounds(0.5, 0.2, [x.hex() for x in states])
        self.assertEqual(status, "PASS")
        self.assertLess(bounds[-1], Fraction(1, 2**1000))
        self.assertTrue(all(b.denominator <= GRID for b in bounds))

    def test_bad_or_oversized_orbits_have_no_enclosure(self):
        for orbit in ([0.2.hex(), 0.9.hex()], [0.2.hex()] * 1002, ["nan", "nan"]):
            status, _, bounds = trajectory_error_bounds(3.9, 0.2, orbit)
            self.assertEqual(status, "FAIL")
            self.assertEqual(bounds, ())

    def test_unsupported_arithmetic_abstains(self):
        with patch("rational_oracle.binary64_assumptions_hold", return_value=False):
            self.assertEqual(trajectory_error_bounds(4.0, 0.75, [0.75.hex()] * 2)[::2],
                             ("ABSTAIN", ()))
