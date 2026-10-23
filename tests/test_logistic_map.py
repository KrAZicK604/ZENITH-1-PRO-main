import math
import unittest

from logistic_map import MAX_ITERATIONS, logistic_orbit, lyapunov_exponent


class LogisticOrbitTest(unittest.TestCase):
    def test_known_orbit(self) -> None:
        self.assertEqual(logistic_orbit(4.0, 0.5, 3), [0.5, 1.0, 0.0, 0.0])

    def test_result_is_deterministic_and_bounded(self) -> None:
        first = logistic_orbit(3.9, 0.2, 100)
        second = logistic_orbit(3.9, 0.2, 100)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 101)
        self.assertTrue(all(0.0 <= state <= 1.0 for state in first))

    def test_accepts_ui_boundaries_at_maximum_work(self) -> None:
        for rate in (0.0, 4.0):
            for initial_state in (0.001, 0.999):
                with self.subTest(rate=rate, initial_state=initial_state):
                    orbit = logistic_orbit(rate, initial_state, MAX_ITERATIONS)

                    self.assertEqual(len(orbit), MAX_ITERATIONS + 1)
                    self.assertTrue(all(0.0 <= state <= 1.0 for state in orbit))

    def test_rejects_invalid_rate(self) -> None:
        for rate in (-0.01, 4.01, math.inf, math.nan):
            with self.subTest(rate=rate):
                with self.assertRaises(ValueError):
                    logistic_orbit(rate, 0.2, 10)

    def test_rejects_invalid_initial_state(self) -> None:
        for initial_state in (0.0, 1.0, math.inf, math.nan):
            with self.subTest(initial_state=initial_state):
                with self.assertRaises(ValueError):
                    logistic_orbit(3.9, initial_state, 10)

    def test_rejects_unbounded_iteration_requests(self) -> None:
        for iterations in (0, MAX_ITERATIONS + 1):
            with self.subTest(iterations=iterations):
                with self.assertRaises(ValueError):
                    logistic_orbit(3.9, 0.2, iterations)

    def test_rejects_non_numeric_or_boolean_inputs(self) -> None:
        invalid_arguments = (
            ("3.9", 0.2, 10),
            (3.9, "0.2", 10),
            (3.9, 0.2, True),
        )
        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                with self.assertRaises(TypeError):
                    logistic_orbit(*arguments)


class LyapunovExponentTest(unittest.TestCase):
    def test_known_exponent_for_fixed_orbit(self) -> None:
        exponent = lyapunov_exponent(4.0, 0.25, 20, discard=5)

        self.assertAlmostEqual(exponent, math.log(2.0), places=12)

    def test_distinguishes_contracting_and_chaotic_regimes(self) -> None:
        contracting = lyapunov_exponent(2.5, 0.2, 200, discard=100)
        chaotic = lyapunov_exponent(4.0, 0.25, 200, discard=100)

        self.assertLess(contracting, 0.0)
        self.assertGreater(chaotic, 0.0)

    def test_zero_derivative_returns_negative_infinity(self) -> None:
        exponent = lyapunov_exponent(4.0, 0.5, 10)

        self.assertEqual(exponent, float("-inf"))

    def test_rejects_invalid_discard(self) -> None:
        for discard in (-1, 10):
            with self.subTest(discard=discard):
                with self.assertRaises(ValueError):
                    lyapunov_exponent(3.9, 0.2, 10, discard=discard)

        for discard in (True, 1.5):
            with self.subTest(discard=discard):
                with self.assertRaises(TypeError):
                    lyapunov_exponent(3.9, 0.2, 10, discard=discard)
