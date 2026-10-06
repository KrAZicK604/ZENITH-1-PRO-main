import math
import unittest

from logistic_map import MAX_ITERATIONS, logistic_orbit


class LogisticOrbitTest(unittest.TestCase):
    def test_known_orbit(self) -> None:
        self.assertEqual(logistic_orbit(4.0, 0.5, 3), [0.5, 1.0, 0.0, 0.0])

    def test_result_is_deterministic_and_bounded(self) -> None:
        first = logistic_orbit(3.9, 0.2, 100)
        second = logistic_orbit(3.9, 0.2, 100)

        self.assertEqual(first, second)
        self.assertEqual(len(first), 101)
        self.assertTrue(all(0.0 <= state <= 1.0 for state in first))

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
