import unittest

from periodicity import estimate_period


class PeriodicityTests(unittest.TestCase):
    def test_detects_fixed_point_and_cycle(self) -> None:
        self.assertEqual(estimate_period([0.5, 0.5, 0.5, 0.5]), 1)
        self.assertEqual(estimate_period([1.0, 0.0, 1.0, 0.0, 1.0, 0.0]), 2)

    def test_ignores_non_repeating_transient(self) -> None:
        orbit = [0.1, 0.2, 0.3, 0.4, 0.2, 0.3, 0.4, 0.2, 0.3, 0.4]
        self.assertEqual(estimate_period(orbit, max_period=5), 3)

    def test_rejects_invalid_inputs(self) -> None:
        with self.assertRaises(ValueError):
            estimate_period([])
        with self.assertRaises(ValueError):
            estimate_period([0.5], max_period=0)
        with self.assertRaises(TypeError):
            estimate_period([0.5], tolerance=True)


if __name__ == "__main__":
    unittest.main()
