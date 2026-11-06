import unittest

from bifurcation import bifurcation_points


class BifurcationTests(unittest.TestCase):
    def test_sweep_includes_rate_endpoints_and_bounded_states(self) -> None:
        points = bifurcation_points(
            2.5,
            3.5,
            rate_samples=3,
            iterations=20,
            discard=10,
            points_per_rate=4,
        )

        self.assertEqual(len(points), 12)
        self.assertEqual(points[0][0], 2.5)
        self.assertEqual(points[4][0], 3.0)
        self.assertEqual(points[8][0], 3.5)
        self.assertTrue(all(0.0 <= state <= 1.0 for _, state in points))

    def test_output_is_deterministic(self) -> None:
        options = dict(
            rate_samples=5,
            iterations=30,
            discard=20,
            points_per_rate=3,
        )
        self.assertEqual(
            bifurcation_points(2.8, 3.9, **options),
            bifurcation_points(2.8, 3.9, **options),
        )

    def test_rejects_invalid_rate_interval(self) -> None:
        with self.assertRaises(ValueError):
            bifurcation_points(3.0, 3.0)
        with self.assertRaises(ValueError):
            bifurcation_points(-0.1, 3.0)

    def test_rejects_unbounded_or_invalid_options(self) -> None:
        with self.assertRaises(ValueError):
            bifurcation_points(2.0, 4.0, rate_samples=101)
        with self.assertRaises(ValueError):
            bifurcation_points(2.0, 4.0, iterations=1)
        with self.assertRaises(ValueError):
            bifurcation_points(2.0, 4.0, iterations=10, discard=10)
        with self.assertRaises(TypeError):
            bifurcation_points(2.0, 4.0, rate_samples=True)


if __name__ == "__main__":
    unittest.main()
