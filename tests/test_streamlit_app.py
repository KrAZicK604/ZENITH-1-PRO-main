import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


class StreamlitAppSmokeTest(unittest.TestCase):
    def test_entry_point_renders_without_exceptions(self) -> None:
        app_path = Path(__file__).parents[1] / "streamlit_app.py"
        app = AppTest.from_file(str(app_path)).run(timeout=10)

        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, "ZENITH-1-PRO Logistic Map Lab")
        self.assertEqual(len(app.slider), 3)

    def test_control_boundaries_render_without_exceptions(self) -> None:
        app_path = Path(__file__).parents[1] / "streamlit_app.py"
        boundary_cases = (
            (0.0, 0.001, 10),
            (4.0, 0.999, 500),
        )

        for rate, initial_state, iterations in boundary_cases:
            with self.subTest(
                rate=rate,
                initial_state=initial_state,
                iterations=iterations,
            ):
                app = AppTest.from_file(str(app_path)).run(timeout=10)
                app.slider[0].set_value(rate)
                app.slider[1].set_value(initial_state)
                app.slider[2].set_value(iterations)
                app.run(timeout=10)

                self.assertFalse(app.exception)
