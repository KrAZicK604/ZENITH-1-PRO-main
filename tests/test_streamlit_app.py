import unittest
from pathlib import Path

from streamlit.testing.v1 import AppTest


class StreamlitAppSmokeTest(unittest.TestCase):
    def test_entry_point_renders_without_exceptions(self) -> None:
        app_path = Path(__file__).parents[1] / "streamlit_app.py"
        app = AppTest.from_file(str(app_path)).run()

        self.assertFalse(app.exception)
        self.assertEqual(app.title[0].value, "🎈 My new app")
