import json
import tomllib
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).parents[1]


class ConfigurationTest(unittest.TestCase):
    def test_devcontainer_is_valid_json(self) -> None:
        config_path = REPOSITORY_ROOT / ".devcontainer" / "devcontainer.json"

        with config_path.open(encoding="utf-8") as config_file:
            json.load(config_file)

    def test_devcontainer_uses_locked_package_manager_commands(self) -> None:
        config_path = REPOSITORY_ROOT / ".devcontainer" / "devcontainer.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        update_command = config["updateContentCommand"]
        server_command = config["postAttachCommand"]["server"]

        self.assertIn("pipx install uv", update_command)
        self.assertNotIn("curl", update_command)
        self.assertNotIn("| sh", update_command)
        self.assertIn("UV_PROJECT_ENVIRONMENT=", update_command)
        self.assertIn("zenith-1-pro", update_command)
        self.assertIn("uv sync --locked", update_command)
        self.assertIn("uv run --locked", server_command)
        self.assertNotIn("--server.enableCORS false", server_command)
        self.assertNotIn("--server.enableXsrfProtection false", server_command)

    def test_streamlit_security_protections_are_enabled(self) -> None:
        config_path = REPOSITORY_ROOT / ".streamlit" / "config.toml"

        with config_path.open("rb") as config_file:
            config = tomllib.load(config_file)

        self.assertIs(config["server"]["enableCORS"], True)
        self.assertIs(config["server"]["enableXsrfProtection"], True)
        self.assertIs(config["browser"]["gatherUsageStats"], False)
