import json
import re
import tomllib
import unittest
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).parents[1]
UV_VERSION = "0.13.0"
BANDIT_VERSION = "1.9.4"
PIP_AUDIT_VERSION = "2.10.1"
CI_RUNNER = "ubuntu-24.04"
CI_TIMEOUT_MINUTES = 10


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

        self.assertIn(f"pipx install --force uv=={UV_VERSION}", update_command)
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

    def test_ci_enforces_reproducible_security_gates(self) -> None:
        workflow_path = (
            REPOSITORY_ROOT / ".github" / "workflows" / "smoke-test.yml"
        )
        workflow = workflow_path.read_text(encoding="utf-8")

        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("persist-credentials: false", workflow)
        self.assertIn(f"runs-on: {CI_RUNNER}", workflow)
        self.assertIn(f"timeout-minutes: {CI_TIMEOUT_MINUTES}", workflow)
        self.assertIn(f'version: "{UV_VERSION}"', workflow)
        self.assertIn("uv lock --check", workflow)
        self.assertIn(f"bandit=={BANDIT_VERSION}", workflow)
        self.assertIn(f"pip-audit=={PIP_AUDIT_VERSION}", workflow)
        self.assertIn("pip-audit --strict", workflow)
        self.assertRegex(
            workflow,
            re.compile(r"uses: actions/checkout@[0-9a-f]{40}"),
        )
        self.assertRegex(
            workflow,
            re.compile(r"uses: astral-sh/setup-uv@[0-9a-f]{40}"),
        )
