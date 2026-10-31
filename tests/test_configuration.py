
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
SECURITY_GROUP = "security"

BANDIT_COMMAND = (
    f"uv run --locked --group {SECURITY_GROUP} bandit "
    "-q -r . -x ./.venv,./.git"
)


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

    def test_security_tools_are_lock_managed(self) -> None:
        project_path = REPOSITORY_ROOT / "pyproject.toml"

        with project_path.open("rb") as project_file:
            project = tomllib.load(project_file)

        self.assertCountEqual(
            project["dependency-groups"][SECURITY_GROUP],
            [
                f"bandit=={BANDIT_VERSION}",
                f"pip-audit=={PIP_AUDIT_VERSION}",
            ],
        )

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

        self.assertIn(BANDIT_COMMAND, workflow)
        self.assertIn(
            f"uv run --locked --group {SECURITY_GROUP} pip-audit --strict "
            "--path .venv/lib/python3.14/site-packages",
            workflow,
        )

        self.assertNotIn("uvx ", workflow)

        external_actions = re.findall(
            r"^\s*uses:\s*([^\s#]+)",
            workflow,
            flags=re.MULTILINE,
        )

        self.assertTrue(external_actions)

        for action in external_actions:
            if action.startswith("./"):
                continue
            with self.subTest(action=action):
                self.assertRegex(action, r"^[^@]+@[0-9a-f]{40}$")
