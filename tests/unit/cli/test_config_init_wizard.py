# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the interactive configuration wizard (ash config wizard)."""

import yaml
import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import (
    config_app,
    _get_scanner_names,
    _get_reporter_names,
    _prompt_toggle_items,
)


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / ".ash" / ".ash.yaml"


class TestHelperFunctions:
    """Tests for the internal helpers used by the wizard."""

    def test_get_scanner_names_returns_non_empty_list(self):
        names = _get_scanner_names()
        assert isinstance(names, list)
        assert len(names) > 0
        python_names = [n[0] for n in names]
        assert "bandit" in python_names

    def test_get_reporter_names_returns_non_empty_list(self):
        names = _get_reporter_names()
        assert isinstance(names, list)
        assert len(names) > 0
        python_names = [n[0] for n in names]
        assert "html" in python_names

    def test_prompt_toggle_items_respects_defaults(self, monkeypatch):
        """When user accepts all defaults, output matches input."""
        items = [("a", "A"), ("b", "B")]
        current = {"a": True, "b": False}
        responses = iter([True, False])
        monkeypatch.setattr("typer.confirm", lambda *a, **kw: next(responses))
        result = _prompt_toggle_items(items, current, "Test")
        assert result == {"a": True, "b": False}


class TestWizardCommand:
    """Integration tests for the wizard command with mocked prompts."""

    def _build_input(
        self,
        project_name="test-proj",
        scanner_answers=None,
        reporter_answers=None,
        enable_offline=False,
        existing_module_keeps=None,
        new_modules=None,
    ):
        """Build the sequence of stdin lines the wizard expects.

        The wizard prompts:
        1. Project name (text prompt)
        2. For each scanner: "Enable X? [Y/n]:" -> "Y" or "n"
        3. For each reporter: "Enable X? [Y/n]:" -> "Y" or "n"
        4. Offline reminder confirm
        5. For each existing module: "Keep module 'X'? [Y/n]:"
        6. Repeated "Add a plugin module (blank to finish):" until blank
        """
        lines = []
        # 1. project name
        lines.append(project_name)

        # 2. scanner toggles
        scanner_items = _get_scanner_names()
        if scanner_answers is None:
            scanner_answers = {python_name: True for python_name, _ in scanner_items}
        for python_name, _ in scanner_items:
            lines.append("Y" if scanner_answers.get(python_name, True) else "n")

        # 3. reporter toggles
        reporter_items = _get_reporter_names()
        if reporter_answers is None:
            reporter_answers = {python_name: True for python_name, _ in reporter_items}
        for python_name, _ in reporter_items:
            lines.append("Y" if reporter_answers.get(python_name, True) else "n")

        # 4. offline mode
        lines.append("Y" if enable_offline else "n")

        # 5. existing module keeps
        if existing_module_keeps:
            for keep in existing_module_keeps:
                lines.append("Y" if keep else "n")

        # 6. new plugin modules
        if new_modules:
            for mod in new_modules:
                lines.append(mod)
        lines.append("")  # blank to finish

        return "\n".join(lines) + "\n"

    def test_wizard_creates_config_from_scratch(self, cli_runner, config_path):
        """Wizard creates a valid config when none exists."""
        user_input = self._build_input(project_name="my-project")
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"
        assert config_path.exists()

        with open(config_path) as f:
            data = yaml.safe_load(f)

        assert data["project_name"] == "my-project"
        assert "scanners" in data
        assert "reporters" in data

    def test_wizard_disables_scanner(self, cli_runner, config_path):
        """Disabling a scanner sets its enabled field to false."""
        scanner_answers = {python_name: True for python_name, _ in _get_scanner_names()}
        scanner_answers["bandit"] = False

        user_input = self._build_input(scanner_answers=scanner_answers)
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        with open(config_path) as f:
            data = yaml.safe_load(f)

        assert data["scanners"]["bandit"]["enabled"] is False

    def test_wizard_disables_reporter(self, cli_runner, config_path):
        """Disabling a reporter sets its enabled field to false."""
        reporter_answers = {python_name: True for python_name, _ in _get_reporter_names()}
        reporter_answers["html"] = False

        user_input = self._build_input(reporter_answers=reporter_answers)
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        with open(config_path) as f:
            data = yaml.safe_load(f)

        assert data["reporters"]["html"]["enabled"] is False

    def test_wizard_offline_reminder_comment(self, cli_runner, config_path):
        """When offline mode is selected, the config includes a reminder comment."""
        user_input = self._build_input(enable_offline=True)
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        raw = config_path.read_text()
        assert "ASH_OFFLINE=YES" in raw

    def test_wizard_no_offline_reminder_by_default(self, cli_runner, config_path):
        """When offline mode is declined, no reminder comment appears."""
        user_input = self._build_input(enable_offline=False)
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        raw = config_path.read_text()
        assert "ASH_OFFLINE" not in raw

    def test_wizard_adds_community_plugin_modules(self, cli_runner, config_path):
        """New community plugin modules are written to the config."""
        user_input = self._build_input(
            new_modules=["my_company.ash_plugins.scanners"],
        )
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        with open(config_path) as f:
            data = yaml.safe_load(f)

        assert "my_company.ash_plugins.scanners" in data.get(
            "ash_plugin_modules", []
        )

    def test_wizard_reads_existing_config(self, cli_runner, config_path):
        """Wizard loads an existing config and preserves unchanged values."""
        # First create a config with a known project name
        config_path.parent.mkdir(parents=True, exist_ok=True)
        seed = {
            "project_name": "seed-project",
            "scanners": {"bandit": {"enabled": False}},
            "reporters": {"html": {"enabled": True}},
        }
        config_path.write_text(yaml.dump(seed))

        # Accept all defaults (press Enter through everything)
        # The project name prompt should default to "seed-project"
        user_input = self._build_input(project_name="seed-project")
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        with open(config_path) as f:
            data = yaml.safe_load(f)

        assert data["project_name"] == "seed-project"

    def test_wizard_excludes_internal_fields(self, cli_runner, config_path):
        """Generated config must not contain internal-only fields."""
        user_input = self._build_input()
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        with open(config_path) as f:
            data = yaml.safe_load(f)

        # Internal top-level fields
        assert "build" not in data
        assert "mcp-resource-management" not in data

        # Internal scanner fields
        internal_fields = {"name", "extension", "tool_version", "install_timeout"}
        for scanner_name, scanner_cfg in data.get("scanners", {}).items():
            if isinstance(scanner_cfg, dict):
                for field in internal_fields:
                    assert field not in scanner_cfg, (
                        f"Scanner '{scanner_name}' contains internal field '{field}'"
                    )
