# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Unit tests for the interactive configuration wizard (ash config wizard)."""

import os

import yaml
import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.config import (
    config_app,
    _get_scanner_names,
    _get_reporter_names,
    _prompt_toggle_items,
)
from tests.unit.config._plugin_module_helpers import (
    INSTALLED,
    SEC_ONE,
    plant_site_and_environment,
)

pytestmark = pytest.mark.unit


@pytest.fixture
def cli_runner():
    return CliRunner()


@pytest.fixture
def root(tmp_path, monkeypatch):
    return plant_site_and_environment(tmp_path, monkeypatch)


@pytest.fixture
def config_path(tmp_path):
    return tmp_path / ".ash" / ".ash.yaml"


def _unfolded(output: str) -> str:
    """*output* with whitespace and the panels' border glyphs removed, so a
    value a panel folded across lines reads contiguously again."""
    return "".join(ch for ch in output if not ch.isspace() and ch not in "│╭╮╰╯─")


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
        reporter_answers = {
            python_name: True for python_name, _ in _get_reporter_names()
        }
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
        """New community plugin modules are written to the config.

        The typed module's top-level package ends in ``_ash_plugins``, which puts
        it inside ASH's plugin namespace (plugins/loader.py's rule): the wizard
        refuses a module outside the namespace before writing, as a scan of the
        written file would, and writes one inside it whether or not a package
        provides it yet.
        """
        user_input = self._build_input(
            new_modules=["my_company_ash_plugins.scanners"],
        )
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=user_input,
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        with open(config_path) as f:
            data = yaml.safe_load(f)

        assert "my_company_ash_plugins.scanners" in data.get("ash_plugin_modules", [])

    def test_the_wizard_keeps_a_listed_module_and_adds_one(
        self, cli_runner, config_path, root
    ):
        """A plain listed module the user drops goes, the one kept stays first,
        and the added module follows it in the written file."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            yaml.dump(
                {
                    "project_name": "seed-project",
                    "ash_plugin_modules": [INSTALLED, SEC_ONE],
                }
            )
        )

        # Inside ASH's plugin namespace by its top-level package, as the planted
        # names are; the wizard refuses a typed module outside it before writing.
        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=self._build_input(
                project_name="seed-project",
                existing_module_keeps=[False, True],
                new_modules=["my_company_ash_plugins.extra"],
            ),
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        data = yaml.safe_load(config_path.read_text())
        assert data["ash_plugin_modules"] == [SEC_ONE, "my_company_ash_plugins.extra"]

    def test_wizard_keeps_output_formats_loadable(self, cli_runner, config_path):
        """An existing output_formats list comes back as names, not Python tags.

        The wizard writes with PyYAML's full Dumper, which wrote an
        ``ExportFormat`` member as a ``!!python/object/apply`` tag that no later
        load could read.
        """
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(
            yaml.dump({"project_name": "seed-project", "output_formats": ["sarif"]})
        )

        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=self._build_input(project_name="seed-project"),
        )
        assert result.exit_code == 0, f"wizard failed: {result.output}"

        text = config_path.read_text()
        assert "!!python" not in text
        assert yaml.safe_load(text)["output_formats"] == ["sarif"]

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

    @pytest.mark.skipif(
        os.name == "nt", reason="a control character cannot appear in a Windows name"
    )
    def test_wizard_panels_show_a_control_in_the_config_path_as_text(
        self, cli_runner, tmp_path
    ):
        """The loading and written panels print the config path shown.

        Rich's Text strips only a few controls, not ESC, so a config path whose
        name carries a terminal control sequence (here an OSC 52 clipboard
        write, built with chr) would otherwise reach an interactive terminal
        raw. Both panels name the path, so both outputs are checked at once.
        """
        osc = chr(0x1B) + "]52;c;aGk=" + chr(0x1B) + chr(0x5C)
        config_path = tmp_path / ("cfg-" + osc) / ".ash.yaml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(yaml.dump({"project_name": "seed-project"}))

        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=self._build_input(project_name="seed-project"),
        )

        assert result.exit_code == 0, f"wizard failed: {result.output}"
        # The controls: both panels printed and named the path.
        assert "Loading existing config from" in result.output
        assert "Config written to" in result.output
        assert chr(0x1B) not in result.output, repr(result.output)
        # Shown as the text of its escape instead; the panel folds a long
        # line between its borders, so compare with whitespace and the
        # panel's own glyphs removed. Counted, not searched: both panels name
        # the path, and a membership check would stay green if one of them
        # stopped.
        flat = _unfolded(result.output)
        assert flat.count("\\x1b]52;c;aGk=") >= 2, repr(result.output)

    def test_wizard_panels_show_a_plain_config_path_unchanged(
        self, cli_runner, config_path
    ):
        """The must-not-fire side: a plain name prints as it is, in both panels."""
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(yaml.dump({"project_name": "seed-project"}))

        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=self._build_input(project_name="seed-project"),
        )

        assert result.exit_code == 0, f"wizard failed: {result.output}"
        assert "Loading existing config from" in result.output
        assert "Config written to" in result.output
        # Both sides unfolded: _unfolded strips whitespace from the output, so
        # a path holding a space would otherwise count 0 however often the
        # panels name it.
        flat = _unfolded(result.output)
        assert flat.count(_unfolded(str(config_path.absolute()))) >= 2, repr(
            result.output
        )
        assert chr(0x1B) not in result.output, repr(result.output)

    def test_wizard_panels_count_a_path_with_a_space_in_both_panels(
        self, cli_runner, tmp_path
    ):
        """The count survives a space in the path: the comparison unfolds the
        searched path as it unfolds the output, so a name whitespace sits in
        is still found in both panels rather than counted 0."""
        config_path = tmp_path / "has space" / ".ash" / ".ash.yaml"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(yaml.dump({"project_name": "seed-project"}))

        result = cli_runner.invoke(
            config_app,
            ["wizard", "--config", str(config_path)],
            input=self._build_input(project_name="seed-project"),
        )

        assert result.exit_code == 0, f"wizard failed: {result.output}"
        flat = _unfolded(result.output)
        assert flat.count(_unfolded(str(config_path.absolute()))) >= 2, repr(
            result.output
        )

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


# --- The wizard's two path panels, with a planted name -------------------------
#
# The loading and written panels print the config path through shown_on_one_line
# inside a Text, so a terminal control in the path draws as its escape and a
# newline the name carries cannot start a fresh output line. These cells plant a
# name holding a BEL-terminated OSC 52 clipboard write and a newline followed by
# a CI command ("::add-mask::"), built with chr so this file holds no raw
# control, and read each invariant on its own.

ESC, BEL = chr(0x1B), chr(0x07)
OSC52 = ESC + "]52;c;ZXZpbA==" + BEL
MASK = "::add-mask::wizard-mask-831"

pytestmark_controls = pytest.mark.skipif(
    os.name == "nt", reason="a control character cannot appear in a Windows name"
)


@pytest.fixture
def plain_console(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("FORCE_COLOR", raising=False)
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.chdir(tmp_path)
    return tmp_path


def _unboxed(output: str) -> list:
    """Each output line with a panel's border characters and padding taken off."""
    return [line.strip(" │┃|╭╮╰╯─") for line in output.splitlines()]


def _planted_name() -> str:
    return "cfg" + OSC52 + "x\n" + MASK + ".yaml"


def _loading_run(tmp_path):
    """The loading panel alone: the planted config is invalid, so the wizard
    prints the panel and refuses without prompting."""
    path = tmp_path / _planted_name()
    path.write_text("project_name: t\nfail_on_findings: maybe\n", encoding="utf-8")
    return CliRunner().invoke(config_app, ["wizard", "--config", str(path)])


def _written_run(tmp_path):
    path = tmp_path / _planted_name()
    lines = ["seed-project"]
    lines += ["" for _ in _get_scanner_names()]
    lines += ["" for _ in _get_reporter_names()]
    lines += ["y", ""]
    return path, CliRunner().invoke(
        config_app, ["wizard", "--config", str(path)], input="\n".join(lines) + "\n"
    )


@pytestmark_controls
def test_the_loading_panel_is_reached_with_a_planted_name(plain_console):
    result = _loading_run(plain_console)
    assert "Loading existing config from" in result.output, result.output[-2000:]


@pytestmark_controls
def test_the_loading_panel_writes_no_raw_control(plain_console):
    result = _loading_run(plain_console)
    assert ESC not in result.output and BEL not in result.output, repr(
        result.output[:1500]
    )


@pytestmark_controls
def test_the_loading_panel_writes_no_st_terminated_osc(plain_console):
    """The same OSC 52 ended by ST (ESC backslash) instead of BEL: Rich strips a
    BEL from a Text, never an ESC, so this form would reach the stream whole."""
    path = plain_console / ("cfg" + ESC + "]52;c;ZXZpbA==" + ESC + "\\x.yaml")
    path.write_text("project_name: t\nfail_on_findings: maybe\n", encoding="utf-8")
    result = CliRunner().invoke(config_app, ["wizard", "--config", str(path)])
    assert "Loading existing config from" in result.output, result.output[-2000:]
    assert ESC + "]52" not in result.output, repr(result.output[:1500])


@pytestmark_controls
def test_the_loading_panel_names_the_path_on_one_line(plain_console):
    result = _loading_run(plain_console)
    panel = [
        line
        for line in result.output.splitlines()
        if "Loading existing config from" in line
    ]
    assert panel and MASK in panel[0], repr(result.output[:1500])


@pytestmark_controls
def test_the_loading_panel_starts_no_line_with_a_ci_command(plain_console):
    result = _loading_run(plain_console)
    assert [line for line in _unboxed(result.output) if line.startswith("::")] == [], (
        repr(result.output[:1500])
    )


@pytestmark_controls
def test_the_written_panel_is_reached_with_a_planted_name(plain_console):
    path, result = _written_run(plain_console)
    assert result.exit_code == 0 and path.exists(), (
        result.exit_code,
        result.output[-2000:],
    )
    assert "Config written to" in result.output, result.output[-2000:]


@pytestmark_controls
def test_the_written_panel_writes_no_raw_control(plain_console):
    _, result = _written_run(plain_console)
    assert ESC not in result.output and BEL not in result.output, repr(
        result.output[-1500:]
    )


@pytestmark_controls
def test_the_written_panel_names_the_path_on_one_line(plain_console):
    _, result = _written_run(plain_console)
    panel = [line for line in result.output.splitlines() if "Config written to" in line]
    assert panel and MASK in panel[0], repr(result.output[-1500:])


def test_a_value_the_wizard_read_from_the_environment_is_never_printed(
    plain_console, monkeypatch
):
    monkeypatch.setenv("ASH_WIZARD_NAME", "envvalue-wizard-4412")
    path = plain_console / ".ash.yaml"
    path.write_text("project_name: ${ASH_WIZARD_NAME}\n", encoding="utf-8")
    result = CliRunner().invoke(
        config_app, ["wizard", "--config", str(path)], input="\n" * 80
    )
    assert "envvalue-wizard-4412" not in result.output, result.output[-2000:]
    assert result.exit_code != 0, result.output[-2000:]
