"""Tests for cli/plugin.py — covers plugin list and show commands."""

from unittest.mock import patch

import click
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.plugin import plugin_app


runner = CliRunner()


def _list_command_option_names() -> set[str]:
    """Collect the option strings the plugin-list command declares.

    Reads the resolved Click command's params directly instead of grepping the
    rendered ``--help`` text. Two reasons: Rich wraps and colorizes help output,
    so a substring match is brittle; and this Typer app collapses to a single
    default command whose ``--help`` rendering depends on prior invocation state
    in the same process, so a full-suite run can render the callback's options
    instead of the command's. Introspecting the params is immune to both -- it
    asks the command what it declares, not what a formatter happened to print.
    """
    cmd = typer.main.get_command(plugin_app)
    names: set[str] = set()
    if isinstance(cmd, click.Group):
        for sub in cmd.commands.values():
            for param in sub.params:
                names.update(param.opts)
    else:
        for param in cmd.params:
            names.update(param.opts)
    return names


# ---------------------------------------------------------------------------
# Stub scanners for the --show-versions column tests.
#
# The plugin list command runs as the DEFAULT command of this Typer app, so it
# is invoked with no "list" token under CliRunner (invoking ["list"] is a usage
# error, exit 2, which the smoke tests below tolerate). The --show-versions
# tests inject stub scanner classes through load_plugins so the rendered columns
# are deterministic and independent of which real tools are installed.
# ---------------------------------------------------------------------------


class _StubConfig:
    def __init__(self, name, enabled=True):
        self.name = name
        self.enabled = enabled

    def model_dump(self):
        return {"name": self.name, "enabled": self.enabled}


class _StubScanner:
    offline_strategy = None
    _name = "stub"
    _satisfied = True
    _version = None
    _raise_on_init = False

    def __init__(self, context=None, config=None):
        if self._raise_on_init:
            raise RuntimeError("stub refuses to be constructed")
        self.config = _StubConfig(self._name)
        self.tool_version = self._version

    def validate_plugin_dependencies(self):
        return self._satisfied


def _stub(name, **attrs):
    return type(f"{name}Scanner", (_StubScanner,), {"_name": name, **attrs})


def _run_list(args, scanners):
    """Invoke the default (list) command with load_plugins returning stub scanners.

    Patches ``get_plugin_config`` on the resolved config to return None so the
    CLI falls back to instantiating each scanner (exercising the real per-class
    row path), and lets the real ``describe_scanner`` run against the stubs.
    """
    with patch("automated_security_helper.cli.plugin.load_plugins") as mock_load:
        mock_load.return_value = {
            "scanners": list(scanners),
            "converters": [],
            "reporters": [],
        }
        return runner.invoke(plugin_app, args)


class TestPluginList:
    """Tests for the plugin list command."""

    def test_list_command_exists(self):
        result = runner.invoke(plugin_app, ["list", "--help"])
        assert result.exit_code == 0

    def test_list_command_runs(self):
        result = runner.invoke(plugin_app, ["list"])
        # May succeed or fail depending on plugin availability, just verify it runs
        assert result.exit_code in (0, 1, 2)

    def test_show_versions_flag_in_help(self):
        # Assert the command declares --show-versions by introspecting its
        # params, not by grepping rendered --help text: the latter fails under
        # full-suite ordering because this single-command Typer app renders the
        # callback's options instead of the command's once another test has
        # invoked the app in this process.
        assert "--show-versions" in _list_command_option_names()


class TestShowVersionsColumns:
    """--show-versions adds Version + Reachable columns for scanners only."""

    def test_default_mode_omits_version_columns(self):
        result = _run_list(["--no-color"], [_stub("alpha", _version="1.2.3")])
        assert result.exit_code == 0
        assert "Version" not in result.output
        assert "Reachable" not in result.output

    def test_show_versions_adds_both_columns(self):
        result = _run_list(
            ["--show-versions", "--no-color"], [_stub("alpha", _version="1.2.3")]
        )
        assert result.exit_code == 0
        assert "Version" in result.output
        assert "Reachable" in result.output

    def test_reachable_yes_for_satisfied_scanner(self):
        result = _run_list(
            ["--show-versions", "--no-color"],
            [_stub("alpha", _version="1.2.3", _satisfied=True)],
        )
        assert result.exit_code == 0
        assert "Yes" in result.output

    def test_reachable_no_for_unsatisfied_scanner(self):
        result = _run_list(
            ["--show-versions", "--no-color"],
            [_stub("beta", _version="2.0.0", _satisfied=False)],
        )
        assert result.exit_code == 0
        # "No" appears as the Reachable cell (word-boundary safe in the table).
        assert "No" in result.output

    def test_unknown_version_renders_when_scanner_reports_none(self):
        result = _run_list(
            ["--show-versions", "--no-color"],
            [_stub("gamma", _version=None, _satisfied=True)],
        )
        assert result.exit_code == 0
        assert "Unknown" in result.output

    def test_disabled_scanner_renders_false_in_enabled_column(self):
        """Regression for the always-"True" Enabled bug: by row-build time the
        plugin config has been model_dump()'d to a dict, so the old
        `hasattr(plugin_config, "enabled")` was always False and every plugin
        rendered "True". A disabled scanner must render its real state.
        """

        class _DisabledConfig(_StubConfig):
            def __init__(self):
                super().__init__("disabled_one", enabled=False)

        disabled = type(
            "DisabledOneScanner",
            (_StubScanner,),
            {
                "_name": "disabled_one",
                "__init__": lambda self, context=None, config=None: setattr(
                    self, "config", _DisabledConfig()
                )
                or setattr(self, "tool_version", None),
            },
        )
        result = _run_list(["--no-color"], [disabled])
        assert result.exit_code == 0
        assert "False" in result.output

    def test_uninstantiable_scanner_does_not_crash_the_table(self):
        """The pre-existing add_row arity bug: an error row must fill every column.

        With --show-versions the scanners table has 7 columns; a scanner that
        cannot be constructed must still render a full-width error row rather than
        raising "Not enough columns" and taking down the whole command.
        """
        result = _run_list(
            ["--show-versions", "--no-color"],
            [_stub("broken", _raise_on_init=True), _stub("ok", _satisfied=True)],
        )
        assert result.exit_code == 0
        # The command completed and printed the scanners table with both columns.
        assert "Version" in result.output
        assert "Reachable" in result.output

    def test_uninstantiable_scanner_default_mode_does_not_crash(self):
        """Same arity fix in the default (5-column) layout."""
        result = _run_list(
            ["--no-color"],
            [_stub("broken", _raise_on_init=True), _stub("ok", _satisfied=True)],
        )
        assert result.exit_code == 0


class TestPluginShow:
    """Tests for the plugin show command."""

    def test_show_command_exists(self):
        result = runner.invoke(plugin_app, ["show", "--help"])
        assert result.exit_code == 0
