# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip` lets an older ASH skip tools it does not have.

Why this file exists
--------------------
ASH's own required check installs ASH from a pull request's base commit, while the
workflow files, and the tools they ask to install, come from the pull request. A pull
request that adds support for a new tool and asks the check to install it therefore
runs ``ash dependencies install --tool <new tool>`` with an ASH that has never heard of
it, which refuses with exit 2, so that pull request could not pass its own check.

The base ASH has no scanner for such a tool either, and the base config cannot enable
one, so the check needs nothing from it. With ``ASH_DEPENDENCIES_UNKNOWN_TOOLS=skip``
the command names each such tool, skips it, and installs the tools it knows. Without
the setting an unknown name is still refused, which is what catches a typo.

What this asserts
-----------------
1. Control: without the setting, an unknown ``--tool`` is refused (exit 2).
2. With it, the known tools are selected and judged as before, the unknown ones are
   named in the output and not selected, and a run naming only unknown tools installs
   nothing and succeeds.
3. Only the exact value ``skip`` turns it on; a value that only strips to it does not.
4. When some plugin failed to load, an unknown name is still refused: it may be that
   plugin's, so skipping it could skip a tool the ASH does have.
5. Under ``--plugin-type``, a name that is a plugin of a type left out is not unknown to
   this ASH: with or without the setting it is refused, and the message names its type.
   A name no plugin of any type has is skipped, and the message says exactly that.
"""

import io
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import (
    EXIT_BAD_SELECTION,
    EXIT_OK,
    dependencies_app,
)

runner = CliRunner()
SETTING = "ASH_DEPENDENCIES_UNKNOWN_TOOLS"


class TestWithTheRealRegistry:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv(SETTING, raising=False)
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        self.bin_args = ["--bin-path", str(tmp_path / "bin")]
        self.panels = io.StringIO()
        monkeypatch.setattr(
            dependencies_module,
            "console",
            Console(file=self.panels, width=200, no_color=True),
        )
        self.verdicts = []
        real = dependencies_module._report_and_exit

        def recording(outcomes, requested_tools):
            self.verdicts.append(([o.name for o in outcomes], list(requested_tools)))
            return real(outcomes, requested_tools=requested_tools)

        monkeypatch.setattr(dependencies_module, "_report_and_exit", recording)

    def _invoke(self, *args):
        return runner.invoke(dependencies_app, [*args, *self.bin_args])

    def _output(self, result) -> str:
        return self.panels.getvalue() + result.output

    def test_without_the_setting_an_unknown_name_is_refused(self):
        result = self._invoke("--tool", "archive", "--tool", "not-a-real-tool")
        assert result.exit_code == EXIT_BAD_SELECTION
        assert "Unknown tool(s): not-a-real-tool" in self.panels.getvalue()
        assert self.verdicts == []

    def test_with_skip_the_known_tools_install_and_the_unknown_are_named(
        self, monkeypatch
    ):
        monkeypatch.setenv(SETTING, "skip")
        result = self._invoke("--tool", "archive", "--tool", "not-a-real-tool")
        assert result.exit_code == EXIT_OK, self._output(result)
        assert self.verdicts == [(["archive"], ["archive"])], self.verdicts
        output = self._output(result)
        assert "not-a-real-tool" in output and "not known" in output.lower(), output

    def test_with_skip_only_unknown_names_install_nothing_and_succeed(
        self, monkeypatch
    ):
        monkeypatch.setenv(SETTING, "skip")
        result = self._invoke("--tool", "not-a-real-tool")
        assert result.exit_code == EXIT_OK, self._output(result)
        assert self.verdicts == [], "an unknown-only run selected something"
        assert "not-a-real-tool" in self._output(result)

    @pytest.mark.parametrize(
        "value",
        ["", "1", "true", "Skip", "skipped", "refuse", " skip", "skip ", "skip\n"],
    )
    def test_only_the_value_skip_turns_it_on(self, monkeypatch, value):
        monkeypatch.setenv(SETTING, value)
        result = self._invoke("--tool", "not-a-real-tool")
        assert result.exit_code == EXIT_BAD_SELECTION, (value, self._output(result))

    @pytest.mark.parametrize("skip", [False, True], ids=["without skip", "with skip"])
    def test_a_tool_of_an_unselected_plugin_type_is_refused_as_such(
        self, monkeypatch, skip
    ):
        """bandit is a scanner here. Under --plugin-type converter it is not missing from
        this ASH, so it is never skipped as unknown, and the refusal says what it is."""
        if skip:
            monkeypatch.setenv(SETTING, "skip")
        result = self._invoke("--plugin-type", "converter", "--tool", "bandit")
        output = self._output(result)
        assert result.exit_code == EXIT_BAD_SELECTION, output
        assert self.verdicts == [], self.verdicts
        assert "not known" not in output.lower(), output
        assert "bandit is a scanner plugin" in output, output
        assert "--plugin-type" in output, output

    UNKNOWN_PAIR = ("not-a-real-tool", "also-not-a-tool")

    def _names_every_unknown(self, output: str) -> None:
        for name in self.UNKNOWN_PAIR:
            assert name in output, (name, output)

    @pytest.mark.parametrize("skip", [False, True], ids=["refused", "skipped"])
    def test_a_mixed_request_names_every_unknown_tool(self, monkeypatch, skip):
        if skip:
            monkeypatch.setenv(SETTING, "skip")
        args = ["--tool", "archive"]
        for name in self.UNKNOWN_PAIR:
            args += ["--tool", name]
        result = self._invoke(*args)
        output = self._output(result)
        assert result.exit_code == (EXIT_OK if skip else EXIT_BAD_SELECTION), output
        self._names_every_unknown(output)

    @pytest.mark.parametrize("skip", [False, True], ids=["without skip", "with skip"])
    def test_a_refusal_for_an_unselected_type_also_names_every_unknown_tool(
        self, monkeypatch, skip
    ):
        if skip:
            monkeypatch.setenv(SETTING, "skip")
        args = ["--plugin-type", "converter", "--tool", "bandit"]
        for name in self.UNKNOWN_PAIR:
            args += ["--tool", name]
        result = self._invoke(*args)
        output = self._output(result)
        assert result.exit_code == EXIT_BAD_SELECTION, output
        assert "bandit is a scanner plugin" in output, output
        self._names_every_unknown(output)

    def test_under_plugin_type_the_skip_names_only_tools_no_plugin_has(
        self, monkeypatch
    ):
        monkeypatch.setenv(SETTING, "skip")
        result = self._invoke(
            "--plugin-type",
            "converter",
            "--tool",
            "archive",
            "--tool",
            "not-a-real-tool",
        )
        output = self._output(result)
        assert result.exit_code == EXIT_OK, output
        assert self.verdicts == [(["archive"], ["archive"])], self.verdicts
        assert "no converter, scanner or reporter plugin" in output, output
        assert "no scanner for" not in output, output


def test_a_plugin_that_failed_to_load_keeps_the_refusal(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(SETTING, "skip")
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    good = MagicMock()
    good.config = SimpleNamespace(name="good-scanner")
    good.command = "good-scanner"
    good.get_installation_commands.return_value = [["echo", "install"]]

    class Broken:
        def __init__(self, **_kwargs):
            raise RuntimeError("this plugin will not construct")

    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.load_plugins",
        lambda *_a, **_k: {},
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [lambda **_kw: good, Broken] if kind == "scanner" else []
            )
        ),
    )
    monkeypatch.setattr(
        "automated_security_helper.cli.dependencies.run_command",
        lambda cmd, shell=False: 0,
    )
    result = runner.invoke(
        dependencies_app,
        [
            "--plugin-type",
            "scanner",
            "--bin-path",
            str(tmp_path / "bin"),
            "--tool",
            "good-scanner",
            "--tool",
            "not-a-real-tool",
        ],
    )
    assert result.exit_code == EXIT_BAD_SELECTION, result.output
    assert "failed to load" in result.output
