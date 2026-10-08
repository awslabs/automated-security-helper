# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`--tool` names that #766 renamed keep working as deprecated aliases.

#766 made `ash dependencies install` build each plugin from its own config section.
The archive converter had been listed under its class name, `ArchiveConverter`,
because it was built without a config; it is now listed under its config key,
`archive`. A script or doc that used the old spelling went from installing the
converter to exiting 2 with "Unknown tool(s)".

These tests run the real command against the real plugin registry and capture what
it selected and how it judged the run, rather than reading its stdout (see
TestToolSelection in test_dependencies_verdict.py for why stdout is unreliable
in-process).
"""

import io
import shutil
import subprocess

import pytest
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.base.plugin_config import plugin_config_key
from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import (
    DEPRECATED_TOOL_ALIASES,
    EXIT_BAD_SELECTION,
    EXIT_OK,
    dependencies_app,
)

runner = CliRunner()

# Measured, not derived from the table under test: the `Available:` list of
# `ash dependencies install --tool <unknown>` at 3aa74305 (just before #766) and at
# 5fe35b33 (#766), for each plugin type, with every bundled plugin module loaded
# (ash_builtin, ash_aws_plugins, and the snyk, trivy and ferret community modules).
# This is the only name that differs. Written out here so that emptying the table
# fails these tests instead of collecting none of them.
ALIASES = [("ArchiveConverter", "archive")]


def test_the_alias_table_holds_exactly_the_measured_renames():
    assert DEPRECATED_TOOL_ALIASES == dict(ALIASES)


@pytest.mark.parametrize(("old_name", "new_key"), ALIASES)
def test_each_alias_names_the_class_it_used_to_select(old_name, new_key):
    """The old name was a class name; the new key must be that same class's key.

    Pins the table to the registry, so an entry cannot point an old spelling at a
    different plugin than the one it used to select.
    """
    from automated_security_helper.plugins import ash_plugin_manager

    classes = [
        cls
        for plugin_type in ("converter", "scanner", "reporter")
        for cls in ash_plugin_manager.plugin_modules(plugin_type)
        if cls.__name__ == old_name
    ]
    assert len(classes) == 1, f"{old_name} matches {len(classes)} plugin classes"
    assert plugin_config_key(classes[0]) == new_key


class TestDeprecatedToolAliases:
    @pytest.fixture(autouse=True)
    def _isolate(self, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
        self.bin_args = ["--bin-path", str(tmp_path / "bin")]
        self.panels = io.StringIO()
        self.warnings = io.StringIO()
        monkeypatch.setattr(
            dependencies_module,
            "console",
            Console(file=self.panels, width=200, no_color=True),
        )
        monkeypatch.setattr(
            dependencies_module,
            "err_console",
            Console(file=self.warnings, width=200, no_color=True),
        )
        # What the command selected and how it judged it, captured on the way into
        # the verdict function and then handed through unchanged.
        self.verdicts = []
        real_report_and_exit = dependencies_module._report_and_exit

        def recording_report_and_exit(outcomes, requested_tools):
            self.verdicts.append(
                (
                    [(o.plugin_type, o.name, o.status) for o in outcomes],
                    list(requested_tools),
                )
            )
            return real_report_and_exit(outcomes, requested_tools=requested_tools)

        monkeypatch.setattr(
            dependencies_module, "_report_and_exit", recording_report_and_exit
        )

    def _invoke(self, *args):
        return runner.invoke(dependencies_app, [*args, *self.bin_args])

    @pytest.mark.parametrize(("old_name", "new_key"), ALIASES)
    def test_old_name_selects_the_plugin_and_warns(self, old_name, new_key):
        result = self._invoke("--tool", old_name)
        assert result.exit_code == EXIT_OK, self.panels.getvalue()
        assert len(self.verdicts) == 1
        outcomes, requested = self.verdicts[0]
        assert [name for _, name, _ in outcomes] == [new_key]
        assert requested == [new_key]

        warned = self.warnings.getvalue()
        assert warned.count("Deprecated") == 1, warned
        assert f"--tool {old_name}" in warned
        assert f"--tool {new_key}" in warned
        # The warning is the only output that goes to the warning stream; the panels
        # stay where they were.
        assert "Deprecated" not in self.panels.getvalue()

    @pytest.mark.parametrize(("old_name", "new_key"), ALIASES)
    def test_old_name_behaves_exactly_like_the_new_key(self, old_name, new_key):
        old = self._invoke("--tool", old_name)
        new = self._invoke("--tool", new_key)
        assert old.exit_code == new.exit_code == EXIT_OK
        assert len(self.verdicts) == 2
        assert self.verdicts[0] == self.verdicts[1]

    @pytest.mark.parametrize(("old_name", "new_key"), ALIASES)
    def test_repeating_the_old_name_warns_once(self, old_name, new_key):
        result = self._invoke("--tool", old_name, "--tool", old_name, "--tool", new_key)
        assert result.exit_code == EXIT_OK, self.panels.getvalue()
        assert self.warnings.getvalue().count("Deprecated") == 1
        outcomes, requested = self.verdicts[0]
        assert [name for _, name, _ in outcomes] == [new_key]
        assert requested == [new_key]

    @pytest.mark.parametrize("new_key", sorted({new for _, new in ALIASES}))
    def test_new_key_works_without_a_warning(self, new_key):
        result = self._invoke("--tool", new_key)
        assert result.exit_code == EXIT_OK, self.panels.getvalue()
        assert [name for _, name, _ in self.verdicts[0][0]] == [new_key]
        assert self.warnings.getvalue() == ""

    def test_unknown_name_still_exits_two_without_a_warning(self):
        result = self._invoke("--tool", "not-a-real-tool")
        assert result.exit_code == EXIT_BAD_SELECTION
        assert "Unknown tool(s): not-a-real-tool" in self.panels.getvalue()
        assert self.warnings.getvalue() == ""
        assert self.verdicts == []

    @pytest.mark.parametrize(("old_name", "new_key"), ALIASES)
    def test_old_name_outside_its_plugin_type_is_refused_like_the_new_key(
        self, old_name, new_key
    ):
        """Narrowed to scanners, neither spelling of a converter can be selected.

        The refusal names the spelling the caller typed, so the message matches
        the command line rather than a name they never wrote.
        """
        new = self._invoke("--plugin-type", "scanner", "--tool", new_key)
        old = self._invoke("--plugin-type", "scanner", "--tool", old_name)
        assert new.exit_code == old.exit_code == EXIT_BAD_SELECTION
        panels = self.panels.getvalue()
        assert f"Unknown tool(s): {new_key}" in panels
        assert f"Unknown tool(s): {old_name}" in panels
        assert self.verdicts == []

    @pytest.mark.parametrize(("old_name", "new_key"), ALIASES)
    def test_without_the_alias_table_the_old_name_is_unknown(
        self, monkeypatch, old_name, new_key
    ):
        """Negative control: the table, not some other lookup, is what resolves it."""
        monkeypatch.setattr(dependencies_module, "DEPRECATED_TOOL_ALIASES", {})
        result = self._invoke("--tool", old_name)
        assert result.exit_code == EXIT_BAD_SELECTION
        assert f"Unknown tool(s): {old_name}" in self.panels.getvalue()
        assert self.warnings.getvalue() == ""


def test_the_warning_reaches_a_real_stderr(tmp_path):
    """Out of process, so the stream the warning lands on is the real one.

    The in-process tests pin both consoles to buffers, which proves what was
    printed but not where it went.
    """
    ash = shutil.which("ash")
    if ash is None:
        pytest.skip("the `ash` console script is not on PATH in this environment")
    old_name, new_key = ALIASES[0]
    proc = subprocess.run(
        [
            ash,
            "dependencies",
            "install",
            "--plugin-type",
            "converter",
            "--tool",
            old_name,
            "--bin-path",
            str(tmp_path / "bin"),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        cwd=tmp_path,
    )
    assert proc.returncode == EXIT_OK, proc.stdout + proc.stderr
    stderr = " ".join(proc.stderr.split())
    assert f"--tool {old_name} is deprecated; use --tool {new_key} instead" in stderr
    assert "Deprecated" not in proc.stdout
