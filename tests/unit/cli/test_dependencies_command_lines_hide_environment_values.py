# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash dependencies install`` shows an install's argv and output without the
values the configuration read from the environment, and shows any argv.

The command printed each plugin's argv as given and the child's stdout and
stderr as returned, and logged the run with no values to redact. A plugin option
read from the environment (a registry URL with a token in it, say) reaches the
argv the plugin declares, and a tool echoes what it was given, so the value was
printed in clear by the very command that redacts it from every failure line.
Both are now redacted with the configuration's environment values, and the
runner is passed the same values for the lines it logs itself.

The argv line was also built with ``' '.join(cmd)``, which raises TypeError on
an element that is not a str (a Path, a number) and ended the whole install run
with a traceback. It is now shown element by element, as text.
"""

from __future__ import annotations

import io
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from rich.console import Console
from typer.testing import CliRunner

from automated_security_helper.cli import dependencies as dependencies_module
from automated_security_helper.cli.dependencies import dependencies_app
from automated_security_helper.utils import subprocess_utils

pytestmark = pytest.mark.unit

#: Long enough, and with a "-", to be hidden wherever it is printed.
CANARY = "ash-canary-value-xq9"


def test_a_path_element_is_text_to_the_command_check():
    """The shape check refused a Path element as "not text" before the argv was
    shown or run; subprocess accepts a path object, so the check reads it as its
    text. A number is still refused."""
    checked = dependencies_module._well_formed_commands(
        [["copy", Path("plain-path"), "dest"]]
    )

    assert checked == [(["copy", "plain-path", "dest"], False)], checked
    with pytest.raises(TypeError):
        dependencies_module._well_formed_commands([["copy", 3]])


def test_a_command_line_is_shown_as_text_without_the_values():
    shown = dependencies_module._shown_command(
        ["pip", "install", Path("plain-path"), 3, CANARY], (CANARY,)
    )
    assert shown.startswith("pip install plain-path 3 "), shown
    assert CANARY not in shown, shown


def test_the_command_line_is_the_runners_own_form(monkeypatch):
    """Built with the runner's helpers: a --config-overrides value is written as
    its key, as the runner's "Running command" log line writes it, so the two
    lines about one child read the same. Compared with the line the runner
    logs, not with the helper call that builds it: the runner's spawn and its
    argv[0] resolution are stood in, so no program starts and the argv is logged
    as given."""
    argv = ["ash", "--config-overrides", f"scanners.x.options.token={CANARY}"]
    logged: list[str] = []
    monkeypatch.setattr(
        subprocess_utils.ASH_LOGGER,
        "log",
        lambda level, message, *args, **kwargs: logged.append(message),
    )
    monkeypatch.setattr(subprocess_utils, "_resolved_or_refused", lambda *_a: None)
    monkeypatch.setattr(
        subprocess_utils,
        "_runner",
        lambda sandboxed: (
            lambda args, **kwargs: subprocess.CompletedProcess(args, 0, "", "")
        ),
    )

    subprocess_utils.run_command(argv)
    shown = dependencies_module._shown_command(argv, ())

    assert f"Running command: {shown}" in logged, (shown, logged)
    assert CANARY not in shown, shown


def test_a_lone_string_value_is_one_value_not_its_characters():
    """The values reach the redactor through the one normalizer every sink
    reads them with; tuple() of a lone string would be its characters, each
    too short to redact, so the value would print whole."""
    shown = dependencies_module._shown_command(["echo", CANARY], CANARY)
    assert CANARY not in shown, shown


@pytest.fixture
def install_values():
    token = dependencies_module._INSTALL_VALUES.set((CANARY,))
    yield (CANARY,)
    dependencies_module._INSTALL_VALUES.reset(token)


def test_the_childs_output_is_printed_without_the_values(
    monkeypatch, capsys, install_values
):
    monkeypatch.setenv("COLUMNS", "300")
    received = {}

    def child(**kwargs):
        received.update(kwargs)
        return subprocess.CompletedProcess(
            kwargs["args"], 0, f"token {CANARY} accepted\n", f"warning: {CANARY}\n"
        )

    monkeypatch.setattr(subprocess_utils, "run_command", child)

    assert dependencies_module.run_command(["echo", "x"]) == 0

    printed = "".join(capsys.readouterr())
    assert CANARY not in printed, printed
    # The controls: the rest of each line is shown, and the runner's own log
    # lines are passed the same values.
    assert "token" in printed and "accepted" in printed, printed
    assert "warning:" in printed, printed
    assert received["values"] == install_values, received


def test_a_spawn_error_is_printed_without_the_values(
    monkeypatch, capsys, install_values
):
    monkeypatch.setenv("COLUMNS", "300")

    def boom(**_kwargs):
        raise RuntimeError(f"no such host {CANARY}")

    monkeypatch.setattr(subprocess_utils, "run_command", boom)

    assert dependencies_module.run_command(["curl", CANARY]) == 1

    printed = "".join(capsys.readouterr())
    assert CANARY not in printed, printed
    assert "Error running command curl" in printed, printed


class _Lines(io.StringIO):
    """The installer's panel output, plus the values the run_command stand-in
    found set for each command it was handed."""

    values_seen: list


def _one_scanner_with(monkeypatch, tmp_path, commands):
    """One scanner whose declared install argv are ``commands``, built from a
    configuration that read CANARY from the environment. No install runs: the
    stand-in for run_command records the values the install loop set for it
    (``_INSTALL_VALUES``), which is the wiring the redaction rests on."""
    monkeypatch.setenv("ASH_BIN_PATH", str(tmp_path / "bin"))
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(dependencies_module, "load_plugins", lambda *_a, **_k: {})
    fake = MagicMock()
    fake.config = SimpleNamespace(name="fake-scanner")
    fake.command = "fake-scanner"
    fake.get_installation_commands.return_value = commands
    monkeypatch.setattr(
        dependencies_module,
        "ash_plugin_manager",
        SimpleNamespace(
            plugin_modules=lambda kind: (
                [lambda **_kw: fake] if kind == "scanner" else []
            )
        ),
    )
    lines = _Lines()
    lines.values_seen = []

    def run_command(cmd, shell=False):
        lines.values_seen.append(dependencies_module._INSTALL_VALUES.get())
        return 0

    monkeypatch.setattr(dependencies_module, "run_command", run_command)
    real_resolve = dependencies_module.resolve_config

    def resolved_with_the_canary(*args, **kwargs):
        config = real_resolve(*args, **kwargs)
        config._environment_values = [CANARY]
        return config

    monkeypatch.setattr(dependencies_module, "resolve_config", resolved_with_the_canary)
    monkeypatch.setattr(
        dependencies_module,
        "console",
        Console(file=lines, width=300, no_color=True),
    )
    return lines


def _install(tmp_path):
    # What the command printed is read from the result's `output` (stdout and
    # stderr as the terminal shows them), not its `stdout`: on Click 8.2 and
    # later `stdout` leaves stderr out, so a value printed there was never read.
    return CliRunner().invoke(
        dependencies_app,
        ["--plugin-type", "scanner", "--bin-path", str(tmp_path / "bin")],
        env={"COLUMNS": "300"},
    )


def test_the_running_command_line_hides_the_values(tmp_path, monkeypatch):
    lines = _one_scanner_with(monkeypatch, tmp_path, [["fetch", "--token", CANARY]])

    result = _install(tmp_path)

    printed = lines.getvalue() + result.output
    assert "Running command: fetch --token" in printed, printed
    assert CANARY not in printed, printed
    # The run set the configuration's values for the runner's own lines: with
    # the set dropped, every assertion above still held.
    assert lines.values_seen == [(CANARY,)], lines.values_seen


def test_the_values_are_reset_when_the_install_loop_raises(tmp_path, monkeypatch):
    """An in-process caller (this runner, an embedding host) must not find the
    previous run's values still set after an exception escaped the loop."""
    _one_scanner_with(monkeypatch, tmp_path, [["fetch", "x"]])
    seen_in_the_loop: list = []

    def boom(cmd):
        # Recorded before the raise: there was something set to reset.
        seen_in_the_loop.append(dependencies_module._INSTALL_VALUES.get())
        raise RuntimeError("the pinned-install check failed")

    monkeypatch.setattr(dependencies_module, "pinned_install_already_satisfied", boom)
    assert dependencies_module._INSTALL_VALUES.get() == ()

    result = _install(tmp_path)

    assert isinstance(result.exception, RuntimeError), result.exception
    assert seen_in_the_loop == [(CANARY,)], seen_in_the_loop
    assert dependencies_module._INSTALL_VALUES.get() == ()


def test_an_argv_with_a_path_element_is_shown_and_run(tmp_path, monkeypatch):
    """A Path in a plugin's argv ended the run with a TypeError from ' '.join."""
    lines = _one_scanner_with(monkeypatch, tmp_path, [["copy", Path("plain-path")]])

    result = _install(tmp_path)

    printed = lines.getvalue() + result.output
    assert "Running command: copy plain-path" in printed, printed
    assert "TypeError" not in printed + str(result.exception), result.exception
