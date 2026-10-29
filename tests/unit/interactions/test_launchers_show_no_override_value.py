# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A command line ASH shows writes each --config-overrides value as its key.

Container and Nix mode pass the user's --config-overrides on to the ASH they
start, and the command they start is shown: Nix mode's debug log line and
--debug echo, container mode's --debug echoes, and the log line each
subprocess helper writes for the command it runs. An override's value can be
a credential, and none of these show it: an override reads ``key=<value>``.
The command that runs carries the value. The value each cell sets is made up
when it runs.
"""

from __future__ import annotations

import logging
import secrets
import subprocess
from pathlib import Path
from typing import Iterator, List

import pytest

from automated_security_helper.interactions import run_ash_container, run_ash_nix
from automated_security_helper.utils import subprocess_utils


@pytest.fixture
def planted() -> str:
    """A value made up for this run, which no text in ASH can hold."""
    return f"planted-{secrets.token_hex(6)}"


@pytest.fixture
def true_program(tmp_path: Path) -> str:
    """A program that exits 0, written under the test's own directory, which
    the real-program guard admits (tests/utils/no_real_programs.py)."""
    program = tmp_path / "true"
    program.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    program.chmod(0o755)
    return str(program)


class _Keep(logging.Handler):
    def __init__(self, sink: List[str]) -> None:
        super().__init__(level=1)
        self.sink = sink

    def emit(self, record: logging.LogRecord) -> None:
        self.sink.append(record.getMessage())


@pytest.fixture
def logged() -> Iterator[List[str]]:
    """Every message the "ash" logger handles, at any level."""
    sink: List[str] = []
    handler = _Keep(sink)
    logger = logging.getLogger("ash")
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(1)
    try:
        yield sink
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


def _overrides(planted: str) -> List[str]:
    return [
        "--config-overrides",
        f"project_name={planted}",
        f"--config-overrides=global_settings.severity_threshold={planted}",
    ]


def _assert_shown_by_key(shown: str, planted: str) -> None:
    assert planted not in shown, shown
    assert "project_name=<value>" in shown, shown
    assert "global_settings.severity_threshold=<value>" in shown, shown


@pytest.mark.unit
def test_nix_mode_shows_its_command_without_override_values(
    monkeypatch, capfd, logged, planted
):
    ran: List[List[str]] = []

    def enter_shell(cmd, **kwargs):
        ran.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.delenv(run_ash_nix.ASH_IN_NIX_ENV_VAR, raising=False)
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda name: "/fake/nix")
    monkeypatch.setattr(run_ash_nix, "resolve_flake_ref", lambda ref=None: "flake-ref")
    monkeypatch.setattr(
        "automated_security_helper.interactions.run_ash_nix.subprocess.run",
        enter_shell,
    )
    # Where the module enters the shell through its own _enter_shell (a Popen
    # that passes Ctrl-C on), that is the call the shell starts from.
    monkeypatch.setattr(run_ash_nix, "_enter_shell", enter_shell, raising=False)

    run_ash_nix.run_ash_nix(argv=["scan", *_overrides(planted)], debug=True)

    out, err = capfd.readouterr()
    nix_lines = [message for message in logged if "Nix command" in message]
    assert nix_lines, logged
    _assert_shown_by_key("\n".join(nix_lines), planted)
    _assert_shown_by_key(out, planted)
    assert planted not in err, err
    assert [message for message in logged if planted in message] == []
    # The Nix shell runs the overrides as given.
    assert f"project_name={planted}" in ran[0]


@pytest.mark.unit
def test_container_mode_shows_its_command_without_override_values(
    monkeypatch, capfd, planted
):
    ran: List[List[str]] = []

    def run_cmd_direct(cmd, debug=False, **kwargs):
        ran.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0)

    monkeypatch.setattr(run_ash_container, "run_cmd_direct", run_cmd_direct)

    run_ash_container._execute_container(
        ["docker", "run", "image", "ash", *_overrides(planted)], debug=True
    )

    out, err = capfd.readouterr()
    _assert_shown_by_key(out, planted)
    assert planted not in err, err
    assert f"project_name={planted}" in ran[0]


@pytest.mark.integration
def test_run_cmd_direct_shows_its_command_without_override_values(
    capfd, logged, planted, true_program
):
    result = run_ash_container.run_cmd_direct(
        [true_program, *_overrides(planted)], debug=True
    )

    assert result.returncode == 0
    out, err = capfd.readouterr()
    _assert_shown_by_key(out, planted)
    assert planted not in err, err
    assert [message for message in logged if planted in message] == []


@pytest.mark.parametrize(
    "run",
    [
        pytest.param(lambda args: subprocess_utils.run_command(args), id="run_command"),
        pytest.param(
            lambda args: subprocess_utils.run_command_with_output_handling(
                args, stdout_preference="return", stderr_preference="return"
            ),
            id="run_command_with_output_handling",
        ),
        pytest.param(
            lambda args: subprocess_utils.run_command_stream_output(args),
            id="run_command_stream_output",
        ),
        pytest.param(
            lambda args: subprocess_utils.create_process_with_pipes(args).wait(),
            id="create_process_with_pipes",
        ),
    ],
)
@pytest.mark.integration
def test_a_subprocess_helper_logs_its_command_without_override_values(
    logged, planted, true_program, run
):
    run([true_program, *_overrides(planted)])

    commands = [message for message in logged if true_program in message]
    assert commands, logged
    _assert_shown_by_key("\n".join(commands), planted)
    assert [message for message in logged if planted in message] == []
