# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What Nix mode prints around the ``nix develop`` call, and what it exits with.

The real CLI runs in-process. Only the lookup of the ``nix`` executable and the one
call that would enter the shell (``run_ash_nix._enter_shell``) are replaced, so the flake reference
ASH resolves, the command it builds from the scan's own options, the messages and
the exit code are ASH's own. The fake records the command, which is part of each
snapshot: it is what an operator sees with ``--debug``, and an option lost on the
way into the shell would show up there.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 - only CompletedProcess is used, to fake the shell's result
import sys
from pathlib import Path

import pytest

from tests.snapshot.container.conftest import completed_by

#: Where the fake says ``nix`` is. Fixed, so the recorded command is the same everywhere.
FAKE_NIX = "/nix/var/nix/profiles/default/bin/nix"

SCAN = [
    "scan",
    "--mode",
    "nix",
    "--no-progress",
    "--source-dir",
    "src",
    "--output-dir",
    "out",
]

#: The host prints "ASH Scan Completed in <duration>" from its own wall clock.
pytestmark = [
    pytest.mark.unit,
    pytest.mark.snapshot_masking(mask_durations=True),
]

#: The snapshots are POSIX text by construction: they name the fake nix path.
_POSIX_TEXT = pytest.mark.skipif(
    os.name == "nt",
    reason="the recorded text is POSIX by construction: it names /nix/var/nix/profiles/default/bin/nix",
)


class FakeNixShell:
    """Answers the ``nix develop`` call with a status, optionally leaving results."""

    def __init__(self) -> None:
        self.returncode = 0
        self.results_json: str | None = None
        #: Whether the inner run marks its results completed, as it does when it
        #: finishes; False leaves them as an ASH older than the host's would.
        self.marks_completion = True
        self.commands: list[list[str]] = []
        self.environments: list[dict[str, str]] = []

    def run(self, cmd, env=None):
        # Replaces run_ash_nix._enter_shell, which owns the stdin and
        # interrupt handling; only the command and environment are observed.
        self.commands.append(list(cmd))
        self.environments.append(dict(env or {}))
        if self.results_json is not None:
            out = Path("out")
            out.mkdir(exist_ok=True)
            # surrogateescape: a lone surrogate such as "\udcff" is written as the
            # byte it stands for, so a test can leave a file that is not UTF-8.
            results_json = (
                completed_by(self.results_json, (env or {}).get("ASH_OUTER_RUN_ID"))
                if self.marks_completion
                else self.results_json
            )
            out.joinpath("ash_aggregated_results.json").write_text(
                results_json, encoding="utf-8", errors="surrogateescape"
            )
        return subprocess.CompletedProcess(args=cmd, returncode=self.returncode)


@pytest.fixture(autouse=True)
def _src(in_tmp, monkeypatch):
    (in_tmp / "src").mkdir()
    # Absolute output paths in the summary would fold at a machine-dependent column.
    monkeypatch.setenv("COLUMNS", "1000")
    for name in ("ASH_IN_NIX", "ASH_NIX_FLAKE_REF"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def nix_shell(monkeypatch) -> FakeNixShell:
    from automated_security_helper.interactions import run_ash_nix

    shell = FakeNixShell()
    monkeypatch.setattr(
        run_ash_nix, "find_executable", lambda name: FAKE_NIX if name == "nix" else None
    )
    monkeypatch.setattr(run_ash_nix, "_enter_shell", shell.run)
    return shell


@pytest.fixture
def scan(run_cli, monkeypatch):
    """Run ``ash <args>`` with ``sys.argv`` set as a real ``ash`` process would have it.

    The scan entry point builds the inner command from the call's own options, not
    from this process's argv; ``sys.argv`` is still set as ``ash`` would have it so
    that anything the CLI reads from it in-process reads the scan's, not pytest's.
    """

    def _scan(args):
        monkeypatch.setattr(sys, "argv", ["ash", *args])
        return run_cli(args)

    return _scan


def _normalized(command: list[str]) -> list[str]:
    """The command with this interpreter's path and its safe-path flags as placeholders.

    The inner scan runs on this interpreter, whose path differs between hosts, and
    the flags that keep the working directory off sys.path differ between Python
    versions (``-P`` exists from 3.11). The placeholder stands for exactly this
    version's flags, so a command that left them out would not match.
    """
    from automated_security_helper.utils.python_child import _SAFE_PATH_FLAGS

    out: list[str] = []
    i = 0
    while i < len(command):
        part = command[i]
        i += 1
        if part != sys.executable:
            out.append(part)
            continue
        out.append("<PYTHON>")
        if command[i : i + len(_SAFE_PATH_FLAGS)] == _SAFE_PATH_FLAGS:
            out.append("<SAFE_PATH_FLAGS>")
            i += len(_SAFE_PATH_FLAGS)
    return out


def _seen(result, shell: FakeNixShell) -> dict:
    # The printed output names the interpreter too, whose path is the machine's.
    printed = {
        stream: result[stream].replace(sys.executable, "<PYTHON>")
        for stream in ("stdout", "stderr")
        if isinstance(result.get(stream), str)
    }
    commands = [_normalized(command) for command in shell.commands]
    return {
        **result,
        **printed,
        "nix_commands": commands,
        "ASH_IN_NIX": [env.get("ASH_IN_NIX") for env in shell.environments],
        "ASH_OFFLINE": [env.get("ASH_OFFLINE") for env in shell.environments],
    }


@_POSIX_TEXT
def test_nix_not_installed(scan, snapshot, monkeypatch):
    from automated_security_helper.interactions import run_ash_nix

    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)
    assert scan(SCAN) == snapshot


@_POSIX_TEXT
def test_already_inside_a_nix_shell(scan, snapshot, nix_shell, monkeypatch):
    monkeypatch.setenv("ASH_IN_NIX", "1")
    assert _seen(scan(SCAN), nix_shell) == snapshot


@_POSIX_TEXT
@pytest.mark.parametrize("returncode", [0, 1])
def test_shell_left_no_results(returncode, scan, snapshot, nix_shell):
    nix_shell.returncode = returncode
    assert _seen(scan(SCAN), nix_shell) == snapshot


@_POSIX_TEXT
def test_shell_exit_with_results(scan, snapshot, nix_shell, fixture_model):
    # The inner scan found something and exited 2; the host reports the shell's
    # status as a warning and reaches its own verdict from the results.
    nix_shell.returncode = 2
    nix_shell.results_json = fixture_model.model_dump_json()
    assert (
        _seen(scan([*SCAN, "--no-fail-on-incomplete-scanners"]), nix_shell) == snapshot
    )


@_POSIX_TEXT
def test_results_the_inner_run_did_not_mark_completed(
    scan, snapshot, nix_shell, fixture_model
):
    # As an older ASH first on PATH inside the shell leaves them: not read back,
    # and the host exits 1 naming the file, although the shell exited 2.
    nix_shell.returncode = 2
    nix_shell.results_json = fixture_model.model_dump_json()
    nix_shell.marks_completion = False
    assert (
        _seen(scan([*SCAN, "--no-fail-on-incomplete-scanners"]), nix_shell) == snapshot
    )


@_POSIX_TEXT
def test_unparseable_results(scan, snapshot, nix_shell):
    nix_shell.results_json = "{not json"
    assert _seen(scan(SCAN), nix_shell) == snapshot


#: A key or value of a results file, with what a terminal or a CI runner obeys.
SECRET = "wJalrXUtnFEMIK7MDENG"
HOSTILE = SECRET + "\x1b[31m\n::error title=scan::" + SECRET


@pytest.mark.parametrize(
    "results_json, reason",
    [
        pytest.param('{"T": ' + SECRET, "Invalid JSON", id="not-json"),
        pytest.param(
            json.dumps({"scanner_results": {HOSTILE: 5}}),
            "Invalid value at 'scanner_results.<key>'",
            id="key",
        ),
        # Written with surrogateescape: the file holds the byte 0xff.
        pytest.param('{"name": "ok\udcff"}', "not UTF-8 at byte offset", id="not-utf8"),
    ],
)
def test_unparseable_results_are_not_quoted(scan, nix_shell, results_json, reason):
    """The results file holds finding data. pydantic's text quotes it
    (input_value='...'), its locations name the file's keys, and a decode error
    prints the byte; Rich read the quoting part as a tag and dropped it, and once
    log messages print as text it reached the console. A decode error escaped
    the parse handler as a traceback."""
    nix_shell.results_json = results_json
    result = scan(SCAN)

    shown = result["stdout"] + result["stderr"]
    assert result["exit_code"] == 1, shown
    assert "Failed to parse results file" in shown, shown
    assert reason in shown, shown
    assert SECRET not in shown, shown
    assert "\x1b[31m" not in shown and "\n::" not in shown, repr(shown)


def test_the_hosts_equals_form_of_mode_is_not_forwarded(scan, nix_shell):
    """`--mode=nix` is one token on the host's command line. The inner command is
    built from the scan's own options, so that spelling is not forwarded, and the
    inner scan gets the local mode once, or it would try to enter the shell
    again."""
    args = ["scan", "--mode=nix", *SCAN[3:]]
    nix_shell.returncode = 1

    scan(args)

    (command,) = nix_shell.commands
    assert not [token for token in command if token.startswith("--mode=")], command
    assert command.count("--mode") == 1, command
    assert command[command.index("--mode") + 1] == "local", command
